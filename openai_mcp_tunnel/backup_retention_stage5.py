"""Stage 5 LOCAL-ONLY: quarantine-first, descriptor-based backup retention.

This deliberately REFUSES /config and /homeassistant_config; no production operation.
Backups are selected using directory fd, verified and moved into a newly-created
0700 quarantine BEFORE any actual deletion. If a path was replaced between
validation and rename, the unexpected inode is preserved, never deleted.

Guarantees depend on private quarantine permissions and an exclusive cooperating
writer lock; this cannot defeat a hostile process with root/same-uid access or
already-open write fds. Production deployment needs a separate review.
"""
from __future__ import annotations
import fcntl
import hashlib
import os
import re
import stat
import uuid
from pathlib import Path
from backup_retention_stage3 import _dirfd, _hash_regular_at, _selected, BACKUP, MAX_BACKUP_BYTES

NAME=re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,100}\Z')

def _snapshot(fd,name):
    digest,meta=_hash_regular_at(fd,name)
    if meta.st_nlink!=1:
        raise PermissionError('Hardlink-Kandidat verweigert')
    return (meta.st_dev,meta.st_ino,meta.st_size,digest)

def _restore(qfd,fd,name):
    """Never overwrite a new path: hardlink restores only when destination absent."""
    try:
        os.link(name,name,src_dir_fd=qfd,dst_dir_fd=fd,follow_symlinks=False)
    except FileExistsError:
        return False
    os.unlink(name,dir_fd=qfd)
    return True

def _validate(folder,package,new_backup_name,expected_sha256,keep,enabled):
    if not isinstance(enabled,bool):raise TypeError('enabled muss bool sein')
    if not isinstance(keep,int) or isinstance(keep,bool) or keep!=10:raise ValueError('Nur 10 Sicherungen je Package')
    if not isinstance(package,str) or not NAME.fullmatch(package):raise ValueError('Ungültiges Package')
    match=BACKUP.fullmatch(new_backup_name) if isinstance(new_backup_name,str) else None
    if not match or match.group(1)!=package:raise ValueError('Ungültiger Backup-Name')
    if not isinstance(expected_sha256,str) or not re.fullmatch('[a-f0-9]{64}',expected_sha256):raise ValueError('Ungültiger SHA256')
    path=Path(folder)
    # Reject production paths even when /config does not exist in local tests.
    raw=os.path.abspath(os.fspath(path))
    if raw in ('/config','/homeassistant_config') or raw.startswith(('/config/','/homeassistant_config/')):
        raise PermissionError('Produktive HAOS-Pfade in Stage 5 gesperrt')
    if path.is_symlink():raise PermissionError('Symlink-Verzeichnis nicht erlaubt')
    path=path.resolve(strict=True)
    if path==Path('/config') or path==Path('/homeassistant_config') or str(path).startswith(('/config/','/homeassistant_config/')):
        raise PermissionError('Produktive HAOS-Pfade in Stage 5 gesperrt')
    return path

def retention_after_verified_backup(folder,*,package,new_backup_name,expected_sha256,
                                     keep=10,enabled=False,expected_new_backup_bytes=None,
                                     _test_hook=None):
    folder=_validate(folder,package,new_backup_name,expected_sha256,keep,enabled)
    fd=_dirfd(folder)
    lock=None;qfd=None;qname=None
    try:
        lock=os.open(str(folder.parent/'.gw-retention-test.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        fcntl.flock(lock,fcntl.LOCK_EX)
        digest,meta=_hash_regular_at(fd,new_backup_name)
        if digest!=expected_sha256:raise ValueError('SHA256 der neuen Sicherung stimmt nicht')
        if expected_new_backup_bytes is not None and meta.st_size!=expected_new_backup_bytes:raise ValueError('Größe stimmt nicht')
        retained,excess=_selected(fd,package,keep)
        if new_backup_name not in retained:raise ValueError('Neue Sicherung nicht in den zehn neuesten')
        result={'package':package,'keep_per_package':10,'new_backup':new_backup_name,
                'new_backup_sha256':digest,'would_delete':excess,'retained':retained,
                'deleted':[],'enabled':enabled,'quarantined':[]}
        if not enabled or not excess:return result
        # Verify all candidates first; a later swap is detected after atomic move.
        snapshots={name:_snapshot(fd,name) for name in excess}
        # Use private per-run directory; no target filename may be pre-created.
        qname='.gw-retention-quarantine-'+uuid.uuid4().hex
        os.mkdir(qname,0o700,dir_fd=fd)
        qfd=os.open(qname,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        if os.fstat(qfd).st_mode & 0o077:
            raise PermissionError('Quarantäneberechtigungen unzureichend')
        # Stage 6: durable intent journal, committed before the first rename.
        from backup_retention_stage6 import create_journal, clear_journal
        create_journal(qfd,package,snapshots)
        os.fsync(fd)
        staged=[]
        try:
            for name in excess:
                if _test_hook:_test_hook('before_move',name,folder)
                # rename is atomic: either the candidate or its replacement is moved.
                # We never unlink this moved inode unless it matches the snapshot.
                os.rename(name,name,src_dir_fd=fd,dst_dir_fd=qfd)
                staged.append(name)
                os.fsync(qfd);os.fsync(fd)
                if _test_hook:_test_hook('after_move',name,folder)
                if _snapshot(qfd,name)!=snapshots[name]:
                    raise PermissionError('Kandidat wurde beim Verschieben ersetzt oder verändert')
            if _test_hook:_test_hook('before_delete',None,folder)
            # All candidates are now isolated in a private 0700 dir.
            # One final content+identity validation before destructive operations.
            for name in staged:
                if _snapshot(qfd,name)!=snapshots[name]:
                    raise PermissionError('Quarantäneinhalt wurde verändert')
            # After this point the private namespace is inaccessible to other
            # non-privileged users. Same UID/root or pre-opened writers are out of scope.
            for name in staged:
                os.unlink(name,dir_fd=qfd)
                result['deleted'].append(name)
                os.fsync(qfd)
                if _test_hook:_test_hook('after_delete',name,folder)
            os.fsync(qfd);os.fsync(fd)
        except Exception as error:
            # Fail closed: attempt restoration only into absent original paths.
            # Otherwise retain file in quarantine for explicit manual recovery.
            for name in reversed(staged):
                try:
                    if not _restore(qfd,fd,name):result['quarantined'].append(name)
                except OSError:result['quarantined'].append(name)
            if result['quarantined']:
                raise RuntimeError('Bereinigung abgebrochen; Dateien sicher in Quarantäne: '+qname) from error
            raise
        finally:
            # Remove journal only when no quarantined backups remain. A hard
            # crash (BaseException) intentionally skips this cleanup path.
            if qfd is not None:
                try:
                    remaining=[e.name for e in os.scandir(qfd) if e.name != '.retention-journal.json']
                    if not remaining:clear_journal(qfd)
                except OSError:pass
                os.close(qfd);qfd=None
            try:os.rmdir(qname,dir_fd=fd)
            except OSError:pass  # Preserve quarantine for manual recovery.
        return result
    finally:
        if qfd is not None:os.close(qfd)
        if lock is not None:
            fcntl.flock(lock,fcntl.LOCK_UN)
            os.close(lock)
        os.close(fd)
