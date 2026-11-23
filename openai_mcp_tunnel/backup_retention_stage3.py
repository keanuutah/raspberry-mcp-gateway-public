"""LOCAL-ONLY prototype: retention for gateway-created YAML backups.

No gateway registration or Home Assistant integration. Test only in an explicitly
supplied temporary directory. Never run this module against production /config.
Deletion requires a separate explicit opt-in and a verified *new* backup. AppArmor
rules would need separate review for any later deployment.
"""
from __future__ import annotations
import contextlib
import fcntl
import hashlib
import os
import re
import stat
from pathlib import Path

BACKUP = re.compile(r'^([a-zA-Z0-9][a-zA-Z0-9_-]{0,100})_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_\d{6})\.yaml\.bak$')
MAX_BACKUP_BYTES = 1024 * 1024


def _hash_regular_at(fd: int, name: str):
    h = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        s = os.fstat(h)
        if not stat.S_ISREG(s.st_mode) or s.st_size > MAX_BACKUP_BYTES:
            raise ValueError('Keine reguläre oder zu große Sicherung')
        digest = hashlib.sha256()
        total = 0
        while True:
            b = os.read(h, min(65536, MAX_BACKUP_BYTES + 1 - total))
            if not b: break
            total += len(b)
            if total > MAX_BACKUP_BYTES: raise ValueError('Sicherung zu groß')
            digest.update(b)
        return digest.hexdigest(), s
    finally:
        os.close(h)


def _dirfd(folder: Path):
    if folder.is_symlink(): raise PermissionError('Symlink-Verzeichnis nicht erlaubt')
    return os.open(str(folder), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _selected(fd: int, package: str, keep: int):
    groups = []
    with os.scandir(fd) as it:
        for e in it:
            m = BACKUP.fullmatch(e.name)
            if not m or m.group(1) != package or not e.is_file(follow_symlinks=False):
                continue
            groups.append(e.name)
    groups.sort(reverse=True)
    return groups[:keep], groups[keep:]


def retention_after_verified_backup(folder: str | Path, *, package: str,
                                     new_backup_name: str, expected_sha256: str,
                                     keep: int = 10, enabled: bool = False,
                                     expected_new_backup_bytes: int | None = None):
    """Remove *only* older backups for this package, under one exclusive lock.

    A successful caller-side commit is necessary but cannot be verified here;
    integration must invoke only after a completed package commit and verified
    backup. This local prototype deliberately does not accept /config paths.
    A failed validation never unlinks files. A partial unlink raises and is reported.
    """
    folder = Path(folder)
    if folder.is_symlink(): raise PermissionError('Symlink-Verzeichnis nicht erlaubt')
    folder = folder.resolve(strict=True)
    if folder == Path('/config') or folder == Path('/homeassistant_config') or str(folder).startswith(('/config/','/homeassistant_config/')):
        raise PermissionError('Lokaler Prototyp darf nicht auf HAOS-Konfiguration ausgeführt werden')
    if not isinstance(keep,int) or isinstance(keep,bool) or keep != 10:
        raise ValueError('Nur exakt 10 Sicherungen je Package vorgesehen')
    if not isinstance(package,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,100}',package):
        raise ValueError('Ungültiger Package-Name')
    m = BACKUP.fullmatch(new_backup_name) if isinstance(new_backup_name,str) else None
    if not m or m.group(1) != package:
        raise ValueError('Neue Sicherung gehört nicht zu diesem Package')
    if not isinstance(expected_sha256,str) or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise ValueError('Ungültige erwartete Prüfsumme')
    if not isinstance(enabled,bool): raise TypeError('enabled muss bool sein')
    fd = _dirfd(folder)
    try:
        # Lock file stored outside the backup folder, so it cannot count as backup.
        # This only serializes cooperating gateway callers, not Samba editors.
        lockfile = folder.parent / '.gw-retention-test.lock'
        lock = os.open(lockfile,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX)
            current_hash, meta = _hash_regular_at(fd,new_backup_name)
            if current_hash != expected_sha256: raise ValueError('SHA256 der neuen Sicherung stimmt nicht')
            if expected_new_backup_bytes is not None and meta.st_size != expected_new_backup_bytes:
                raise ValueError('Dateigröße der neuen Sicherung stimmt nicht')
            retained, excess = _selected(fd,package,keep)
            if new_backup_name not in retained:
                raise ValueError('Neue Sicherung ist nicht unter den zehn neuesten')
            result = {'package':package,'keep_per_package':keep,'new_backup':new_backup_name,
                      'new_backup_sha256':current_hash,'would_delete':excess,
                      'retained':retained,'deleted':[],'enabled':enabled}
            if not enabled: return result
            # Precheck ALL candidate files before performing any removal.
            # Ensure they are still regular, single-link files; record inode for race guard.
            candidates=[]
            for name in excess:
                st=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise PermissionError('Kandidat nicht sichere reguläre Datei')
                candidates.append((name,st.st_dev,st.st_ino))
            for name,dev,ino in candidates:
                st=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or (st.st_dev,st.st_ino)!=(dev,ino):
                    raise PermissionError('Kandidat zwischenzeitlich ersetzt')
                os.unlink(name,dir_fd=fd)
                result['deleted'].append(name)
            os.fsync(fd)
            return result
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN)
            os.close(lock)
    finally:
        os.close(fd)
