"""GW-14: explicitly approved, fail-closed ten-backup retention.

This module is never called by normal YAML commits. Every productive deletion
requires a specific plan and an additional one-time user approval. An interrupted
transaction may be recovered separately; recovery never resumes deletion.
No snapshot/backup contents are included in MCP responses.
"""
from __future__ import annotations
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import uuid

from backup_retention_stage3 import BACKUP, MAX_BACKUP_BYTES
from dashboard_safety_stage2 import ApprovalStore
from dashboard_commit import _read_option
from dashboard_approval_reset import clear_consumed_backup_retention_approval, clear_consumed_backup_recovery_approval

PACKAGE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,100}\.yaml\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
QNAME = re.compile(r'\.gw14-quarantine-[0-9a-f]{32}\Z')
JOURNAL = '.gw14-journal.json'
MAX_JOURNAL = 100 * 1024


def _digest(blob):
    return hashlib.sha256(blob).hexdigest()


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _package(package):
    if not isinstance(package, str) or not PACKAGE.fullmatch(package):
        raise ValueError('Ungueltiger Package-Name')
    return package[:-5]


def _folder(folder):
    """Pin each directory component, never cross a symbolic link."""
    path = Path(folder).absolute()
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise PermissionError('Symlink in Verzeichniskette')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise PermissionError('Kein Backup-Verzeichnis')
    return fd


def _read_backup(fd, name):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        first = os.fstat(handle)
        if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or first.st_size > MAX_BACKUP_BYTES:
            raise PermissionError('Keine sichere Backup-Datei')
        h = hashlib.sha256()
        size = 0
        while True:
            block = os.read(handle, min(65536, MAX_BACKUP_BYTES + 1 - size))
            if not block:
                break
            h.update(block)
            size += len(block)
            if size > MAX_BACKUP_BYTES:
                raise PermissionError('Backup zu gross')
        last = os.fstat(handle)
        stat_fields = lambda s: (s.st_dev, s.st_ino, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if size != first.st_size or stat_fields(first) != stat_fields(last):
            raise RuntimeError('Backup waehrend des Lesens geaendert')
        return {'name':name,'sha256':h.hexdigest(),'size':size,'dev':first.st_dev,'ino':first.st_ino}
    finally:
        os.close(handle)


def _inventory(fd, package):
    prefix = _package(package)
    records = []
    with os.scandir(fd) as it:
        entries = list(it)
    # Any pending quarantine for any package blocks all destructive operations.
    if any(QNAME.fullmatch(e.name) for e in entries):
        raise RuntimeError('Offene Quarantaene: erst manuelle Recovery')
    unsafe = []
    for entry in entries:
        m = BACKUP.fullmatch(entry.name)
        if m is None or m.group(1) != prefix:
            continue
        try:
            records.append(_read_backup(fd, entry.name))
        except (OSError, ValueError, PermissionError, RuntimeError):
            unsafe.append(entry.name)
    if unsafe:
        raise PermissionError('Unsichere Backup-Eintraege: kein Loeschplan')
    records.sort(key=lambda d: d['name'], reverse=True)
    return records


def _manifest(package, records):
    # Bound to content hashes and inode identities, so replacement invalidates plan.
    encoded = {'format':1,'package':package,'keep':10,
               'files':records}
    return _digest(_canonical(encoded))


def _plan(fd, package, newest_name, newest_sha256):
    _package(package)
    if not isinstance(newest_name, str) or not BACKUP.fullmatch(newest_name):
        raise ValueError('Backup-Name ungueltig')
    if not newest_name.startswith(package[:-5] + '_'):
        raise ValueError('Backup gehoert zu anderem Package')
    if not isinstance(newest_sha256, str) or not HASH.fullmatch(newest_sha256):
        raise ValueError('SHA256 ungueltig')
    records = _inventory(fd, package)
    if len(records) <= 10:
        raise ValueError('Keine ueberschuessigen Backups')
    if records[0]['name'] != newest_name or records[0]['sha256'] != newest_sha256:
        raise ValueError('Neuestes verifiziertes Backup stimmt nicht ueberein')
    return records, _manifest(package, records)


def plan(folder, package_name, newest_backup_name, newest_backup_sha256):
    fd = _folder(folder)
    try:
        records, plan_sha = _plan(fd,package_name,newest_backup_name,newest_backup_sha256)
        return {'package_name':package_name,'newest_backup':newest_backup_name,
                'keep_per_package':10,'retained':[r['name'] for r in records[:10]],
                'would_delete':[{'name':r['name'],'sha256':r['sha256'],'size_bytes':r['size']} for r in records[10:]],
                'plan_sha256':plan_sha,'approval_setting':'APPROVED_ACTION',
                'approved_change_value':f'RETENTION|{package_name}|{plan_sha}',
                'approval_argument':f'FREIGABE RETENTION {package_name} {plan_sha}',
                'preview_only':True,'deletion_enabled':False}
    finally:
        os.close(fd)


def _journal(fd, payload):
    data = _canonical(payload)
    if len(data)>MAX_JOURNAL:
        raise ValueError('Journal zu gross')
    h=os.open(JOURNAL, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    try:
        os.write(h,data);os.fsync(h)
    finally:
        os.close(h)
    os.fsync(fd)


def _write_lock(lock_path):
    path=Path(lock_path)
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    h=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(h,fcntl.LOCK_EX)
    return h


def _release_lock(h):
    fcntl.flock(h,fcntl.LOCK_UN);os.close(h)


def _preflight(record, qfd):
    actual=_read_backup(qfd,record['name'])
    if actual != record:
        raise RuntimeError('Quarantaene-Datei veraendert')


def _restore_one(qfd,fd,name):
    # Never overwrite newly created backup path.
    try:
        os.link(name,name,src_dir_fd=qfd,dst_dir_fd=fd,follow_symlinks=False)
    except FileExistsError:
        return False
    os.unlink(name,dir_fd=qfd)
    os.fsync(qfd);os.fsync(fd)
    return True


def commit(folder, package_name, newest_backup_name, newest_backup_sha256, plan_sha256,
           approval, *, enabled=False, approved_setting=None, private_dir='/data/retention_guard',
           lock_path='/data/retention_guard/retention.lock', clear_approval=None, _test_hook=None):
    """One explicit, plan-bound destructive operation; never called automatically.

    Offline tests inject enabled/approved_setting/private_dir. The MCP wrapper
    exposes none of those parameters to the user.
    """
    if enabled is not True:
        raise PermissionError('Produktive Backup-Retention deaktiviert')
    _package(package_name)
    if not isinstance(plan_sha256,str) or not HASH.fullmatch(plan_sha256):
        raise ValueError('Plan-SHA256 ungueltig')
    opt=f'RETENTION|{package_name}|{plan_sha256}'
    arg=f'FREIGABE RETENTION {package_name} {plan_sha256}'
    if not isinstance(approval,str) or not hmac.compare_digest(approval,arg):
        raise PermissionError('Explizite Einzelgenehmigung fehlt')
    if approved_setting is None:
        approved_setting=_read_option('APPROVED_BACKUP_RETENTION','/data/options.json')
    if not isinstance(approved_setting,str) or not hmac.compare_digest(opt,approved_setting):
        raise PermissionError('Separate Home-Assistant-Freigabe fehlt')
    guard = ApprovalStore(private_dir)
    with guard.exclusive():
        if _digest(opt.encode()) in guard._keys():
            raise PermissionError('Retention-Freigabe bereits verbraucht')
        lock=_write_lock(lock_path)
        try:
            fd=_folder(folder)
            try:
                records, actual_plan=_plan(fd,package_name,newest_backup_name,newest_backup_sha256)
                if not hmac.compare_digest(actual_plan,plan_sha256):
                    raise RuntimeError('Dateien seit Vorschau veraendert')
                candidates=records[10:]
                # The journal must fit and its recovery format supports <=100 rows.
                # Fail BEFORE creating a quarantine if it cannot be persisted.
                if len(candidates)>100 or len(_canonical({'format':1,'package':package_name,
                        'plan_sha256':plan_sha256,'records':candidates}))>MAX_JOURNAL:
                    raise ValueError('Zu viele Backup-Kandidaten fuer sicheres Journal')
                qname='.gw14-quarantine-'+uuid.uuid4().hex
                os.mkdir(qname,0o700,dir_fd=fd)
                qfd=os.open(qname,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                moved=[]
                deleted=[]
                try:
                    if os.fstat(qfd).st_mode & 0o077:
                        raise PermissionError('Quarantaene nicht privat')
                    _journal(qfd,{'format':1,'package':package_name,'plan_sha256':plan_sha256,'records':candidates})
                    os.fsync(fd)
                    # Consume before first move, even if later action fails.
                    guard.consume_locked(opt)
                    try:
                        for item in candidates:
                            if _test_hook:_test_hook('before_move',item['name'])
                            # Atomic move; if replaced, we preserve the unexpected inode.
                            os.rename(item['name'],item['name'],src_dir_fd=fd,dst_dir_fd=qfd)
                            moved.append(item)
                            os.fsync(qfd);os.fsync(fd)
                            _preflight(item,qfd)
                            if _test_hook:_test_hook('after_move',item['name'])
                        for item in moved:
                            _preflight(item,qfd)
                        # Each unlink only after successful quarantine+hash verification.
                        for item in moved:
                            if _test_hook:_test_hook('before_delete',item['name'])
                            _preflight(item,qfd)
                            os.unlink(item['name'],dir_fd=qfd)
                            os.fsync(qfd)
                            deleted.append(item['name'])
                            if _test_hook:_test_hook('after_delete',item['name'])
                        os.fsync(fd)
                    except Exception:
                        (clear_approval or clear_consumed_backup_retention_approval)(opt)
                        # Preserve all remaining bytes where possible. Deleted candidates
                        # cannot be reconstructed; the newest ten remain untouched.
                        for item in reversed(moved):
                            try:
                                _restore_one(qfd,fd,item['name'])
                            except (OSError,ValueError):
                                pass
                        raise
                    finally:
                        # A crash leaves journal and quarantine for explicit recovery.
                        try:
                            remnants=[e.name for e in os.scandir(qfd)]
                            if remnants==[JOURNAL]:
                                os.unlink(JOURNAL,dir_fd=qfd)
                                os.fsync(qfd)
                            if not list(os.scandir(qfd)):
                                os.close(qfd);qfd=None
                                os.rmdir(qname,dir_fd=fd);os.fsync(fd)
                        except OSError:
                            pass
                    return {'package_name':package_name,'deleted':deleted,'retained': [r['name'] for r in records[:10]],
                            'plan_sha256':plan_sha256,'approval_consumed':True,
                            'approval_field_cleared':(clear_approval or clear_consumed_backup_retention_approval)(opt),'quarantine_cleaned':qfd is None}
                finally:
                    if qfd is not None:os.close(qfd)
            finally:
                os.close(fd)
        finally:
            _release_lock(lock)


def recover(folder, *, lock_path='/data/retention_guard/retention.lock'):
    """Offline/manual recovery; never auto-run on gateway startup."""
    lock=_write_lock(lock_path)
    try:
        fd=_folder(folder)
        try:
            return _recover_locked(fd)
        finally:os.close(fd)
    finally:_release_lock(lock)


def _recover_locked(fd):
    result={'restored':[],'preserved':[],'cleaned':[],'errors':[]}
    for entry in sorted(e.name for e in os.scandir(fd) if QNAME.fullmatch(e.name)):
        qfd=None
        try:
            qfd=os.open(entry,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            if os.fstat(qfd).st_mode & 0o077:
                raise PermissionError('Quarantaene nicht privat')
            jfd=os.open(JOURNAL,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=qfd)
            try:
                st=os.fstat(jfd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or not (0<st.st_size<=MAX_JOURNAL):
                    raise ValueError('Journal ungueltig')
                data=os.read(jfd,MAX_JOURNAL+1)
                if len(data)!=st.st_size:raise ValueError('Journal geaendert')
            finally:os.close(jfd)
            journal=json.loads(data)
            if not isinstance(journal,dict) or set(journal)!={'format','package','plan_sha256','records'} or journal['format']!=1:
                raise ValueError('Journalformat ungueltig')
            pkg=journal['package'];_package(pkg)
            if not isinstance(journal['plan_sha256'],str) or not HASH.fullmatch(journal['plan_sha256']):
                raise ValueError('Journalhash ungueltig')
            rows=journal['records']
            if not isinstance(rows,list) or not 1<=len(rows)<=100 or len(set(x.get('name','') for x in rows if isinstance(x,dict)))!=len(rows):
                raise ValueError('Journaleintraege ungueltig')
            for row in rows:
                if not isinstance(row,dict) or set(row)!={'name','sha256','size','dev','ino'}:
                    raise ValueError('Journal-Eintrag ungueltig')
                if not BACKUP.fullmatch(row['name']) or not row['name'].startswith(pkg[:-5]+'_'):
                    raise ValueError('Fremdes Backup im Journal')
                for attr in ('size','dev','ino'):
                    if type(row[attr]) is not int or row[attr]<0:
                        raise ValueError('Journal Metadaten ungueltig')
                if not isinstance(row['sha256'],str) or not HASH.fullmatch(row['sha256']):
                    raise ValueError('Journal SHA ungueltig')
            for row in rows:
                try:
                    actual=_read_backup(qfd,row['name'])
                except FileNotFoundError:
                    continue
                if actual!=row:
                    result['preserved'].append(row['name'])
                    continue
                if _restore_one(qfd,fd,row['name']):
                    result['restored'].append(row['name'])
                else:
                    result['preserved'].append(row['name'])
            residual=set(e.name for e in os.scandir(qfd))
            if residual=={JOURNAL}:
                os.unlink(JOURNAL,dir_fd=qfd);os.fsync(qfd)
                os.close(qfd);qfd=None
                os.rmdir(entry,dir_fd=fd);os.fsync(fd)
                result['cleaned'].append(entry)
        except (OSError,ValueError,PermissionError,TypeError,KeyError,RuntimeError) as exc:
            result['errors'].append({'quarantine':entry,'reason':type(exc).__name__})
        finally:
            if qfd is not None:os.close(qfd)
    return result


def _recovery_inventory(fd):
    """Hash the pending private quarantine namespace without disclosing bytes."""
    items=[]
    for ent in sorted(os.scandir(fd),key=lambda e:e.name):
        if not QNAME.fullmatch(ent.name):continue
        qfd=os.open(ent.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            if os.fstat(qfd).st_mode & 0o077:raise PermissionError('Quarantaene nicht privat')
            entries=[]
            for item in sorted(os.scandir(qfd),key=lambda e:e.name):
                if item.name == JOURNAL:
                    h=os.open(JOURNAL,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=qfd)
                    try:
                        st=os.fstat(h)
                        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or not (0<st.st_size<=MAX_JOURNAL):
                            raise PermissionError('Journal nicht sicher')
                        blob=os.read(h,MAX_JOURNAL+1)
                        if len(blob)!=st.st_size:raise RuntimeError('Journal wurde veraendert')
                        entries.append({'name':JOURNAL,'sha256':_digest(blob),'size':len(blob)})
                    finally:os.close(h)
                else:
                    entries.append(_read_backup(qfd,item.name))
            items.append({'quarantine':ent.name,'entries':entries})
        finally:os.close(qfd)
    return items


def plan_recovery(folder):
    fd=_folder(folder)
    try:
        entries=_recovery_inventory(fd)
        if not entries:raise ValueError('Keine offene Quarantaene')
        key=_digest(_canonical({'format':1,'quarantines':entries}))
        return {'pending_quarantines':[e['quarantine'] for e in entries],
                'plan_sha256':key,'approval_setting':'APPROVED_ACTION',
                'approved_change_value':f'RECOVERY|{key}',
                'approval_argument':f'FREIGABE RECOVERY {key}',
                'preview_only':True,'deletion_enabled':False}
    finally:os.close(fd)


def commit_recovery(folder, expected_plan_sha256, approval, *, enabled=False, approved_setting=None,
                    private_dir='/data/retention_guard',lock_path='/data/retention_guard/retention.lock',
                    clear_approval=None):
    if enabled is not True:raise PermissionError('Recovery-Schreibzugriff deaktiviert')
    if not isinstance(expected_plan_sha256,str) or not HASH.fullmatch(expected_plan_sha256):
        raise ValueError('Recovery-Plan-SHA ungueltig')
    option='RECOVERY|'+expected_plan_sha256
    if approval!='FREIGABE RECOVERY '+expected_plan_sha256:
        raise PermissionError('Explizite Recovery-Genehmigung fehlt')
    if approved_setting is None:approved_setting=_read_option('APPROVED_BACKUP_RECOVERY','/data/options.json')
    if not isinstance(approved_setting,str) or not hmac.compare_digest(option,approved_setting):
        raise PermissionError('Separate Recovery-App-Freigabe fehlt')
    ledger=ApprovalStore(private_dir)
    with ledger.exclusive():
        if _digest(option.encode()) in ledger._keys():raise PermissionError('Recovery-Freigabe verbraucht')
        lock=_write_lock(lock_path)
        try:
            fd=_folder(folder)
            try:
                inventory=_recovery_inventory(fd)
                if not inventory or _digest(_canonical({'format':1,'quarantines':inventory}))!=expected_plan_sha256:
                    raise RuntimeError('Recovery-Bestand seit Vorschau geaendert')
                ledger.consume_locked(option)
                cleared=False
                try:
                    result=_recover_locked(fd)
                finally:
                    cleared=(clear_approval or clear_consumed_backup_recovery_approval)(option)
                return {**result,'approval_consumed':True,'approval_field_cleared':cleared}
            finally:os.close(fd)
        finally:_release_lock(lock)
