"""LOCAL-ONLY crash journal and conservative quarantine recovery for Stage 6.

Recovery never resumes deletion. It restores *verified* quarantined backup files
only to absent original filenames; uncertain/corrupt files are left untouched.
No production HAOS paths, no automatic invocation on startup.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from backup_retention_stage3 import _dirfd, _hash_regular_at, BACKUP
from backup_retention_stage5 import _validate, _snapshot, _restore

JOURNAL = '.retention-journal.json'
QNAME = re.compile(r'\.gw-retention-quarantine-[a-f0-9]{32}\Z')
MAX_JOURNAL = 65536


def _safe_fd_at(fd, name):
    return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)


def _manifest_bytes(package, candidates):
    records = []
    for name, snap in candidates.items():
        records.append({'name':name, 'dev':snap[0], 'ino':snap[1],
                        'size':snap[2], 'sha256':snap[3]})
    body = {'format':1,'package':package,'entries':records}
    encoded = json.dumps(body, sort_keys=True, separators=(',',':')).encode()
    return encoded


def create_journal(qfd, package, candidates):
    """Persist intent before FIRST rename; journal + directory are fsynced."""
    data = _manifest_bytes(package,candidates)
    if len(data)>MAX_JOURNAL: raise ValueError('Journal zu groß')
    out = os.open(JOURNAL, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=qfd)
    try:
        with os.fdopen(out,'wb',closefd=False) as file:
            file.write(data);file.flush();os.fsync(out)
    finally:os.close(out)
    os.fsync(qfd)


def clear_journal(qfd):
    os.unlink(JOURNAL,dir_fd=qfd)
    os.fsync(qfd)


def _read_journal(qfd):
    h=_safe_fd_at(qfd,JOURNAL)
    try:
        st=os.fstat(h)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>MAX_JOURNAL or st.st_size<2:
            raise ValueError('Journaltyp oder Größe unzulässig')
        data=os.read(h,MAX_JOURNAL+1)
        if len(data)!=st.st_size:raise ValueError('Journal veränderte sich beim Lesen')
    finally:os.close(h)
    raw=json.loads(data)
    if not isinstance(raw,dict) or set(raw)!={'format','package','entries'} or raw['format']!=1:
        raise ValueError('Journalformat ungültig')
    pkg=raw['package']
    if not isinstance(pkg,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,100}',pkg):
        raise ValueError('Package im Journal ungültig')
    entries=raw['entries']
    if not isinstance(entries,list) or not 1<=len(entries)<=100 or len({repr(x) for x in entries})!=len(entries):
        raise ValueError('Journal-Einträge ungültig')
    found=set()
    for entry in entries:
        if not isinstance(entry,dict) or set(entry)!={'name','dev','ino','size','sha256'}:
            raise ValueError('Journal-Eintrag ungültig')
        name=entry['name'];m=BACKUP.fullmatch(name) if isinstance(name,str) else None
        if not m or m.group(1)!=pkg or name in found:raise ValueError('Backupname im Journal ungültig')
        found.add(name)
        for attr in ('dev','ino','size'):
            if not isinstance(entry[attr],int) or isinstance(entry[attr],bool) or entry[attr]<0:raise ValueError('Metadaten ungültig')
        if not isinstance(entry['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',entry['sha256']):
            raise ValueError('Hash im Journal ungültig')
    return entries


def _reconcile_one(fd,qfd,entry):
    name=entry['name']
    try:
        os.stat(name,dir_fd=qfd,follow_symlinks=False)
    except FileNotFoundError:
        return 'not_in_quarantine'
    try:
        actual=_snapshot(qfd,name)
    except (ValueError,PermissionError,OSError):
        return 'unsafe_preserved'
    expected=(entry['dev'],entry['ino'],entry['size'],entry['sha256'])
    if actual!=expected: return 'modified_preserved'
    # Never overwrite a concurrent newly created destination.
    if not _restore(qfd,fd,name):return 'occupied_preserved'
    os.fsync(qfd);os.fsync(fd)
    return 'restored'


def recover_interrupted_quarantines(folder,*,_test_hook=None):
    """Conservative manual restart recovery; no deletion of backup bytes.

    Only clean fully empty quarantine directories after all entries reconcile.
    Any malformed journal or unfamiliar file keeps quarantine for manual review.
    """
    folder=_validate(folder,'recovery','recovery_2026-11-18_00-00-00_000000.yaml.bak','0'*64,10,False)
    fd=_dirfd(folder); lock=None
    result={'restored':[],'preserved':[],'already_absent':[],'cleaned_quarantines':[], 'errors':[]}
    try:
        lock=os.open(str(folder.parent/'.gw-retention-test.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        fcntl.flock(lock,fcntl.LOCK_EX)
        names=sorted(e.name for e in os.scandir(fd) if QNAME.fullmatch(e.name))
        for qname in names:
            qfd=None
            try:
                qfd=os.open(qname,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                st=os.fstat(qfd)
                if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
                    raise PermissionError('Quarantäne nicht privat')
                entries=_read_journal(qfd)
                for entry in entries:
                    if _test_hook:_test_hook('before_restore',entry['name'],folder)
                    outcome=_reconcile_one(fd,qfd,entry)
                    key={'restored':'restored','not_in_quarantine':'already_absent'}.get(outcome,'preserved')
                    result[key].append({'quarantine':qname,'name':entry['name'],'status':outcome})
                # Strictly verify no unrecognized files exist and no backups remain.
                remnants=[e.name for e in os.scandir(qfd)]
                if remnants==[JOURNAL] or set(remnants)=={JOURNAL}:
                    clear_journal(qfd)
                    os.close(qfd);qfd=None
                    os.rmdir(qname,dir_fd=fd)
                    os.fsync(fd)
                    result['cleaned_quarantines'].append(qname)
                elif any(n!=JOURNAL for n in remnants):
                    result['errors'].append({'quarantine':qname,'reason':'retained_for_manual_review'})
            except (OSError,ValueError,PermissionError,TypeError) as exc:
                result['errors'].append({'quarantine':qname,'reason':type(exc).__name__})
            finally:
                if qfd is not None:os.close(qfd)
        return result
    finally:
        if lock is not None:
            fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
        os.close(fd)
