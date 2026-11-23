"""Offline-only secured dashboard transaction and backup retention engine.

NOT connected to Home Assistant or gateway.py. All paths used are temporary in tests.
No production WebSocket save implementation. The standalone file-based adapter is ONLY
for isolated simulation and is never mounted at a HA config path.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
from datetime import datetime, timezone
from dashboard_writes import canonical, sha, prepare, approval_value, validate_id

HEX64 = re.compile(r'^[0-9a-f]{64}$')
BACKUP = re.compile(r'^([a-zA-Z0-9_\-]+)_(\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d_\d+)\.yaml\.bak$')


def _durable_write(dirpath, basename, payload):
    """Write a new private file atomically and synchronously; reject symlink directory."""
    path=pathlib.Path(dirpath)
    if path.is_symlink(): raise PermissionError('Backup-Verzeichnis ist ein Symlink')
    path.mkdir(parents=True,exist_ok=True, mode=0o700)
    if path.is_symlink(): raise PermissionError('Backup-Verzeichnis ist ein Symlink')
    fd_dir=os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        tmpname='.'+basename+'.tmp-'+os.urandom(8).hex()
        fd=os.open(tmpname,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd_dir)
        try:
            with os.fdopen(fd,'wb') as fp:
                fp.write(payload);fp.flush();os.fsync(fp.fileno())
            os.rename(tmpname,basename,src_dir_fd=fd_dir,dst_dir_fd=fd_dir)
            os.fsync(fd_dir)
        except BaseException:
            with contextlib.suppress(FileNotFoundError): os.unlink(tmpname,dir_fd=fd_dir)
            raise
    finally:os.close(fd_dir)


class ApprovalStore:
    """Cross-process locked, durable, fail-closed ledger for local isolated tests."""
    def __init__(self, private_dir):
        self.dir=pathlib.Path(private_dir)
        self.dir.mkdir(mode=0o700,parents=True,exist_ok=True)
        if self.dir.is_symlink():raise PermissionError('Datenverzeichnis darf kein Symlink sein')

    @contextlib.contextmanager
    def exclusive(self):
        fd=os.open(self.dir/'dashboard-approvals.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

    def _keys(self):
        file=self.dir/'dashboard-approvals-used.json'
        if not file.exists():return []
        if file.is_symlink():raise PermissionError('Freigabeprotokoll ist Symlink')
        obj=json.loads(file.read_text(encoding='utf-8'))
        if not isinstance(obj,list) or len(obj)>100000 or any(not isinstance(k,str) or not HEX64.fullmatch(k) for k in obj) or len(obj)!=len(set(obj)):
            raise ValueError('Freigabeprotokoll beschädigt')
        return obj

    def consume_locked(self, approval):
        keys=self._keys()
        digest=sha(approval.encode())
        if digest in keys:raise PermissionError('Dashboard-Freigabe bereits verbraucht')
        keys.append(digest)
        _durable_write(self.dir,'dashboard-approvals-used.json',json.dumps(keys,separators=(',',':')).encode())


class OfflineSnapshotStore:
    """Separately namespaced, durable dashboard JSON snapshots; NO HA access."""
    def __init__(self,folder):self.folder=pathlib.Path(folder)
    def create(self,dashboard_id,original):
        validate_id(dashboard_id)
        b=canonical(original)
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        name=dashboard_id+'_'+stamp+'_'+sha(b)[:12]+'.json'
        # Create-once: a collision is refused, never replace previous backup.
        if (self.folder/name).exists():raise FileExistsError('Snapshot existiert')
        _durable_write(self.folder,name,b)
        if (self.folder/name).read_bytes()!=b:raise IOError('Snapshot nicht verifizierbar')
        return {'file':name,'sha256':sha(b),'bytes':len(b)}


def transaction_offline(*, id, original, proposed, option, argument, explicit_consent, store, snapshots, ledger, mode='storage'):
    """Offline simulation only. store must be an in-memory or temporary fake adapter.

    A later integration MUST also ensure the correct dashboard is a storage-mode
    dashboard, explicitly bind ID, use a constrained WS command and independently
    obtain user approval. HA WebSocket does NOT provide atomic CAS.
    """
    if not explicit_consent:raise PermissionError('Ausdrückliche Einzelzustimmung fehlt')
    plan=prepare(id,original,proposed,mode=mode)
    key=approval_value(plan)
    import hmac
    if not hmac.compare_digest(str(option),key) or not hmac.compare_digest(str(argument),'FREIGABE DASHBOARD '+id+' '+plan['proposed_sha256']):
        raise PermissionError('Dashboard-Freigabe ungültig')
    with ledger.exclusive():
        # Anti-replay MUST be checked before checking current dashboard version.
        if sha(key.encode()) in ledger._keys():raise PermissionError('Dashboard-Freigabe bereits verbraucht')
        live=store.read(id)
        if sha(canonical(live))!=plan['expected_sha256']:raise RuntimeError('Dashboard zwischenzeitlich geändert')
        # Snapshot before approval consumption and before fake save.
        snap=snapshots.create(id,live)
        ledger.consume_locked(key)
        store.save(id,proposed)
        if sha(canonical(store.read(id)))!=plan['proposed_sha256']:
            raise RuntimeError('Nachkontrolle fehlgeschlagen; Snapshot vorhanden')
        return {'mode':'OFFLINE_ONLY','dashboard_id':id,'sha256':plan['proposed_sha256'],'snapshot':snap,'approval_consumed':True}


def plan_yaml_backup_retention(folder, *, keep_per_package=10):
    """Dry-run ONLY. Never deletes; recognizes only own backup file names.

    Never execute on a real /config path from this module. The future production
    implementation must run ONLY after successful backup+SHA verification and
    explicit opt-in, while holding a write lock.
    """
    if keep_per_package<2:raise ValueError('Mindestens zwei Sicherungen behalten')
    folder=pathlib.Path(folder)
    if folder.is_symlink():raise PermissionError('Backup-Verzeichnis ist Symlink')
    groups={}
    for p in folder.iterdir():
        m=BACKUP.fullmatch(p.name)
        if not m or p.is_symlink() or not p.is_file():continue
        groups.setdefault(m.group(1),[]).append(p)
    deletable=[]; retained=[]
    for name,files in sorted(groups.items()):
        # Timestamp is sortable under the enforced name format; never remove newest.
        files=sorted(files,key=lambda x:x.name,reverse=True)
        retained.extend(p.name for p in files[:keep_per_package])
        deletable.extend(p.name for p in files[keep_per_package:])
    return {'dry_run':True,'keep_per_package':keep_per_package,
            'would_delete':sorted(deletable),'retained_count':len(retained),
            'deletes_performed':0}
