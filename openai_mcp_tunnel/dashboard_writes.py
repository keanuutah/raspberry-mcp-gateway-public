"""GW-13 isolated preview / one-time approval core, NOT wired into gateway.py.

Deliberately no network transport, no production save, no HA filesystem access.
An integration must explicitly supply a constrained storage-dashboard adapter
and separately obtain user consent before each commit invocation.
"""
from __future__ import annotations
import difflib
import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path

DASH_ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,99}$')
SHA = re.compile(r'^[0-9a-f]{64}$')
MAX_BYTES = 384 * 1024
MAX_DEPTH = 35


def canonical(value):
    """Deterministic serialization; rejects non-JSON and duplicate-like invalid input."""
    def check(v, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError('Dashboard-Konfiguration zu tief verschachtelt')
        if isinstance(v, dict):
            if any(not isinstance(k, str) for k in v):
                raise ValueError('Nur JSON-Schlüssel erlaubt')
            return {k: check(x, depth+1) for k, x in v.items()}
        if isinstance(v, list):
            return [check(x, depth+1) for x in v]
        if v is None or isinstance(v, (str, bool, int)):
            return v
        if isinstance(v, float):
            raise ValueError('Float-Werte im sicheren Prototyp nicht erlaubt')
        raise ValueError('Kein gültiger JSON-Wert')
    data = json.dumps(check(value), sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(data) > MAX_BYTES:
        raise ValueError('Dashboard zu groß')
    return data


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_id(dashboard_id):
    if not isinstance(dashboard_id, str) or not DASH_ID.fullmatch(dashboard_id):
        raise ValueError('Ungültige Dashboard-ID')
    return dashboard_id


def prepare(dashboard_id, current, proposed, *, mode='storage'):
    validate_id(dashboard_id)
    if mode != 'storage':
        raise PermissionError('Nur Storage-Dashboards schreibbar')
    if not isinstance(current, dict) or not isinstance(proposed, dict):
        raise ValueError('Dashboard muss ein JSON-Objekt sein')
    old, new = canonical(current), canonical(proposed)
    if old == new:
        raise ValueError('Keine Änderung')
    # Diff may contain secrets; it must be explicitly requested, then redacted
    # at presentation; do not expose it automatically from this function.
    return {'dashboard_id':dashboard_id,'expected_sha256':sha(old),
            'proposed_sha256':sha(new),'modified':True,
            'preview_only':True,'requires_explicit_approval':True}


def approval_value(plan):
    validate_id(plan['dashboard_id'])
    for key in ('expected_sha256','proposed_sha256'):
        if not SHA.fullmatch(plan[key]):
            raise ValueError('Ungültiger SHA256')
    return ('DASHBOARD|' + plan['dashboard_id'] + '|' +
            plan['expected_sha256'] + '|' + plan['proposed_sha256'])


def preview_diff(current, proposed, max_chars=12000):
    """Separate function because raw diff might contain credentials.

    Caller MUST sanitize/redact it before any user-facing response or log.
    """
    a = json.dumps(json.loads(canonical(current)), ensure_ascii=False,
                   sort_keys=True, indent=2).splitlines(keepends=True)
    b = json.dumps(json.loads(canonical(proposed)), ensure_ascii=False,
                   sort_keys=True, indent=2).splitlines(keepends=True)
    return ''.join(difflib.unified_diff(a,b,fromfile='current',tofile='proposed'))[:max_chars]


class OfflineApprovalLedger:
    """Persistent anti-replay demo, isolated outside HA and not for multi-process use.

    Production will need filesystem locking, fail-closed load, fsync and protected
    app-private storage. A ledger that cannot be persisted MUST stop a commit.
    """
    def __init__(self, path):
        self.path = Path(path)

    def _read(self):
        if not self.path.exists():
            return []
        obj=json.loads(self.path.read_text(encoding='utf-8'))
        if (not isinstance(obj,list) or
            any(not isinstance(v,str) or not SHA.fullmatch(v) for v in obj)):
            raise ValueError('Freigabeprotokoll beschädigt; Abbruch')
        return obj

    def assert_unused(self, approval):
        if sha(approval.encode('utf-8')) in self._read():
            raise PermissionError('Freigabe bereits verbraucht')

    def consume(self, approval):
        used=self._read()
        key=sha(approval.encode('utf-8'))
        if key in used:
            raise PermissionError('Freigabe bereits verbraucht')
        used.append(key)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd, temp=tempfile.mkstemp(prefix='dashboard-ledger-',dir=self.path.parent)
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as out:
                json.dump(used,out)
                out.flush(); os.fsync(out.fileno())
            os.replace(temp,self.path)
        finally:
            if os.path.exists(temp): os.unlink(temp)


def simulate_authorized_save(*, dashboard_id, original, proposed,
                             approval_option, approval_argument, ledger, adapter,
                             explicit_consent=False, mode='storage'):
    """OFFLINE ONLY: adapter is a fake dashboard store in tests.

    No HA WebSocket save here. A production adapter must atomically snapshot
    before any save and report conflicts; WebSocket does not guarantee CAS.
    """
    if not explicit_consent:
        raise PermissionError('Separate Benutzerzustimmung erforderlich')
    plan=prepare(dashboard_id,original,proposed,mode=mode)
    key=approval_value(plan)
    if not (hmac.compare_digest(str(approval_option),key) and
            hmac.compare_digest(str(approval_argument),
                                'FREIGABE DASHBOARD '+dashboard_id+' '+plan['proposed_sha256'])):
        raise PermissionError('Dashboard-Einmalfreigabe fehlt')
    ledger.assert_unused(key)
    if sha(canonical(adapter.read(dashboard_id)))!=plan['expected_sha256']:
        raise RuntimeError('Dashboard seit Vorschau verändert; kein Schreiben')
    # This prototype consumes approval and snapshots before the fake save.
    # Never reuse after a failure. Real backup needs durable audited storage.
    ledger.consume(key)
    adapter.backup(dashboard_id,canonical(original))
    adapter.save(dashboard_id,json.loads(canonical(proposed)))
    if sha(canonical(adapter.read(dashboard_id)))!=plan['proposed_sha256']:
        raise RuntimeError('Nachkontrolle fehlgeschlagen')
    return {'dashboard_id':dashboard_id,'sha256':plan['proposed_sha256'],
            'backup_created':True,'offline_simulation':True}
