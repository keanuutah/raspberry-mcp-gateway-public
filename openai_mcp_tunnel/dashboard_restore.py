"""GW-13-R: guarded snapshot-to-dashboard restore.

Offline candidate, NOT enabled by default. Never returns snapshot JSON.
Uses existing dashboard storage reader, durable backup and replay ledger.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import stat

from dashboard_writes import canonical, sha, validate_id
from dashboard_commit import raw_storage_dashboard, _read_option, _changed_paths
from dashboard_safety_stage2 import ApprovalStore, OfflineSnapshotStore
from dashboard_snapshot_metadata import SNAP_NAME, MAX_SNAPSHOT_BYTES, _open_snapshots_dir
from dashboard_approval_reset import clear_consumed_dashboard_restore_approval
from dashboards import _ws_command, _target_url

HASH = re.compile(r'[0-9a-f]{64}\Z')


def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('Doppelter Snapshot-JSON-Schlüssel')
        obj[key] = value
    return obj


def _snapshot(dashboard_id: str, name: str, expected_hash: str, *, open_dir=None):
    """Read one bounded, fd-bound, regular snapshot; verify canonical encoding.

    open_dir injection is only for offline tests, never exposed as an MCP argument.
    """
    validate_id(dashboard_id)
    if not isinstance(name, str):
        raise ValueError('Snapshot-Name ungültig')
    match = SNAP_NAME.fullmatch(name)
    if not match or match.group(1) != dashboard_id:
        raise PermissionError('Snapshot gehört nicht zu dieser Dashboard-ID')
    if not isinstance(expected_hash, str) or not HASH.fullmatch(expected_hash):
        raise ValueError('Snapshot-SHA256 ungültig')
    dirfd = (open_dir or _open_snapshots_dir)()
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not (1 <= before.st_size <= MAX_SNAPSHOT_BYTES):
                raise ValueError('Snapshot muss regulär und größenbegrenzt sein')
            chunks = []
            amount = 0
            while True:
                chunk = os.read(fd, min(65536, MAX_SNAPSHOT_BYTES + 1 - amount))
                if not chunk:
                    break
                amount += len(chunk)
                if amount > MAX_SNAPSHOT_BYTES:
                    raise ValueError('Snapshot zu groß')
                chunks.append(chunk)
            after = os.fstat(fd)
            if (amount != before.st_size or amount != after.st_size or
                (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)):
                raise IOError('Snapshot während des Lesens verändert')
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)
    data = b''.join(chunks)
    digest = sha(data)
    if not hmac.compare_digest(digest, expected_hash) or not digest.startswith(match.group(3)):
        raise ValueError('Snapshot-Integritätsprüfung fehlgeschlagen')
    obj = json.loads(data.decode('utf-8'), object_pairs_hook=_no_duplicates,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Ungültiger JSON-Wert')))
    if not isinstance(obj, dict) or canonical(obj) != data:
        raise ValueError('Snapshot ist nicht kanonisch oder kein JSON-Objekt')
    return obj


def _approval(dashboard_id, snapshot_name, current_sha256, snapshot_sha256):
    return f'DASHBOARD_RESTORE|{dashboard_id}|{snapshot_name}|{current_sha256}|{snapshot_sha256}'


def _argument(dashboard_id, snapshot_name, snapshot_sha256):
    return f'FREIGABE RESTORE {dashboard_id} {snapshot_name} {snapshot_sha256}'


async def dashboard_plan_restore(dashboard_id: str, snapshot_name: str, snapshot_sha256: str,
                                 *, upstream=None, token=None, read=None, open_dir=None):
    """Pure read-only preview. No snapshot payload in result."""
    original = _snapshot(dashboard_id, snapshot_name, snapshot_sha256, open_dir=open_dir)
    upstream = upstream or os.environ['HA_MCP_SERVER_URL']
    token = token or os.environ['HA_ACCESS_TOKEN']
    current = await (read or raw_storage_dashboard)(dashboard_id, upstream=upstream, token=token)
    current_sha = sha(canonical(current))
    if current_sha == snapshot_sha256:
        raise ValueError('Dashboard entspricht dem Snapshot bereits')
    return {
        'dashboard_id': dashboard_id, 'snapshot_name': snapshot_name,
        'expected_sha256': current_sha, 'proposed_sha256': snapshot_sha256,
        'changed_paths': _changed_paths(current, original),
        'approval_setting': 'APPROVED_ACTION',
        'approved_change_value': _approval(dashboard_id, snapshot_name, current_sha, snapshot_sha256),
        'approval_argument': _argument(dashboard_id, snapshot_name, snapshot_sha256),
        'preview_only': True, 'snapshot_contents_disclosed': False,
        'warning': 'Kein atomarer CAS-Schutz bei parallelen HA-UI-Änderungen',
    }


async def dashboard_commit_restore(dashboard_id: str, snapshot_name: str, snapshot_sha256: str,
                                   expected_sha256: str, approval: str, *, upstream=None,
                                   token=None, read=None, save=None, open_dir=None,
                                   options_file='/data/options.json',
                                   private_dir='/data/dashboard_guard', enabled=None,
                                   explicit_consent=False, clear_approval=None):
    """One approved restore; HA writes only via existing constrained WebSocket path.

    An offline test may inject fake read/save and a temp directory; no such args
    are exposed in the gateway's MCP wrapper.
    """
    if not explicit_consent:
        raise PermissionError('Ausdrückliche Restore-Einzelfreigabe erforderlich')
    if enabled is None:
        enabled = os.environ.get('DASHBOARD_RESTORE_ENABLED', 'false') == 'true'
    if not enabled:
        raise PermissionError('Dashboard-Restore deaktiviert')
    validate_id(dashboard_id)
    if not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256):
        raise ValueError('Ausgangs-SHA256 ungültig')
    if not isinstance(snapshot_sha256, str) or not HASH.fullmatch(snapshot_sha256):
        raise ValueError('Snapshot-SHA256 ungültig')
    expected_option = _approval(dashboard_id, snapshot_name, expected_sha256, snapshot_sha256)
    option = _read_option('APPROVED_DASHBOARD_RESTORE', options_file)
    if not isinstance(option, str) or not hmac.compare_digest(option, expected_option):
        raise PermissionError('Getrennte Restore-Freigabe in App-Einstellungen fehlt')
    if not isinstance(approval, str) or not hmac.compare_digest(
            approval, _argument(dashboard_id, snapshot_name, snapshot_sha256)):
        raise PermissionError('Ausdrückliche Restore-Freigabe ungültig')
    upstream = upstream or os.environ['HA_MCP_SERVER_URL']
    token = token or os.environ['HA_ACCESS_TOKEN']
    _target_url(upstream)
    store = ApprovalStore(private_dir)
    snapshots = OfflineSnapshotStore(os.path.join(private_dir, 'snapshots'))
    with store.exclusive():
        if sha(expected_option.encode()) in store._keys():
            raise PermissionError('Restore-Freigabe bereits verbraucht')
        # Re-read verified snapshot inside the exclusive ledger lock.
        target = _snapshot(dashboard_id, snapshot_name, snapshot_sha256, open_dir=open_dir)
        current = await (read or raw_storage_dashboard)(dashboard_id, upstream=upstream, token=token)
        if sha(canonical(current)) != expected_sha256:
            raise RuntimeError('Dashboard seit Restore-Vorschau geändert')
        if current == target:
            raise ValueError('Keine Änderung')
        rollback = snapshots.create(dashboard_id, current)
        store.consume_locked(expected_option)
        cmd = {'type': 'lovelace/config/save', 'config': target}
        if dashboard_id != 'default':
            cmd['url_path'] = dashboard_id
        cleared = False
        try:
            if save is None:
                await _ws_command(cmd, upstream=upstream, token=token)
            else:
                await save(cmd, upstream=upstream, token=token)
            after = await (read or raw_storage_dashboard)(dashboard_id, upstream=upstream, token=token)
            if sha(canonical(after)) != snapshot_sha256:
                raise RuntimeError('Restore-Nachprüfung fehlgeschlagen')
        except Exception:
            raise RuntimeError('Restore/Nachprüfung fehlgeschlagen; Rücksicherung vorhanden, Freigabe verbraucht') from None
        finally:
            cleared = (clear_approval or clear_consumed_dashboard_restore_approval)(expected_option)
        return {'dashboard_id': dashboard_id, 'restored': True,
                'sha256': snapshot_sha256, 'rollback_snapshot': rollback,
                'approval_consumed': True, 'approval_field_cleared': cleared,
                'warning': 'Kein atomarer CAS-Schutz gegen parallele HA-UI-Änderungen'}
