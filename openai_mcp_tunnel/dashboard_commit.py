"""Constrained Home Assistant dashboard write path (local integration candidate).

Default disabled. User must separately set APPROVED_DASHBOARD_CHANGE in HA app
settings and approve each MCP invocation. This module never writes .storage.
"""
from __future__ import annotations
from unified_approval import unified_mode, read_approval
import hmac
import json
import os
import re
from dashboard_writes import canonical, sha, prepare, approval_value, validate_id
from dashboard_safety_stage2 import ApprovalStore, OfflineSnapshotStore
from dashboards import _ws_command, dashboard_list, _target_url
from dashboard_approval_reset import clear_consumed_dashboard_approval

SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_CONFIG_BYTES = 384 * 1024


def parse_proposed(value):
    if not isinstance(value, str) or len(value.encode('utf-8')) > MAX_CONFIG_BYTES:
        raise ValueError('Dashboard-Vorschlag fehlt oder ist zu groß')
    def no_duplicate(pairs):
        d = {}
        for k, v in pairs:
            if k in d: raise ValueError('Doppelter Dashboard-JSON-Schlüssel')
            d[k] = v
        return d
    proposed = json.loads(value, object_pairs_hook=no_duplicate)
    if not isinstance(proposed,dict):raise ValueError('Dashboard muss JSON-Objekt sein')
    canonical(proposed)
    return proposed


async def raw_storage_dashboard(dashboard_id, *, upstream, token, command=None):
    validate_id(dashboard_id)
    listing = await dashboard_list(upstream=upstream,token=token)
    entries = [entry for entry in listing['dashboards'] if (entry.get('url_path') in (None, 'default') if dashboard_id == 'default' else entry.get('url_path') == dashboard_id)]
    if dashboard_id == 'default':
        # HA's built-in default may have url_path null, omit it on WS wire.
        if len(entries) != 1 or entries[0].get('mode') != 'storage':
            raise PermissionError('Standarddashboard ist nicht im Storage-Modus')
    elif len(entries) != 1 or entries[0].get('mode') != 'storage':
        raise PermissionError('Dashboard ist nicht eindeutig als Storage-Dashboard gelistet')
    cmd={'type':'lovelace/config'}
    if dashboard_id != 'default': cmd['url_path']=dashboard_id
    raw = await (command or _ws_command)(cmd,upstream=upstream,token=token)
    if not isinstance(raw,dict):raise ValueError('Dashboard-Konfiguration ungültig')
    canonical(raw) # full raw, never sanitized before hashing or saving
    return raw


async def dashboard_plan_write(dashboard_id, proposed_json, *, upstream=None, token=None,
                               read=None):
    upstream = upstream or os.environ['HA_MCP_SERVER_URL']
    token = token or os.environ['HA_ACCESS_TOKEN']
    proposed = parse_proposed(proposed_json)
    old = await (read or raw_storage_dashboard)(dashboard_id,upstream=upstream,token=token)
    plan = prepare(dashboard_id,old,proposed,mode='storage')
    return {**plan, 'changed_paths':_changed_paths(old,proposed),
            'approval_setting':'APPROVED_ACTION',
            'approved_change_value':approval_value(plan),
            'approval_argument':f"FREIGABE DASHBOARD {dashboard_id} {plan['proposed_sha256']}",
            'note':'Eine Vorschau, KEINE Freigabe. Nur eine gesonderte Einstellung plus ausdrückliche Benutzerzustimmung erlaubt Schreiben.'}


def _changed_paths(old, new, prefix='', depth=0, limit=80):
    """Return only changed JSON paths, never values or keys suspiciously containing secrets."""
    if depth > 15:return ['[tiefe Struktur]']
    if type(old) is not type(new):return [prefix or '/']
    if isinstance(old, dict):
        output=[]
        for k in sorted(set(old)|set(new)):
            # Keys themselves can be sensitive; mask suspicious key labels.
            safe = '[sensibel]' if any(word in k.lower() for word in ('token','password','secret','key','auth','credential')) else k[:64]
            path=prefix+'/'+safe.replace('~','~0').replace('/','~1')
            if k not in old or k not in new: output.append(path)
            else:output.extend(_changed_paths(old[k],new[k],path,depth+1))
            if len(output)>=limit:break
        return output[:limit]
    if isinstance(old,list):
        output=[]
        for i in range(max(len(old),len(new))):
            path=prefix+'/'+str(i)
            if i>=len(old) or i>=len(new):output.append(path)
            else:output.extend(_changed_paths(old[i],new[i],path,depth+1))
            if len(output)>=limit:break
        return output[:limit]
    return [prefix or '/'] if old!=new else []


def _read_option(name,options_file='/data/options.json'):
    if unified_mode():
        return read_approval(options_file)
    fd=os.open(options_file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        with os.fdopen(fd,'r',encoding='utf-8') as stream: obj=json.load(stream)
    finally:pass
    if not isinstance(obj,dict):raise PermissionError('App-Optionen ungültig')
    return obj.get(name,'')


async def dashboard_commit_write(dashboard_id, proposed_json, expected_sha256,
                                 proposed_sha256, approval, *,
                                 upstream=None, token=None, read=None, save=None,
                                 options_file='/data/options.json', private_dir='/data/dashboard_guard',
                                 enabled=None, explicit_consent=False):
    """Commit with durable snapshot + independent replay ledger; ws save is injected for offline testing.

    No atomic CAS in HA's Lovelace WebSocket API. A racing HA UI change after the
    final read can still be overwritten. Until solved, leave product flag disabled.
    """
    if not explicit_consent:raise PermissionError('Ausdrückliche Einzelfreigabe erforderlich')
    if enabled is None:enabled=os.environ.get('DASHBOARD_WRITE_ENABLED','false')=='true'
    if not enabled:raise PermissionError('Dashboard-Schreibfunktion deaktiviert')
    validate_id(dashboard_id)
    if not isinstance(expected_sha256,str) or not SHA.fullmatch(expected_sha256):raise ValueError('Original-SHA256 ungültig')
    if not isinstance(proposed_sha256,str) or not SHA.fullmatch(proposed_sha256):raise ValueError('Vorschlag-SHA256 ungültig')
    proposed = parse_proposed(proposed_json)
    if not hmac.compare_digest(sha(canonical(proposed)),proposed_sha256):raise ValueError('Vorschlag passt nicht zum SHA256')
    expected_approval=f'DASHBOARD|{dashboard_id}|{expected_sha256}|{proposed_sha256}'
    if not hmac.compare_digest(str(_read_option('APPROVED_DASHBOARD_CHANGE',options_file)),expected_approval):
        raise PermissionError('Unabhängige Freigabe in App-Einstellungen fehlt')
    expected_argument=f'FREIGABE DASHBOARD {dashboard_id} {proposed_sha256}'
    if not hmac.compare_digest(str(approval),expected_argument):raise PermissionError('Dashboard-Freigabewert ungültig')
    upstream=upstream or os.environ['HA_MCP_SERVER_URL']
    token=token or os.environ['HA_ACCESS_TOKEN']
    _target_url(upstream)
    store=ApprovalStore(private_dir)
    snapshots=OfflineSnapshotStore(os.path.join(private_dir,'snapshots'))
    with store.exclusive():
        if sha(expected_approval.encode()) in store._keys():raise PermissionError('Einmalfreigabe bereits verbraucht')
        current=await (read or raw_storage_dashboard)(dashboard_id,upstream=upstream,token=token)
        if sha(canonical(current))!=expected_sha256:raise RuntimeError('Dashboard wurde seit Vorschau verändert')
        if current==proposed:raise ValueError('Keine Änderung')
        # Snapshot must persist BEFORE irreversible approval consumption and save.
        snapshot=snapshots.create(dashboard_id,current)
        store.consume_locked(expected_approval)
        command={'type':'lovelace/config/save','config':proposed}
        if dashboard_id!='default':command['url_path']=dashboard_id
        # Once consumed, attempt to clear the visible option on success AND on error.
        # Ledger protection remains authoritative if Supervisor is unavailable.
        approval_field_cleared = False
        try:
            if save is None:
                response=await _ws_command(command,upstream=upstream,token=token)
            else:
                response=await save(command,upstream=upstream,token=token)
            new=await (read or raw_storage_dashboard)(dashboard_id,upstream=upstream,token=token)
            if sha(canonical(new))!=proposed_sha256:raise RuntimeError('Nachkontrolle fehlgeschlagen')
        except Exception:
            # NO auto rollback: may overwrite a newer HA UI change.
            raise RuntimeError('Dashboard-Speicherung/Nachprüfung fehlgeschlagen; Snapshot vorhanden, Freigabe verbraucht') from None
        finally:
            approval_field_cleared = clear_consumed_dashboard_approval(expected_approval)
        return {'dashboard_id':dashboard_id,'saved':True,'sha256':proposed_sha256,
                'snapshot':snapshot,'approval_consumed':True,
                'approval_setting_clear_attempted':True,
                'approval_field_cleared':approval_field_cleared,
                'warning':'Kein atomarer CAS-Schutz gegen gleichzeitige HA-UI-Schreibvorgänge'}
