"""Best-effort clearing of one consumed dashboard approval via Supervisor.

Only a byte-for-byte matching dashboard approval is cleared. Failure cannot make
an already consumed approval reusable (separate on-disk replay ledger).
"""
import hmac
import json
import logging
import os
import urllib.error
import urllib.request
from unified_approval import unified_mode, clear_approval

LOG = logging.getLogger(__name__)
BASE = 'http://supervisor/addons/self'


def clear_consumed_dashboard_approval(value: str, *, token=None, opener=None) -> bool:
    if unified_mode():
        return clear_approval(value, token=token, opener=opener)
    if not isinstance(value, str) or not value.startswith('DASHBOARD|'):
        return False
    token = token if token is not None else os.environ.get('SUPERVISOR_TOKEN')
    if not token:
        return False
    opener = opener or urllib.request.urlopen
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
    try:
        req = urllib.request.Request(BASE + '/options/config', headers=headers, method='GET')
        with opener(req, timeout=4) as resp:
            body = json.load(resp)
        if not isinstance(body, dict) or body.get('result') != 'ok' or not isinstance(body.get('data'), dict):
            return False
        options = body['data']
        actual = options.get('APPROVED_DASHBOARD_CHANGE')
        if not isinstance(actual, str) or not hmac.compare_digest(actual, value):
            return False  # Never erase a newer or different user approval.
        replacement = dict(options)
        replacement['APPROVED_DASHBOARD_CHANGE'] = ''
        req = urllib.request.Request(
            BASE + '/options',
            data=json.dumps({'options': replacement}, separators=(',', ':')).encode('utf-8'),
            headers={**headers, 'Content-Type': 'application/json'}, method='POST')
        with opener(req, timeout=4) as resp:
            answer = json.load(resp)
        if not isinstance(answer, dict) or answer.get('result') != 'ok':
            return False
        # Confirm the persisted option, not merely Supervisor's POST acknowledgement.
        verify_req = urllib.request.Request(BASE + '/options/config', headers=headers, method='GET')
        with opener(verify_req, timeout=4) as resp:
            verified = json.load(resp)
        return (isinstance(verified, dict) and verified.get('result') == 'ok'
                and isinstance(verified.get('data'), dict)
                and verified['data'].get('APPROVED_DASHBOARD_CHANGE') == '')
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError,
            ValueError, TypeError, json.JSONDecodeError) as exc:
        LOG.warning('Dashboard-Freigabe konnte nicht geleert werden (%s)', type(exc).__name__)
        return False


def clear_consumed_dashboard_restore_approval(value: str, *, token=None, opener=None) -> bool:
    if unified_mode():
        return clear_approval(value, token=token, opener=opener)
    """Same Supervisor verification, but a different one-time approval field."""
    if not isinstance(value, str) or not value.startswith('DASHBOARD_RESTORE|'):
        return False
    token = token if token is not None else os.environ.get('SUPERVISOR_TOKEN')
    if not token:
        return False
    opener = opener or urllib.request.urlopen
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
    try:
        req = urllib.request.Request(BASE + '/options/config', headers=headers, method='GET')
        with opener(req, timeout=4) as resp:
            body = json.load(resp)
        if not isinstance(body, dict) or body.get('result') != 'ok' or not isinstance(body.get('data'), dict):
            return False
        options = body['data']
        actual = options.get('APPROVED_DASHBOARD_RESTORE')
        if not isinstance(actual, str) or not hmac.compare_digest(actual, value):
            return False
        replacement = dict(options)
        replacement['APPROVED_DASHBOARD_RESTORE'] = ''
        req = urllib.request.Request(
            BASE + '/options',
            data=json.dumps({'options': replacement}, separators=(',', ':')).encode('utf-8'),
            headers={**headers, 'Content-Type': 'application/json'}, method='POST')
        with opener(req, timeout=4) as resp:
            answer = json.load(resp)
        if not isinstance(answer, dict) or answer.get('result') != 'ok':
            return False
        verify_req = urllib.request.Request(BASE + '/options/config', headers=headers, method='GET')
        with opener(verify_req, timeout=4) as resp:
            verified = json.load(resp)
        return (isinstance(verified, dict) and verified.get('result') == 'ok'
                and isinstance(verified.get('data'), dict)
                and verified['data'].get('APPROVED_DASHBOARD_RESTORE') == '')
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError,
            ValueError, TypeError, json.JSONDecodeError) as exc:
        LOG.warning('Restore-Freigabe konnte nicht geleert werden (%s)', type(exc).__name__)
        return False


def clear_consumed_backup_retention_approval(value: str, *, token=None, opener=None) -> bool:
    if unified_mode():
        return clear_approval(value, token=token, opener=opener)
    """Clear only a matching, consumed GW-14 approval, verify by GET-after-POST."""
    if not isinstance(value, str) or not value.startswith('RETENTION|'):
        return False
    token = token if token is not None else os.environ.get('SUPERVISOR_TOKEN')
    if not token:
        return False
    opener = opener or urllib.request.urlopen
    headers = {'Authorization':'Bearer '+token,'Accept':'application/json'}
    try:
        req=urllib.request.Request(BASE+'/options/config',headers=headers,method='GET')
        with opener(req,timeout=4) as response:
            obj=json.load(response)
        if not isinstance(obj,dict) or obj.get('result')!='ok' or not isinstance(obj.get('data'),dict):
            return False
        original=obj['data']
        current=original.get('APPROVED_BACKUP_RETENTION')
        if not isinstance(current,str) or not hmac.compare_digest(current,value):
            return False
        updated=dict(original);updated['APPROVED_BACKUP_RETENTION']=''
        req=urllib.request.Request(BASE+'/options',data=json.dumps({'options':updated}).encode(),headers={**headers,'Content-Type':'application/json'},method='POST')
        with opener(req,timeout=4) as response:
            status=json.load(response)
        if not isinstance(status,dict) or status.get('result')!='ok':return False
        req=urllib.request.Request(BASE+'/options/config',headers=headers,method='GET')
        with opener(req,timeout=4) as response:
            verified=json.load(response)
        return isinstance(verified,dict) and verified.get('result')=='ok' and isinstance(verified.get('data'),dict) and verified['data'].get('APPROVED_BACKUP_RETENTION')==''
    except (urllib.error.HTTPError,urllib.error.URLError,OSError,ValueError,TypeError,TimeoutError) as exc:
        LOG.warning('GW-14-Freigabe konnte nicht bereinigt werden (%s)',type(exc).__name__)
        return False


def clear_consumed_backup_recovery_approval(value: str, *, token=None, opener=None) -> bool:
    if unified_mode():
        return clear_approval(value, token=token, opener=opener)
    """Clear only the exact consumed recovery approval and verify result."""
    if not isinstance(value,str) or not value.startswith('RECOVERY|'):return False
    token=token if token is not None else os.environ.get('SUPERVISOR_TOKEN')
    if not token:return False
    opener=opener or urllib.request.urlopen
    headers={'Authorization':'Bearer '+token,'Accept':'application/json'}
    try:
        req=urllib.request.Request(BASE+'/options/config',headers=headers,method='GET')
        with opener(req,timeout=4) as response:obj=json.load(response)
        if not isinstance(obj,dict) or obj.get('result')!='ok' or not isinstance(obj.get('data'),dict):return False
        options=obj['data'];current=options.get('APPROVED_BACKUP_RECOVERY')
        if not isinstance(current,str) or not hmac.compare_digest(current,value):return False
        updated=dict(options);updated['APPROVED_BACKUP_RECOVERY']=''
        req=urllib.request.Request(BASE+'/options',data=json.dumps({'options':updated}).encode(),headers={**headers,'Content-Type':'application/json'},method='POST')
        with opener(req,timeout=4) as response:status=json.load(response)
        if not isinstance(status,dict) or status.get('result')!='ok':return False
        req=urllib.request.Request(BASE+'/options/config',headers=headers,method='GET')
        with opener(req,timeout=4) as response:verified=json.load(response)
        return isinstance(verified,dict) and verified.get('result')=='ok' and isinstance(verified.get('data'),dict) and verified['data'].get('APPROVED_BACKUP_RECOVERY')==''
    except (urllib.error.HTTPError,urllib.error.URLError,OSError,ValueError,TypeError,TimeoutError) as exc:
        LOG.warning('GW-14-Recovery-Freigabe konnte nicht bereinigt werden (%s)',type(exc).__name__)
        return False
