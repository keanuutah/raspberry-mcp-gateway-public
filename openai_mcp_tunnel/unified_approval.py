"""Single, action-scoped, fail-closed HA App approval. Never exposes credentials."""
import hmac
import json
import logging
import os
import urllib.error
import urllib.request

LOG = logging.getLogger(__name__)
FIELD = 'APPROVED_ACTION'
BASE = 'http://supervisor/addons/self'


def unified_mode():
    return os.environ.get('APPROVAL_MODE') == 'unified'


def read_approval(path='/data/options.json'):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r', encoding='utf-8') as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise PermissionError('Ungültige HA-App-Einstellungen')
    value = obj.get(FIELD, '')
    if not isinstance(value, str):
        raise PermissionError('Ungültiges Freigabefeld')
    return value


def clear_approval(expected, *, token=None, opener=None):
    """Never clear a different newly entered approval. Existing ledgers block replay."""
    if not isinstance(expected, str) or not expected or '|' not in expected:
        return False
    token = token if token is not None else os.environ.get('SUPERVISOR_TOKEN')
    if not token:
        return False
    opener = opener or urllib.request.urlopen
    headers = {'Authorization': 'Bearer '+token, 'Accept': 'application/json'}
    try:
        def fetch():
            req = urllib.request.Request(BASE+'/options/config',headers=headers,method='GET')
            with opener(req,timeout=4) as resp:
                obj=json.load(resp)
            if not isinstance(obj,dict) or obj.get('result')!='ok' or not isinstance(obj.get('data'),dict):
                raise ValueError('Supervisor options invalid')
            return obj['data']
        options=fetch()
        if not isinstance(options.get(FIELD),str) or not hmac.compare_digest(options[FIELD],expected):
            return False
        updated=dict(options)
        updated[FIELD]=''
        req=urllib.request.Request(BASE+'/options',data=json.dumps({'options':updated}).encode('utf-8'),
           headers={**headers,'Content-Type':'application/json'},method='POST')
        with opener(req,timeout=4) as resp:
            result=json.load(resp)
        if not isinstance(result,dict) or result.get('result')!='ok':return False
        return fetch().get(FIELD)==''
    except (OSError, ValueError, TypeError, TimeoutError, urllib.error.URLError) as exc:
        LOG.warning('Zentrales Freigabefeld nicht bereinigt (%s)', type(exc).__name__)
        return False
