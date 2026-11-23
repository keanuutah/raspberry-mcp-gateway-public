"""Read-only Home Assistant Lovelace WebSocket client for the Raspberry gateway.

No save/mutate command is implemented. Uses the already-configured internal HA host
and server-side HA token. Do not log raw websocket traffic or secrets.
"""
import asyncio
import json
import os
import re
from urllib.parse import urlsplit

import websockets

ALLOWED_UPSTREAM = {
    'http://homeassistant.local:8123/api/mcp': 'ws://homeassistant.local:8123/api/websocket',
    'http://homeassistant:8123/api/mcp': 'ws://homeassistant:8123/api/websocket',
}
DASH_ID = re.compile(r'^[a-z0-9][a-z0-9_-]{0,99}$')
SECRET_KEY = re.compile(r'(?:token|password|secret|api[_-]?key|authorization|access[_-]?key|client[_-]?secret|credential)', re.I)
SENSITIVE_INLINE = re.compile(r'(?i)(bearer\s+\S+|(?:token|api[_-]?key|password|secret)=[^&\s]+)')
MAX_RESULT_BYTES = 384 * 1024
MAX_DEPTH = 35
# Only explicitly known, non-sensitive protocol identifiers may leave the gateway.
PUBLIC_ERROR_CODES = frozenset({
    'config_not_found', 'unauthorized', 'forbidden', 'invalid_format',
    'not_found', 'unknown_command', 'unknown_error',
})


class DashboardWebSocketError(ValueError):
    """A dashboard request failed; never retain HA's potentially sensitive message."""

    def __init__(self, code: str):
        self.code = code if code in PUBLIC_ERROR_CODES else 'other'
        super().__init__(f'Dashboard-WebSocket-Fehler: {self.code}')


def _target_url(upstream: str) -> str:
    try:
        return ALLOWED_UPSTREAM[upstream]
    except KeyError:
        raise ValueError('Dashboard-Abfrage nur über konfigurierte interne HA-Adresse erlaubt') from None


def _sanitize(value, depth=0):
    if depth > MAX_DEPTH:
        return '[Verschachtelung zu tief]'
    if isinstance(value, dict):
        return {str(k): ('[REDACTED]' if SECRET_KEY.search(str(k)) else _sanitize(v, depth+1)) for k,v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v, depth+1) for v in value]
    if isinstance(value, str):
        return SENSITIVE_INLINE.sub('[REDACTED]', value)
    return value


async def _ws_command(command: dict, *, upstream: str, token: str) -> object:
    url = _target_url(upstream)
    if not isinstance(token, str) or not token:
        raise ValueError('HA-Token fehlt')
    try:
        async with asyncio.timeout(15):
            async with websockets.connect(url, open_timeout=8, max_size=MAX_RESULT_BYTES, compression=None, proxy=None) as ws:
                hello = json.loads(await ws.recv())
                if hello.get('type') != 'auth_required':
                    raise ValueError('Unerwarteter WebSocket-Handshake')
                await ws.send(json.dumps({'type':'auth','access_token':token}))
                ack = json.loads(await ws.recv())
                if ack.get('type') != 'auth_ok':
                    raise ValueError('Home-Assistant-WebSocket-Authentifizierung fehlgeschlagen')
                await ws.send(json.dumps({'id':1, **command}))
                msg = json.loads(await ws.recv())
                if msg.get('id') != 1 or msg.get('type') != 'result':
                    raise ValueError('Unerwartete Dashboard-Antwort')
                if not msg.get('success'):
                    # The error *message* may contain credentials, URLs or YAML.
                    # Publish only an explicit, fixed allowlist of error codes.
                    error = msg.get('error')
                    raw_code = error.get('code') if isinstance(error, dict) else None
                    code = raw_code if isinstance(raw_code, str) else 'other'
                    raise DashboardWebSocketError(code)
                return msg.get('result')
    except (OSError, TimeoutError, websockets.exceptions.WebSocketException):
        raise ValueError('Dashboard-Leseverbindung fehlgeschlagen') from None
    except (json.JSONDecodeError, TypeError, UnicodeError):
        raise ValueError('Ungültige Antwort von Home Assistant') from None


async def dashboard_list(*, upstream: str | None = None, token: str | None = None) -> dict:
    if upstream is None: upstream=os.environ['HA_MCP_SERVER_URL']
    if token is None: token=os.environ['HA_ACCESS_TOKEN']
    items = await _ws_command({'type':'lovelace/dashboards/list'},upstream=upstream,token=token)
    if not isinstance(items, list):
        raise ValueError('Dashboard-Liste ist ungültig')
    if len(items)>200: raise ValueError('Zu viele Dashboards')
    clean=[]
    for d in items:
        if not isinstance(d,dict): continue
        # Return a strict allowlist, not arbitrary dashboard metadata.
        clean.append({k:_sanitize(d[k]) for k in ('url_path','title','mode','icon','show_in_sidebar','require_admin') if k in d})
    return {'dashboards': clean, 'read_only':True, 'default_dashboard':'default'}


async def dashboard_read(dashboard_id: str, *, upstream: str | None = None, token: str | None = None) -> dict:
    if not isinstance(dashboard_id,str) or not DASH_ID.fullmatch(dashboard_id):
        raise ValueError('Ungültige Dashboard-ID')
    if upstream is None: upstream=os.environ['HA_MCP_SERVER_URL']
    if token is None: token=os.environ['HA_ACCESS_TOKEN']
    listing = await dashboard_list(upstream=upstream,token=token)
    matches = [d for d in listing['dashboards'] if d.get('url_path')==dashboard_id]
    if dashboard_id!='default' and not matches:
        raise ValueError('Dashboard-ID nicht in der HA-Dashboard-Liste')
    # The built-in default dashboard omits url_path in lovelace/config.
    cmd={'type':'lovelace/config'}
    if dashboard_id!='default': cmd['url_path']=dashboard_id
    try:
        config=await _ws_command(cmd,upstream=upstream,token=token)
    except DashboardWebSocketError as exc:
        if dashboard_id != 'default' or exc.code != 'config_not_found':
            raise
        # An auto-generated Overview need not have a stored Lovelace config.
        # Never fabricate a stored configuration or claim that we fetched the
        # dynamically generated cards from the frontend.
        return {
            'dashboard_id': 'default',
            'mode': 'generated_or_unconfigured',
            'config': None,
            'stored_config_found': False,
            'websocket_error_code': 'config_not_found',
            'note': ('Keine gespeicherte Konfiguration vorhanden. Die HA-Oberfläche '
                     'kann ihre Standardübersicht dynamisch erzeugen; die sichtbaren '
                     'Karten wurden nicht ausgelesen.'),
            'sensitive_fields_redacted': True,
            'read_only': True,
        }
    if not isinstance(config,dict):
        raise ValueError('Dashboard-Konfiguration ist ungültig')
    clean=_sanitize(config)
    if len(json.dumps(clean,ensure_ascii=False).encode('utf-8'))>MAX_RESULT_BYTES:
        raise ValueError('Dashboard zu groß zur sicheren Ausgabe')
    return {'dashboard_id':dashboard_id,'mode': matches[0].get('mode','unknown') if matches else 'unknown', 'config':clean, 'sensitive_fields_redacted':True,'read_only':True}
