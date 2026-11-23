#!/bin/sh
set -eu
umask 077
OPTIONS=/data/options.json
for k in CONTROL_PLANE_TUNNEL_ID CONTROL_PLANE_API_KEY MCP_SERVER_URL HA_ACCESS_TOKEN; do
  if ! jq -e --arg k "$k" '.[$k] | type == "string" and length > 0' "$OPTIONS" >/dev/null; then
    echo "Konfiguration fehlt: $k" >&2; exit 1
  fi
done
export CONTROL_PLANE_TUNNEL_ID="$(jq -r .CONTROL_PLANE_TUNNEL_ID "$OPTIONS")"
export CONTROL_PLANE_API_KEY="$(jq -r .CONTROL_PLANE_API_KEY "$OPTIONS")"
export HA_MCP_SERVER_URL="$(jq -r .MCP_SERVER_URL "$OPTIONS")"
export HA_ACCESS_TOKEN="$(jq -r .HA_ACCESS_TOKEN "$OPTIONS")"
case "$HA_MCP_SERVER_URL" in
  http://homeassistant.local:8123/api/mcp|http://homeassistant:8123/api/mcp) ;;
  *) echo "Nur interne bekannte Home-Assistant-MCP-Adressen zugelassen" >&2; exit 1 ;;
esac
export HA_CONFIG_ROOT=/homeassistant_config
export TZ=Europe/Berlin
export PYTHONDONTWRITEBYTECODE=1
export APPROVAL_MODE=unified
export MCP_WRITE_ENABLED="$(jq -r '.MCP_WRITE_ENABLED // false' "$OPTIONS")"
case "$MCP_WRITE_ENABLED" in true|false) ;; *) echo "MCP_WRITE_ENABLED ungueltig" >&2; exit 1 ;; esac
# Existing per-operation security gates all require the central opt-in, then
# their own exact action-bound, SHA256-bound approval in APPROVED_ACTION.
export WRITE_ENABLED="$MCP_WRITE_ENABLED"
export DASHBOARD_WRITE_ENABLED="$MCP_WRITE_ENABLED"
export DASHBOARD_RESTORE_ENABLED="$MCP_WRITE_ENABLED"
export BACKUP_RETENTION_DELETE_ENABLED="$MCP_WRITE_ENABLED"
export GW_RETENTION_STAGE4_MODE="$(jq -r ".BACKUP_RETENTION_MODE // \"off\"" "$OPTIONS")"
case "$BACKUP_RETENTION_DELETE_ENABLED" in true|false) ;; *) echo "Backup-Retention-Schalter ungueltig" >&2; exit 1 ;; esac
case "$GW_RETENTION_STAGE4_MODE" in off|preview) ;; *) echo "Backup-Retention-Löschung nicht freigegeben" >&2; exit 1 ;; esac
unset MCP_SERVER_URL MCP_EXTRA_HEADERS MCP_DISCOVERY_EXTRA_HEADERS HA_AUTH_HEADER
[ -d /homeassistant_config/packages ] || { echo 'packages-Ordner nicht gefunden' >&2; exit 1; }
echo "Ein-Tunnel-MCP-Gateway startet: HA-Proxy plus YAML-Guard; MCP_WRITE_ENABLED=$MCP_WRITE_ENABLED."
exec /usr/bin/tunnel-client run --mcp.command='python3 -u /app/gateway.py'
