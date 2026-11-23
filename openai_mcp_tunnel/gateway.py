"""Unified local stdio MCP gateway. No HTTP port, filesystem is AppArmor-restricted.

The HA upstream token stays server-side and is never accepted from incoming tool arguments.
"""
import os
from fastmcp import FastMCP
from fastmcp.server import create_proxy
from fastmcp.server.providers.proxy import ProxyClient
from fastmcp.client.transports import StreamableHttpTransport
from filesystem import list_packages, read_yaml, plan_write, commit_write, verify_backup, list_backups, read_backup
from dashboards import dashboard_list as _dashboard_list, dashboard_read as _dashboard_read
from dashboard_commit import dashboard_plan_write as _dashboard_plan_write, dashboard_commit_write as _dashboard_commit_write
from backup_retention_preview import preview as _retention_preview
from backup_retention_production import plan as _retention_plan, commit as _retention_commit, plan_recovery as _retention_plan_recovery, commit_recovery as _retention_commit_recovery
from filesystem import ROOT, BACKUP_DIR
from apparmor_diagnose import diagnose as _diagnose_apparmor
from dashboard_snapshot_metadata import dashboard_list_snapshots as _dashboard_list_snapshots, dashboard_verify_snapshot as _dashboard_verify_snapshot
from dashboard_restore import dashboard_plan_restore as _dashboard_plan_restore, dashboard_commit_restore as _dashboard_commit_restore

mcp = FastMCP('Raspberry Home Assistant Gateway')
# Writing remains disabled unless MCP_WRITE_ENABLED=true in the Home Assistant app settings.
@mcp.tool
def yaml_diagnose_apparmor() -> dict:
    """Read-only diagnostic: kernel process AppArmor mode and scoped policy checks.

    Does not write, alter settings or probe forbidden paths. Enforce is only
    confirmed from the actual MCP process label in /proc/self/attr/current.
    """
    return _diagnose_apparmor()

@mcp.tool
def yaml_list_packages() -> list[str]:
    """List readable YAML files inside /config/packages only."""
    return list_packages()

@mcp.tool
def yaml_read_yaml(name: str, area: str = 'packages') -> dict:
    """Read package YAML; area='main' only for three approved root YAML files."""
    return read_yaml(name, area)

@mcp.tool
def yaml_verify_backup(name: str, expected_sha256: str | None = None) -> dict:
    """Read-only check of a gateway-created *.yaml.bak file.

    Accepts only a simple backup filename under /config/yaml_backups/.
    Returns existence, size, SHA256 and optional comparison; never contents.
    Does not need WRITE_ENABLED or APPROVED_CHANGE.
    """
    return verify_backup(name, expected_sha256)


@mcp.tool
def yaml_list_backups(limit: int = 50) -> dict:
    """List metadata for gateway-created YAML backups only; no file contents.

    Directory: /config/yaml_backups/. Max 100 entries per request, read-only.
    """
    return list_backups(limit)


@mcp.tool
def yaml_retention_preview(package_name: str) -> dict:
    """Read-only 10-backup retention preview for ONE existing package YAML.

    No backup contents, no deletion, no approval or WRITE_ENABLED needed.
    Unsafe matching files block all deletion proposals. Production deletion
    remains disabled regardless of this preview.
    """
    return _retention_preview(ROOT / BACKUP_DIR, package_name)


@mcp.tool
def yaml_retention_plan_delete(package_name: str, newest_backup_name: str,
                               newest_backup_sha256: str) -> dict:
    """GW-14: read-only, SHA256-bound deletion plan for exactly one package.

    No files deleted; no backup contents disclosed. The plan is invalidated by
    any changed eligible backup or pending quarantine.
    """
    return _retention_plan(ROOT / BACKUP_DIR, package_name, newest_backup_name, newest_backup_sha256)


@mcp.tool
def yaml_retention_commit_delete(package_name: str, newest_backup_name: str,
                                 newest_backup_sha256: str, plan_sha256: str,
                                 approval: str) -> dict:
    """GW-14 destructive operation: requires separately enabled HA App setting,
    matching SHA256-bound APPROVED_ACTION and explicit user consent.

    Never invoked from yaml_commit_write. Protects ten newest per package,
    preserves crash journal and quarantines. No automatic retries.
    """
    return _retention_commit(ROOT / BACKUP_DIR, package_name,
        newest_backup_name, newest_backup_sha256, plan_sha256, approval,
        enabled=os.environ.get('BACKUP_RETENTION_DELETE_ENABLED','false')=='true')


@mcp.tool
def yaml_retention_plan_recovery() -> dict:
    """Read-only plan to restore interrupted quarantines; never delete backups."""
    return _retention_plan_recovery(ROOT / BACKUP_DIR)


@mcp.tool
def yaml_retention_commit_recovery(expected_plan_sha256: str, approval: str) -> dict:
    """Recover quarantined backups under separate explicit approval; never resume deletion."""
    return _retention_commit_recovery(ROOT / BACKUP_DIR, expected_plan_sha256, approval,
        enabled=os.environ.get('BACKUP_RETENTION_DELETE_ENABLED','false')=='true')


@mcp.tool
def yaml_read_backup(name: str, expected_sha256: str | None = None) -> dict:
    """Read ONE specific gateway-created YAML backup as UTF-8 text.

    Only /config/yaml_backups/<gateway-backup-filename>; max 1 MiB,
    symlinks rejected, optional expected SHA256 checked before disclosure.
    Contents may include secrets: call ONLY after explicit user request.
    No WRITE_ENABLED/APPROVED_CHANGE needed; this NEVER modifies files.
    """
    return read_backup(name, expected_sha256)


@mcp.tool
async def dashboard_list() -> dict:
    """List Home Assistant Lovelace dashboard metadata (read-only).

    Uses the server-side HA token; does not expose credentials or edit dashboards.
    """
    return await _dashboard_list()


@mcp.tool
async def dashboard_read(dashboard_id: str) -> dict:
    """Read one listed dashboard configuration with sensitive keys redacted.

    Use dashboard_id='default' for built-in Overview; other IDs must exist in
    dashboard_list. Storage and YAML modes are both READ-ONLY here.
    """
    return await _dashboard_read(dashboard_id)


@mcp.tool
def dashboard_list_snapshots(dashboard_id: str, limit: int = 50) -> dict:
    """List only metadata for existing private dashboard snapshots (read-only).

    Only /data/dashboard_guard/snapshots, never JSON contents. The requested
    dashboard_id is bound to snapshot filenames. No approval setting required.
    """
    return _dashboard_list_snapshots(dashboard_id, limit)


@mcp.tool
def dashboard_verify_snapshot(dashboard_id: str, name: str,
                              expected_sha256: str | None = None) -> dict:
    """Verify SHA256 for ONE private dashboard snapshot; never return contents.

    Reject symlinks, paths, other dashboards and oversized files (read-only).
    """
    return _dashboard_verify_snapshot(dashboard_id, name, expected_sha256)


@mcp.tool
async def dashboard_plan_restore(dashboard_id: str, snapshot_name: str, snapshot_sha256: str) -> dict:
    """Read-only restore preview of a verified snapshot; no JSON contents exposed."""
    return await _dashboard_plan_restore(dashboard_id, snapshot_name, snapshot_sha256)


@mcp.tool
async def dashboard_commit_restore(dashboard_id: str, snapshot_name: str,
                                   snapshot_sha256: str, expected_sha256: str,
                                   approval: str) -> dict:
    """DISABLED BY DEFAULT. Restore one snapshot only after separate HA option AND explicit per-call consent.

    Requires MCP_WRITE_ENABLED, APPROVED_ACTION and a prior
    matching dashboard_plan_restore. Not intended for simultaneous HA UI edits.
    """
    return await _dashboard_commit_restore(dashboard_id, snapshot_name, snapshot_sha256,
        expected_sha256, approval, explicit_consent=True)


@mcp.tool
async def dashboard_plan_write(dashboard_id: str, proposed_json: str) -> dict:
    """Read raw Storage dashboard, calculate SHA256 preview for a JSON proposal; NO write.

    Requires the user to inspect the proposed full configuration; do not log secrets.
    """
    return await _dashboard_plan_write(dashboard_id, proposed_json)


@mcp.tool
async def dashboard_commit_write(dashboard_id: str, proposed_json: str,
                                 expected_sha256: str, proposed_sha256: str,
                                 approval: str) -> dict:
    """DISABLED BY DEFAULT. Save one Storage dashboard after TWO separate permissions.

    Call only after a matching dashboard_plan_write and an explicit user approval.
    Requires MCP_WRITE_ENABLED and an action-scoped APPROVED_ACTION.
    This command has no atomic HA-side compare-and-swap; do not activate on
    production without addressing external concurrent HA dashboard writes.
    """
    return await _dashboard_commit_write(dashboard_id, proposed_json,
        expected_sha256, proposed_sha256, approval, explicit_consent=True)


@mcp.tool
def yaml_plan_write(name: str, content: str) -> dict:
    """Validate proposed package YAML and return diff; does NOT write files."""
    return plan_write(name, content)

@mcp.tool
def yaml_commit_write(name: str, content: str, expected_sha256: str | None,
                      proposed_sha256: str, approval: str) -> dict:
    """After an explicit user approval, write one packages YAML file, with pre-write backup.

    Only use after yaml_plan_write for exactly the same name/content and hashes.
    Ask user for permission before EVERY invocation; never infer approval.
    The user must set APPROVED_ACTION (YAML| prefix) in the Home Assistant app settings
    for this one file/version and restart the app. After successful commit it
    is cleared automatically via Supervisor API. One-time approvals cannot be reused.
    approval must equal 'FREIGABE <name> <proposed_sha256>'.
    """
    return commit_write(name, content, expected_sha256, proposed_sha256, approval)


upstream_url = os.environ['HA_MCP_SERVER_URL']
ha_token = os.environ['HA_ACCESS_TOKEN']
transport = StreamableHttpTransport(
    upstream_url, headers={'Authorization': 'Bearer ' + ha_token}
)
backend = ProxyClient(transport, forward_incoming_headers=False)
ha_proxy = create_proxy(backend)
ha_proxy.enable(
    names={'llm__GetDateTime', 'config__search_integrations', 'homeassistant__search_actions'},
    components={'tool'},
    only=True,
)
mcp.mount(ha_proxy, namespace='ha')

if __name__ == '__main__':
    mcp.run(transport='stdio')
