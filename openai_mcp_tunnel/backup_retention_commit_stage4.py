"""STAGE 4 / LOCAL ONLY: post-commit adapter for ten-backup retention.

Do not deploy this stage to HAOS. Only the working copy under temporary test
roots may delete backups. The existing Stage3 engine refuses HAOS config paths.
The original YAML commit's outcome is independent of retention housekeeping.
"""
from __future__ import annotations
import logging
import re
from pathlib import Path
from backup_retention_stage5 import retention_after_verified_backup
from backup_retention_preview import preview as preview_retention

LOG = logging.getLogger(__name__)
BACKUP_NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,100}_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}_[0-9]{6}\.yaml\.bak$')


def after_successful_commit(result: dict, *, package_name: str,
                            original_sha256: str | None,
                            backup_dir: str | Path, mode: str = 'off') -> dict:
    """Invoke *only* after successful YAML atomic commit, never for failures.

    Uses original SHA256 from authenticated pre-commit preview to validate the
    newly created pre-commit backup. New-file creation manifests (.created.json)
    are not subject to retention. Deletion is not allowed on production paths.
    """
    if mode not in ('off', 'preview', 'local_delete'):
        return {'status': 'disabled', 'reason': 'invalid_mode'}
    if mode == 'off':
        return {'status': 'disabled'}
    if not isinstance(result, dict) or 'written' not in result:
        return {'status': 'skipped', 'reason': 'not_a_successful_commit'}
    if result.get('written') != f'packages/{package_name}':
        return {'status': 'skipped', 'reason': 'package_mismatch'}
    backup = result.get('backup')
    if not isinstance(backup, str) or not backup.startswith('yaml_backups/'):
        return {'status': 'skipped', 'reason': 'no_recognized_backup'}
    name = backup[len('yaml_backups/'):]
    if name.endswith('.created.json'):
        return {'status': 'skipped', 'reason': 'new_file_no_prior_version'}
    if not BACKUP_NAME.fullmatch(name) or not name.startswith(package_name[:-5]+'_'):
        return {'status': 'skipped', 'reason': 'unrecognized_backup_name'}
    if not isinstance(original_sha256, str) or not re.fullmatch('[0-9a-f]{64}', original_sha256):
        return {'status': 'skipped', 'reason': 'no_verified_original_hash'}
    try:
        if mode == 'preview':
            from backup_retention_stage3 import _hash_regular_at, _dirfd
            dir_fd = _dirfd(Path(backup_dir))
            try:
                actual_sha, _ = _hash_regular_at(dir_fd, name)
            finally:
                import os
                os.close(dir_fd)
            if actual_sha != original_sha256:
                return {'status': 'failed', 'reason': 'backup_hash_mismatch'}
            info = preview_retention(backup_dir, package_name)
            if name not in info['retained'] or info['total_unsafe']:
                return {'status': 'skipped', 'reason': 'unsafe_or_new_backup_not_retained'}
            return {'status': 'preview', 'would_delete': info['would_delete'],
                    'deleted': [], 'keep_per_package': 10,
                    'preview_only': True, 'deletion_enabled': False}
        result = retention_after_verified_backup(
            backup_dir,
            package=package_name[:-5], new_backup_name=name,
            expected_sha256=original_sha256, keep=10,
            enabled=(mode == 'local_delete'),
        )
        return {'status': 'local_deleted' if mode == 'local_delete' else 'preview',
                'would_delete': result['would_delete'],
                'deleted': result['deleted'], 'keep_per_package': 10}
    except Exception as exc:
        # No file content, token, or SHA256 dumped in logs.
        LOG.warning('Backup-Bereinigung nach Commit ausgefallen (%s)', type(exc).__name__)
        return {'status': 'failed', 'reason': type(exc).__name__}
