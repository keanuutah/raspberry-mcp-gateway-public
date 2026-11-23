"""Read-only metadata + SHA256 verification for guarded dashboard snapshots.

Proposal for GW-13-R. Never exposes JSON contents, creates paths or writes.
"""
import hashlib
import os
import re
import stat

from dashboard_writes import validate_id

# OfflineSnapshotStore names: <id>_<UTC YYYYMMDDTHHMMSSffffffZ>_<sha256[:12]>.json
SNAP_NAME = re.compile(r'^([a-z0-9][a-z0-9_-]{0,99})_(\d{8}T\d{12}Z)_([0-9a-f]{12})\.json$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
MAX_SNAPSHOT_BYTES = 384 * 1024
MAX_ENTRIES = 100


def _open_snapshots_dir():
    """Open only the existing /data/dashboard_guard/snapshots chain, no symlinks."""
    fd = os.open('/data', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        child = os.open('dashboard_guard', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        snapfd = os.open('snapshots', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=child)
    finally:
        os.close(child)
    return snapfd


def _safe_names(dirfd, dashboard_id):
    results=[]
    # No path joins or file opens for directory listing: filename only.
    for name in os.listdir(dirfd):
        match = SNAP_NAME.fullmatch(name)
        if not match or match.group(1) != dashboard_id:
            continue
        info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            continue
        if not 1 <= info.st_size <= MAX_SNAPSHOT_BYTES:
            continue
        results.append((name, match.group(2), info.st_size))
    return sorted(results, reverse=True)


def dashboard_list_snapshots(dashboard_id: str, limit: int = 50) -> dict:
    """List only filenames, sizes and times. Never reads JSON file contents."""
    validate_id(dashboard_id)
    if type(limit) is not int or not (1 <= limit <= MAX_ENTRIES):
        raise ValueError('limit muss zwischen 1 und 100 liegen')
    fd = _open_snapshots_dir()
    try:
        names = _safe_names(fd, dashboard_id)
        return {'dashboard_id': dashboard_id,
                'snapshots': [{'name': name, 'created_utc': timestamp, 'size_bytes': size}
                              for name, timestamp, size in names[:limit]],
                'count': len(names[:limit]), 'truncated': len(names) > limit,
                'read_only': True, 'contents_disclosed': False}
    finally:
        os.close(fd)


def dashboard_verify_snapshot(dashboard_id: str, name: str,
                              expected_sha256: str | None = None) -> dict:
    """SHA256 the existing bounded regular file without returning its contents."""
    validate_id(dashboard_id)
    if not isinstance(name, str):
        raise ValueError('Ungültiger Snapshot-Name')
    match = SNAP_NAME.fullmatch(name)
    if not match or match.group(1) != dashboard_id:
        raise ValueError('Snapshot-Name gehört nicht zur Dashboard-ID')
    if expected_sha256 is not None and (not isinstance(expected_sha256, str) or
                                        not SHA256.fullmatch(expected_sha256)):
        raise ValueError('Ungültiger erwarteter SHA256')
    dirfd = _open_snapshots_dir()
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_SNAPSHOT_BYTES:
                raise ValueError('Snapshot ist keine zulässige reguläre Datei')
            digest = hashlib.sha256()
            amount = 0
            while chunk := os.read(fd, min(65536, MAX_SNAPSHOT_BYTES + 1 - amount)):
                amount += len(chunk)
                if amount > MAX_SNAPSHOT_BYTES:
                    raise ValueError('Snapshot zu groß')
                digest.update(chunk)
            after = os.fstat(fd)
            if (amount != before.st_size or amount != after.st_size or
                    (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)):
                raise IOError('Snapshot während der Prüfung verändert')
            got = digest.hexdigest()
            return {'dashboard_id': dashboard_id, 'name': name,
                    'exists': True, 'size_bytes': amount, 'sha256': got,
                    'matches_filename_prefix': got.startswith(match.group(3)),
                    'matches_expected': None if expected_sha256 is None else got == expected_sha256,
                    'read_only': True, 'contents_disclosed': False}
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)
