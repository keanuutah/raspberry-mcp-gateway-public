"""Read-only 10-backup retention preview for the HAOS YAML backup directory.

No write primitives, no file bytes returned. No lock file and no deletion.
Decisions are provisional and must not be used as permission to delete: HAOS
production deletion remains strictly disabled. Only a committed and validated
backup may authorize a separately reviewed future deletion flow.
"""
from __future__ import annotations
import os
import re
import stat
from pathlib import Path

from backup_retention_stage3 import BACKUP, MAX_BACKUP_BYTES

PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,100}\.yaml\Z")


def preview(folder: str | Path, package_name: str, *, keep: int = 10) -> dict:
    if not isinstance(package_name, str) or not PACKAGE_NAME.fullmatch(package_name):
        raise ValueError("Ungültiger Package-Name")
    if type(keep) is not int or keep != 10:
        raise ValueError("Nur exakt zehn Backups je Package")
    folder = Path(folder)
    # Protect every component; e.g. a symlink in a parent must not escape.
    p = folder.absolute()
    chain = [p, *p.parents]
    if any(part.is_symlink() for part in chain):
        raise PermissionError("Symlink im Backup-Verzeichnispfad")
    fd = os.open(str(p), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names, unsafe = [], []
        prefix = package_name[:-5]
        with os.scandir(fd) as it:
            for entry in it:
                match = BACKUP.fullmatch(entry.name)
                if match is None or match.group(1) != prefix:
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not (0 <= st.st_size <= MAX_BACKUP_BYTES):
                        unsafe.append(entry.name)
                    else:
                        names.append(entry.name)
                except OSError:
                    unsafe.append(entry.name)
        names.sort(reverse=True)
        unsafe.sort()
        # Never propose deletions if unsafe entries exist. Names are only
        # advisory; no file inode is pinned by this preview.
        return {
            "package_name": package_name,
            "keep_per_package": 10,
            "total_eligible": len(names),
            "total_unsafe": len(unsafe),
            "retained": names[:10],
            "would_delete": names[10:] if not unsafe else [],
            "unsafe_entries": unsafe,
            "preview_only": True,
            "deletion_enabled": False,
            "safe_to_execute": False,
            "note": "Unverbindliche Vorschau ohne Schreib-/Löschberechtigung; neue Backup-SHA256 und Commit-Erfolg müssen gesondert geprüft werden.",
        }
    finally:
        os.close(fd)
