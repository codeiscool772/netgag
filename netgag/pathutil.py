"""Pure path/naming helpers (no Windows APIs, so they are unit-testable anywhere)."""

import hashlib
import ntpath
import os
import re

RULE_PREFIX = "NetGag_"
GROUP_NAME = "NetGag"

# Core Windows components that must never be blocked or force-killed.
PROTECTED_NAMES = frozenset({
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "smss.exe", "dwm.exe", "explorer.exe", "sihost.exe",
    "fontdrvhost.exe", "lsm.exe",
})


def norm_path(path):
    """Canonical display form of a path (Windows semantics on every platform)."""
    return ntpath.normpath(path)


def norm_key(path):
    """Case-insensitive identity key for a path."""
    return ntpath.normcase(ntpath.normpath(path))


def safe_stem(path, limit=16):
    """File stem reduced to characters that are safe in firewall rule names."""
    stem, _ = ntpath.splitext(ntpath.basename(path))
    return re.sub(r"[^A-Za-z0-9_-]", "_", stem)[:limit] or "app"


def rule_name(path, direction):
    """Deterministic, collision-resistant firewall rule name."""
    digest = hashlib.sha256(norm_key(path).encode("utf-8")).hexdigest()[:10]
    return f"{RULE_PREFIX}{direction}_{safe_stem(path)}_{digest}"


def is_protected(path, windir=None):
    """True for critical Windows executables that live inside the Windows folder."""
    windir = windir or os.environ.get("SystemRoot", r"C:\Windows")
    if ntpath.basename(path).lower() not in PROTECTED_NAMES:
        return False
    parent = norm_key(ntpath.dirname(path))
    root = norm_key(windir)
    return parent == root or parent.startswith(root + "\\")


def format_size(num_bytes):
    if num_bytes is None:
        return "N/A"
    if num_bytes >= 1024 ** 3:
        return f"{num_bytes / 1024 ** 3:.2f} GB"
    if num_bytes >= 1024 ** 2:
        return f"{num_bytes / 1024 ** 2:.2f} MB"
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes} B"


PRUNE_DIRS = frozenset({
    "node_modules", ".git", ".hg", ".svn", "__pycache__", "site-packages", ".idea", ".vs",
    ".tox", ".mypy_cache", "$recycle.bin", "system volume information",
})


def _prune(root, dirs):
    """Drop directories that would flood the list (dependencies, VCS data, virtualenvs)."""
    dirs[:] = [
        d for d in dirs
        if d.lower() not in PRUNE_DIRS and not os.path.isfile(os.path.join(root, d, "pyvenv.cfg"))
    ]


def find_files(folder, recursive=True, exts=(".exe",)):
    """Return every file with one of *exts* below *folder* (unreadable dirs are skipped)."""
    exts = tuple(e.lower() for e in exts)
    found = []
    folder = norm_path(folder)
    if recursive:
        for root, dirs, files in os.walk(folder, onerror=lambda _e: None):
            _prune(root, dirs)
            for name in files:
                if name.lower().endswith(exts):
                    found.append(norm_path(os.path.join(root, name)))
    else:
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.name.lower().endswith(exts) and entry.is_file():
                        found.append(norm_path(entry.path))
        except OSError:
            pass
    return found


def find_executables(folder, recursive=True):
    return find_files(folder, recursive, (".exe",))
