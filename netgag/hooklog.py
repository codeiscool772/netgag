"""Reads %TEMP%\\netgag_hook_debug.log - the activity/patch log hookdll.c
writes. Not a stable format, just enough structure to power the "did the
hook actually attach" verification and the Activity Log view in the UI.
"""

import os
import re

_PATCH_RE = re.compile(r"^\[pid (\d+)\] patched ([\w.]+)!(\w+)$")
_ATTACH_RE = re.compile(r"^\[pid (\d+)\] hooknet64\.dll DllMain DLL_PROCESS_ATTACH$")
_COUNTS_RE = re.compile(r"^\[pid (\d+)\] blocked-call counts: (.+)$")

MAX_READ_BYTES = 2_000_000   # tail this many bytes for a bounded, fast read


def log_path():
    return os.path.join(os.environ.get("TEMP", ""), "netgag_hook_debug.log")


def read_lines():
    """Last MAX_READ_BYTES of the log, as lines (empty list if it doesn't exist)."""
    path = log_path()
    try:
        size = os.path.getsize(path)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            if size > MAX_READ_BYTES:
                fh.seek(size - MAX_READ_BYTES)
                fh.readline()  # discard the partial first line from seeking mid-line
            return fh.readlines()
    except OSError:
        return []


def attached_pids(lines=None):
    """PIDs that have ever logged a DllMain attach event (within the tail read)."""
    lines = lines if lines is not None else read_lines()
    return {int(m.group(1)) for line in lines if (m := _ATTACH_RE.match(line.strip()))}


def patched_functions_for_pid(pid, lines=None):
    """Set of 'dll!function' strings successfully patched in *pid*."""
    lines = lines if lines is not None else read_lines()
    found = set()
    for line in lines:
        m = _PATCH_RE.match(line.strip())
        if m and int(m.group(1)) == pid:
            found.add(f"{m.group(2)}!{m.group(3)}")
    return found


def activity_counts_for_pid(pid, lines=None):
    """Most recent 'blocked-call counts' summary for *pid*, as {func: count}."""
    lines = lines if lines is not None else read_lines()
    latest = None
    for line in lines:
        m = _COUNTS_RE.match(line.strip())
        if m and int(m.group(1)) == pid:
            latest = m.group(2)
    if not latest:
        return {}
    out = {}
    for part in latest.split():
        if "=" in part:
            key, value = part.split("=", 1)
            try:
                out[key] = int(value)
            except ValueError:
                pass
    return out
