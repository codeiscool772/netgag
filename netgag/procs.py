"""Process enumeration / termination via the Win32 API (no PowerShell spawns)."""

import ctypes
import json
import logging
import os
import sys
from ctypes import wintypes

from . import firewall, pathutil

log = logging.getLogger(__name__)

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


_kernel32 = None
_INVALID_HANDLE = ctypes.c_void_p(-1).value


def _k32():
    """Lazily bind kernel32 so this module can be imported on any platform."""
    global _kernel32
    if _kernel32 is None:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        k.Process32FirstW.restype = wintypes.BOOL
        k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        k.Process32NextW.restype = wintypes.BOOL
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k.TerminateProcess.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        _kernel32 = k
    return _kernel32


def _image_path(k, pid):
    """Full executable path of *pid*, or None if it cannot be queried."""
    handle = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        k.CloseHandle(handle)


def iter_processes():
    """Yield (pid, image_path_or_None) for every running process."""
    if sys.platform != "win32":
        return
    k = _k32()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == _INVALID_HANDLE:
        log.warning("CreateToolhelp32Snapshot failed")
        return
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            yield entry.th32ProcessID, _image_path(k, entry.th32ProcessID)
            ok = k.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k.CloseHandle(snap)


def running_keys():
    """Set of norm_key() values for every process whose path can be read."""
    return {pathutil.norm_key(path) for _pid, path in iter_processes() if path}


def find_pids_by_path(path):
    """PIDs of every currently-running process at exactly *path* (excluding
    protected system processes and NetGag's own process)."""
    if pathutil.is_protected(path) or is_self(path):
        return []
    target = pathutil.norm_key(path)
    return [pid for pid, image in iter_processes() if image and pathutil.norm_key(image) == target]


def is_self(path):
    """True if *path* is this very program (never terminate ourselves)."""
    me = pathutil.norm_key(sys.executable)
    if pathutil.norm_key(path) == me:
        return True
    return pathutil.norm_key(path) == pathutil.norm_key(os.path.abspath(sys.argv[0]))


def terminate_pid(pid):
    """Force-terminate one process. Returns 1 on success, 0 otherwise."""
    if pid == os.getpid():
        return 0
    k = _k32()
    handle = k.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not handle:
        log.warning("Could not open pid %s for termination (error %s)", pid, ctypes.get_last_error())
        return 0
    try:
        return 1 if k.TerminateProcess(handle, 1) else 0
    finally:
        k.CloseHandle(handle)


def terminate_by_path(path):
    """Force-terminate every process running exactly *path*. Returns how many died."""
    if pathutil.is_protected(path) or is_self(path):
        log.warning("Refusing to terminate protected/own process: %s", path)
        return 0
    target = pathutil.norm_key(path)
    killed = 0
    for pid, image in iter_processes():
        if image and pathutil.norm_key(image) == target:
            killed += terminate_pid(pid)
    return killed


_FIND_SCRIPT = r"""
$p = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
$needle = [string]$p.path
$out = @(Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and $_.CommandLine.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
} | ForEach-Object { [pscustomobject]@{ pid = [int]$_.ProcessId; exe = [string]$_.ExecutablePath } })
ConvertTo-Json -InputObject $out -Compress
"""


def find_script_instances(script_path, interpreter, runner=""):
    """PIDs of interpreter processes currently running *script_path*.

    Scripts run inside a shared interpreter, so they can only be recognised by
    their command line.  Editors that merely have the file open are ignored
    because only processes of the script's own interpreter count, and instances
    that already run from the blocked runner copy are left alone.
    """
    out = firewall.run_powershell(_FIND_SCRIPT, {"path": script_path})
    rows = json.loads(out) if out else []
    if isinstance(rows, dict):
        rows = [rows]
    interp_name = os.path.basename(interpreter).lower()
    runner_key = pathutil.norm_key(runner) if runner else None
    pids = []
    for row in rows:
        exe = row.get("exe") or ""
        if not exe or os.path.basename(exe).lower() != interp_name:
            continue
        if runner_key and pathutil.norm_key(exe) == runner_key:
            continue
        if row.get("pid") and row["pid"] != os.getpid():
            pids.append(int(row["pid"]))
    return pids
