"""Injects netgag/native/hooknet64.dll into a process so it BELIEVES it has no
network (via IAT-hooked connect/getaddrinfo/InternetGetConnectedState/adapter
enumeration - see native/hookdll.c), instead of merely having its connections
refused by the firewall.

64-bit targets only. The classic CreateRemoteThread + LoadLibraryW technique.
"""

import ctypes
import logging
import os
import sys
from ctypes import wintypes

log = logging.getLogger(__name__)

PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                    wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                        wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeThread.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsWow64Process.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
               ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPVOID, wintypes.LPVOID, wintypes.BOOL,
    wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION)]
kernel32.CreateProcessW.restype = wintypes.BOOL


class HookError(RuntimeError):
    """The hook DLL could not be built into / injected into a process."""


def dll_path():
    """Locate hooknet64.dll: next to this file in dev, or under _MEIPASS/netgag
    when frozen (see the ('netgag\\hooknet64.dll', 'netgag') binaries entry in
    Netgag.spec - __file__ isn't a real path once packed into the PYZ archive)."""
    candidates = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooknet64.dll")]
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        candidates.append(os.path.join(meipass, "netgag", "hooknet64.dll"))
        candidates.append(os.path.join(meipass, "hooknet64.dll"))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return ""


def is_64bit_process(pid):
    """False for a 32-bit process on 64-bit Windows (the hook DLL is 64-bit only)."""
    handle = kernel32.OpenProcess(0x0400, False, pid)   # PROCESS_QUERY_INFORMATION
    if not handle:
        return None
    try:
        wow64 = wintypes.BOOL()
        if not kernel32.IsWow64Process(handle, ctypes.byref(wow64)):
            return None
        return not wow64.value
    finally:
        kernel32.CloseHandle(handle)


def inject(pid, dll=None):
    """Load the hook DLL into an already-running 64-bit process."""
    dll = dll or dll_path()
    if not dll:
        raise HookError("hooknet64.dll was not found (build it with native\\build.ps1).")
    if is_64bit_process(pid) is False:
        raise HookError("That process is 32-bit; the network hook only supports 64-bit processes.")

    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        raise HookError(f"Could not open process {pid} (error {ctypes.get_last_error()}).")
    try:
        path_bytes = (dll + "\0").encode("utf-16-le")
        size = len(path_bytes)
        remote_mem = kernel32.VirtualAllocEx(handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            raise HookError(f"VirtualAllocEx failed (error {ctypes.get_last_error()}).")
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(handle, remote_mem, path_bytes, size, ctypes.byref(written)):
            raise HookError(f"WriteProcessMemory failed (error {ctypes.get_last_error()}).")

        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        load_library = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
        if not load_library:
            raise HookError("Could not resolve LoadLibraryW.")

        thread = kernel32.CreateRemoteThread(handle, None, 0, load_library, remote_mem, 0, None)
        if not thread:
            raise HookError(f"CreateRemoteThread failed (error {ctypes.get_last_error()}).")
        try:
            kernel32.WaitForSingleObject(thread, 10000)
            exit_code = wintypes.DWORD(0)
            kernel32.GetExitCodeThread(thread, ctypes.byref(exit_code))
            if exit_code.value == 0:
                raise HookError("The target did not load the hook module (LoadLibraryW returned NULL).")
        finally:
            kernel32.CloseHandle(thread)
            kernel32.VirtualFreeEx(handle, remote_mem, 0, MEM_RELEASE)
    finally:
        kernel32.CloseHandle(handle)


def create_suspended_and_inject(command_line, cwd=None, dll=None, extra_env=None):
    """Start *command_line* suspended, inject before it can run any of its own
    code, then resume. Returns (pid, hProcess) - caller must CloseHandle.

    *extra_env*, if given, is merged into a copy of the current environment
    for the child (e.g. PYTHONPATH for a script's interpreter) without
    touching this process's own os.environ.
    """
    dll = dll or dll_path()
    if not dll:
        raise HookError("hooknet64.dll was not found (build it with native\\build.ps1).")

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    cmd_buf = ctypes.create_unicode_buffer(command_line)

    env_buf = None
    flags = CREATE_SUSPENDED
    lp_environment = None
    if extra_env:
        merged = dict(os.environ)
        merged.update(extra_env)
        block = "\0".join(f"{k}={v}" for k, v in merged.items()) + "\0\0"
        env_buf = ctypes.create_unicode_buffer(block)
        lp_environment = ctypes.cast(env_buf, wintypes.LPVOID)
        flags |= CREATE_UNICODE_ENVIRONMENT

    ok = kernel32.CreateProcessW(None, cmd_buf, None, None, False, flags,
                                 lp_environment, cwd, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise HookError(f"Could not start the process (error {ctypes.get_last_error()}).")
    try:
        inject(pi.dwProcessId, dll)
    except HookError:
        kernel32.TerminateProcess(pi.hProcess, 1)
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
        raise
    kernel32.ResumeThread(pi.hThread)
    kernel32.CloseHandle(pi.hThread)
    return pi.dwProcessId, pi.hProcess
