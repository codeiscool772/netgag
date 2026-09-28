"""Proves hooknet64.dll actually intercepts network calls in a real process -
does not just trust the DLL/injector blindly.

Compares native/nettest.exe run unhooked (real network) vs run suspended and
injected via netgag.nethook (should report "no network" for every check).

Run from the project root: python -m tests.smoke_nethook
"""

import ctypes
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netgag import nethook

NETTEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "native", "nettest.exe")
NETTEST = os.path.abspath(NETTEST)

WSAENETUNREACH = 10051
WSAHOST_NOT_FOUND = 11001


def run_baseline():
    """Unhooked: should show a real, working (or at least normal) network."""
    proc = subprocess.Popen([NETTEST], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    proc.stdin.write("\n")
    proc.stdin.flush()
    lines = [proc.stdout.readline().strip() for _ in range(3)]
    proc.stdin.write("\n")
    proc.stdin.flush()
    proc.wait(timeout=5)
    return _parse(lines)


def _parse(lines):
    out = {}
    for line in lines:
        for part in line.split():
            if "=" in part:
                k, v = part.split("=", 1)
                out[k] = v
    return out


def run_hooked():
    """Suspended + injected: every check should report 'no network'."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    r_read, w_write = os.pipe()
    r_out, w_out = os.pipe()

    # We need real Windows HANDLEs wired as the child's stdio, not Python fds,
    # so build STARTUPINFOW with inherited handles ourselves via msvcrt.
    import msvcrt
    h_stdin_r = msvcrt.get_osfhandle(r_read)
    h_stdout_w = msvcrt.get_osfhandle(w_out)

    kernel32.SetHandleInformation(h_stdin_r, 1, 1)   # HANDLE_FLAG_INHERIT
    kernel32.SetHandleInformation(h_stdout_w, 1, 1)

    si = nethook.STARTUPINFOW()
    si.cb = ctypes.sizeof(nethook.STARTUPINFOW)
    si.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
    si.hStdInput = h_stdin_r
    si.hStdOutput = h_stdout_w
    si.hStdError = h_stdout_w
    pi = nethook.PROCESS_INFORMATION()
    cmd_buf = ctypes.create_unicode_buffer(f'"{NETTEST}"')

    ok = kernel32.CreateProcessW(None, cmd_buf, None, None, True,
                                 nethook.CREATE_SUSPENDED, None, None,
                                 ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise RuntimeError(f"CreateProcessW failed: {ctypes.get_last_error()}")

    os.close(r_read)   # child has its own copy via inheritance
    os.close(w_out)

    nethook.inject(pi.dwProcessId, nethook.dll_path())
    kernel32.ResumeThread(pi.hThread)
    kernel32.CloseHandle(pi.hThread)

    time.sleep(1.0)     # let the hook DLL's fast scan pass run (it starts at ~0-100ms)
    os.write(w_write, b"\n")
    lines = []
    with os.fdopen(r_out, "r") as out:
        for _ in range(3):
            lines.append(out.readline().strip())
        # Check aliveness BEFORE sending the second go-ahead: nettest.c exits
        # immediately once it receives that, so this is the only point where
        # "still blocked on its second fgets, unharmed" is actually true.
        still_running = kernel32.WaitForSingleObject(pi.hProcess, 0) == 0x102  # WAIT_TIMEOUT
        os.write(w_write, b"\n")
        time.sleep(0.3)
    os.close(w_write)
    kernel32.TerminateProcess(pi.hProcess, 0)
    kernel32.CloseHandle(pi.hProcess)
    result = _parse(lines)
    result["_alive_after_checks"] = still_running
    return result


def main():
    if not os.path.isfile(NETTEST):
        print(f"Build native\\nettest.exe first (see native\\build.ps1). Looked for: {NETTEST}")
        return 1
    if not nethook.dll_path():
        print("hooknet64.dll not found next to netgag/nethook.py.")
        return 1

    base = run_baseline()
    print(f"[baseline / unhooked] {base}")
    assert base.get("CONNECT_RC") == "0", "baseline connect() failed - no real internet on this machine?"
    assert base.get("GETADDRINFO_RC") == "0", "baseline getaddrinfo() failed"
    assert base.get("INTERNET_STATE") == "1", "baseline InternetGetConnectedState reported offline"
    print("[ok] baseline shows a genuinely working network (so the hooked run below is a fair comparison)")

    hooked = run_hooked()
    print(f"[hooked / injected]   {hooked}")
    assert hooked.get("CONNECT_RC") == "-1", hooked
    assert hooked.get("ERR") == str(WSAENETUNREACH), hooked
    print(f"[ok] connect() now fails with WSAENETUNREACH ({WSAENETUNREACH}) instead of succeeding")
    assert hooked.get("GETADDRINFO_RC") == str(WSAHOST_NOT_FOUND), hooked
    print(f"[ok] getaddrinfo() now fails with WSAHOST_NOT_FOUND ({WSAHOST_NOT_FOUND}) instead of resolving")
    assert hooked.get("INTERNET_STATE") == "0", hooked
    print("[ok] InternetGetConnectedState() now reports OFFLINE instead of online")
    assert hooked.get("_alive_after_checks") is True
    print("[ok] the process itself was still alive and unharmed after all three checks "
         "(only its network calls were affected, not its execution)")

    print("ALL NETWORK-HOOK LIVE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
