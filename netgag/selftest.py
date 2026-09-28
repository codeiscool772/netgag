"""In-app self-test: proves NetGag's two isolation mechanisms actually work,
using the bundled native/nettest.exe test target - the same check as
tests/smoke_multitype.py and tests/smoke_nethook.py, packaged so it can be
run from inside the shipped app without a dev setup.
"""

import ctypes
import os
import subprocess
import sys
import time

from . import firewall, hooklog, nethook


def nettest_path():
    candidates = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "nettest.exe")]
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        candidates += [os.path.join(meipass, "netgag", "nettest.exe"), os.path.join(meipass, "nettest.exe")]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return ""


def test_firewall_block(progress=None):
    """Returns (ok, detail). Creates and always removes a temporary rule for
    the bundled test program - never touches anything the user added."""
    path = nettest_path()
    if not path:
        return False, "nettest.exe is not included in this build."
    if progress:
        progress("Creating a temporary firewall rule for the built-in test program...")
    results = firewall.block_many([path])
    ok, err = results[0][1], results[0][2]
    if not ok:
        firewall.unblock_many([path])
        return False, f"Could not create the firewall rule: {err}"
    try:
        if progress:
            progress("Launching it to confirm the block actually works...")
        proc = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            proc.stdin.write("\n")
            proc.stdin.flush()
            line1 = proc.stdout.readline()
            proc.stdin.write("\n")
            proc.stdin.flush()
            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.kill()
        if "CONNECT_RC=0" in line1:
            return False, "The test program could still connect - the firewall rule did not take effect."
        if "CONNECT_RC=-1" not in line1:
            return False, f"Unexpected result from the test program: {line1.strip()!r}"
        return True, "Confirmed: the firewall correctly blocked the test program's connection attempt."
    finally:
        firewall.unblock_many([path])


def test_fake_offline(progress=None):
    """Returns (ok, detail). Injects into a throwaway instance of the bundled
    test program and confirms, via the hook's own activity log, that it
    genuinely patched the network functions - not just that injection didn't
    raise an exception."""
    dll = nethook.dll_path()
    path = nettest_path()
    if not dll:
        return False, "hooknet64.dll is not included in this build."
    if not path:
        return False, "nettest.exe is not included in this build."

    if progress:
        progress("Starting the built-in test program with the network hook injected...")
    try:
        pid, handle = nethook.create_suspended_and_inject(f'"{path}"', dll=dll)
    except nethook.HookError as exc:
        return False, f"Injection failed: {exc}"

    kernel32 = ctypes.windll.kernel32
    try:
        if progress:
            progress("Confirming the hook actually patched something...")
        patched = set()
        for _ in range(20):        # up to ~4 seconds
            patched = hooklog.patched_functions_for_pid(pid)
            if patched:
                break
            time.sleep(0.2)
        kernel32.TerminateProcess(handle, 0)
        if not patched:
            return False, ("The hook was injected but its activity log shows no functions were "
                           "patched in that process - is it a 64-bit process?")
        return True, f"Confirmed via the hook's own log: {len(patched)} function(s) patched ({', '.join(sorted(patched))})."
    finally:
        kernel32.CloseHandle(handle)


def run_all(progress=None):
    """Returns [(name, ok, detail), ...] for both mechanisms."""
    results = []
    ok, detail = test_firewall_block(progress)
    results.append(("Firewall block", ok, detail))
    ok, detail = test_fake_offline(progress)
    results.append(("Fake-offline hook", ok, detail))
    return results
