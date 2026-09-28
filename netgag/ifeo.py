"""Optional 'auto-hook' via Image File Execution Options (IFEO) debugger
substitution: Windows will run our small native stub INSTEAD of the named
program every time ANYTHING launches it, by ANY means (double-click, a
shortcut, another program) - not just through NetGag. The stub then starts
the REAL program itself (suspended), injects the network hook, and resumes
it, so the illusion of no network applies automatically forever, without
needing to launch it through NetGag each time.

IMPORTANT / DANGEROUS: IFEO keys by FILE NAME ONLY, not by folder. Enabling
this for "MyGame.exe" affects every process anywhere on the machine literally
named MyGame.exe. For a name shared by many unrelated programs (any common
interpreter or shell - python.exe, node.exe, cmd.exe, ...) this would hijack
ALL of them, not just the one meant, which is the opposite of NetGag's
per-file precision elsewhere. GENERIC_NAMES below is refused outright, no
override - this is not a policy the UI can talk its way around.
"""

import ntpath
import os
import shutil
import sys
import winreg

from . import pathutil

IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

# Never allowed, regardless of path: shared/generic executable names where
# IFEO's filename-only keying would hit far more than the one file meant.
GENERIC_NAMES = frozenset({
    "python.exe", "pythonw.exe", "python3.exe", "node.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "conhost.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe",
    "msiexec.exe", "iexplore.exe", "msedge.exe", "chrome.exe", "firefox.exe", "java.exe", "javaw.exe",
    "ruby.exe", "perl.exe", "php.exe",
}) | pathutil.PROTECTED_NAMES


class IfeoError(RuntimeError):
    """An auto-hook registration could not be made (or refused on purpose)."""


def is_generic_name(path):
    return ntpath.basename(path).lower() in GENERIC_NAMES


def stub_dir():
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    return os.path.join(base, "NetGag")


def stub_path():
    return os.path.join(stub_dir(), "ifeo_stub.exe")


def dll_dest_path():
    return os.path.join(stub_dir(), "hooknet64.dll")


def _bundled_path(name):
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [os.path.join(here, name)]
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        candidates += [os.path.join(meipass, "netgag", name), os.path.join(meipass, name)]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return ""


def _ensure_stub_installed():
    """Copies the stub exe + hook DLL to %ProgramData%\\NetGag - a stable,
    world-readable location the stub can find without needing NetGag's own
    (per-user) config."""
    os.makedirs(stub_dir(), exist_ok=True)
    src_stub = _bundled_path("ifeo_stub.exe")
    src_dll = _bundled_path("hooknet64.dll")
    if not src_stub or not src_dll:
        raise IfeoError("ifeo_stub.exe / hooknet64.dll not found in this build (run native\\build.ps1).")
    for src, dest in ((src_stub, stub_path()), (src_dll, dll_dest_path())):
        if not os.path.isfile(dest) or os.path.getmtime(src) > os.path.getmtime(dest):
            shutil.copy2(src, dest)


def enable(path):
    """Register auto-hook for *path*'s exact file name.

    Raises IfeoError (never enables anything) for a generic/protected name.
    """
    if pathutil.is_protected(path) or is_generic_name(path):
        raise IfeoError(
            f"{ntpath.basename(path)} is a name shared by many unrelated programs (or a core "
            "Windows component). Auto-hook would affect every process anywhere on this machine "
            "with that exact file name, not just this one - NetGag refuses.")
    _ensure_stub_installed()
    name = ntpath.basename(path)
    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, f"{IFEO_KEY}\\{name}", 0, winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, f'"{stub_path()}"')
    finally:
        winreg.CloseKey(key)


def disable(name):
    """Remove the Debugger value (and the subkey, if now otherwise empty) for *name*."""
    key_path = f"{IFEO_KEY}\\{name}"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS)
    except FileNotFoundError:
        return
    try:
        try:
            winreg.DeleteValue(key, "Debugger")
        except FileNotFoundError:
            pass
    finally:
        winreg.CloseKey(key)
    try:
        sub = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        try:
            subkeys, values, _ = winreg.QueryInfoKey(sub)
        finally:
            winreg.CloseKey(sub)
        if subkeys == 0 and values == 0:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
    except FileNotFoundError:
        pass


def list_enabled():
    """File names currently registered with OUR stub as their IFEO Debugger
    (so removing NetGag's own entries never touches anyone else's IFEO use)."""
    out = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return out
    try:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                sub = winreg.OpenKey(root, name, 0, winreg.KEY_READ)
                try:
                    value, _type = winreg.QueryValueEx(sub, "Debugger")
                finally:
                    winreg.CloseKey(sub)
            except FileNotFoundError:
                continue
            if stub_path().lower() in str(value).lower():
                out.append(name)
    finally:
        winreg.CloseKey(root)
    return out
