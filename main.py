"""NetGag entry point: elevate, set up logging, start the GUI."""

import ctypes
import logging
import os
import subprocess
import sys
from logging.handlers import RotatingFileHandler


def set_high_dpi():
    """Crisp text on high-DPI monitors (must run before the Tk window exists)."""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:  # noqa: BLE001
            pass


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:  # noqa: BLE001
        return False


def elevate_if_needed():
    """Relaunch with a UAC prompt when not elevated (the built exe is already
    elevated through its manifest, so this only matters when run as a script)."""
    if is_admin():
        return
    if getattr(sys, "frozen", False):
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])
    shell_execute = ctypes.windll.shell32.ShellExecuteW
    shell_execute.restype = ctypes.c_void_p
    result = shell_execute(None, "runas", sys.executable, params, None, 1) or 0
    if result > 32:          # new elevated instance started
        sys.exit(0)
    ctypes.windll.user32.MessageBoxW(
        0,
        "NetGag needs Administrator rights to create Windows Firewall rules.\n\n"
        "Please start it again and accept the prompt.",
        "NetGag", 0x10)
    sys.exit(1)


def setup_logging():
    from netgag import config
    os.makedirs(config.config_dir(), exist_ok=True)
    handler = RotatingFileHandler(
        os.path.join(config.config_dir(), "netgag.log"),
        maxBytes=512_000, backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])


def main():
    if sys.platform != "win32":
        print("NetGag only runs on Windows.")
        return 1
    if os.environ.get("NETGAG_SELFTEST_NETHOOK"):
        # Diagnostic-only path: proves the RUNNING build (dev tree or frozen
        # exe) can locate its own hooknet64.dll. No elevation beyond the
        # normal manifest, no main GUI. This build has no console, so the
        # result is shown as a message box instead of printed.
        from netgag import nethook
        path = nethook.dll_path()
        msg = f"dll_path() -> {path!r}\n\n{'PASS' if path else 'FAIL: hooknet64.dll not found'}"
        ctypes.windll.user32.MessageBoxW(0, msg, "NetGag self-test", 0)
        return 0 if path else 1
    elevate_if_needed()
    set_high_dpi()
    setup_logging()
    from netgag.ui import NetGagApp
    NetGagApp().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
