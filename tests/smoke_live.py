"""Read-only live checks - this NEVER creates or removes firewall rules.

Run from the project root:  python -m tests.smoke_live
Covers: PowerShell plumbing, Win32 process enumeration, protected-process
refusal, and the GUI (kept hidden) including the busy-state regression.
"""

import copy
import sys
import time

from netgag import config, firewall, pathutil, procs

config.save = lambda *a, **k: None          # never touch the real settings file


def pump(app, seconds):
    end = time.time() + seconds
    while time.time() < end:
        app.update()
        time.sleep(0.05)


def wait_idle(app, timeout=30):
    end = time.time() + timeout
    while app.is_busy and time.time() < end:
        pump(app, 0.1)
    assert not app.is_busy, "app stayed busy"


def main():
    t = time.time()
    managed = firewall.list_managed_programs()
    print(f"[ok] list_managed_programs -> {len(managed)} program(s) in {time.time() - t:.1f}s")
    t = time.time()
    state = firewall.query_state()
    print(f"[ok] query_state -> {len(state)} blocked program(s) in {time.time() - t:.1f}s")

    running = procs.running_keys()
    assert pathutil.norm_key(sys.executable) in running, "own process not detected"
    print(f"[ok] running_keys -> {len(running)} processes, own python.exe detected")
    assert procs.terminate_by_path(sys.executable) == 0
    assert procs.terminate_by_path(r"C:\Windows\System32\svchost.exe") == 0
    print("[ok] refuses to terminate itself / protected system processes")

    from netgag.ui import NetGagApp
    cfg = copy.deepcopy(config.DEFAULTS)
    cfg["files"] = [sys.executable, r"C:\definitely\missing\nothing.exe"]
    app = NetGagApp(cfg)
    app.withdraw()
    pump(app, 0.5)
    wait_idle(app)                                   # startup import + refresh chain
    print(f"[ok] startup chain finished, busy={app.is_busy}")

    box = {}
    assert app.run_task(lambda post: (post("working"), 42)[1], lambda r: box.update(r=r), "test")
    pump(app, 1.0)
    assert box.get("r") == 42, "on_done callback never ran"
    assert not app.is_busy and str(app.btn_block.cget("state")) == "normal", "REGRESSION: UI stuck busy"
    print("[ok] task finished, busy cleared, buttons re-enabled")

    app.refresh_tracked_files()
    wait_idle(app)
    me = app.entries[pathutil.norm_key(sys.executable)]
    gone = app.entries[pathutil.norm_key(r"C:\definitely\missing\nothing.exe")]
    assert me.state == "allowed" and me.running and me.size, (me.state, me.running, me.size)
    assert gone.missing and gone.size is None
    print(f"[ok] refresh: own exe state={me.state} running={me.running}; missing file flagged")

    for col in ("name", "status", "process", "size", "path"):
        app.sort_by(col)
        app.sort_by(col)
    app.tree.selection_set(app.tree.get_children()[:1])
    before = app.get_selected_entries()
    app.render_table()
    assert app.get_selected_entries() == before, "selection lost on re-render"
    print("[ok] all sort columns work, selection survives re-render")

    app.destroy()
    print("ALL LIVE CHECKS PASSED")


if __name__ == "__main__":
    main()
