"""Read-only-ish live checks for the new multi-file-type support.

Run from the project root, ELEVATED (this creates and removes real firewall rules,
so it needs the same admin rights NetGag itself asks for):
  python -m tests.smoke_multitype
"""

import os
import subprocess
import tempfile
import time

from netgag import config, firewall, handlers, pathutil, procs

config.save = lambda *a, **k: None


def main():
    tmp = tempfile.mkdtemp(prefix="netgag_smoke_")
    script = os.path.join(tmp, "loop.py")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write("import time\nwhile True:\n    time.sleep(1)\n")

    plan = handlers.classify(script)
    assert plan.kind == "script", plan.kind
    assert os.path.isfile(plan.interpreter), f"no interpreter found: {plan.interpreter}"
    print(f"[ok] classify() -> script, interpreter={plan.interpreter}")

    runner = None
    proc = None
    try:
        # --- Phase 1: an ordinary, NOT-yet-blocked instance (run via the real
        # interpreter, the way it runs before the user ever clicks Block).
        proc = subprocess.Popen([plan.interpreter, script])
        time.sleep(1.5)
        pids = procs.find_script_instances(script, plan.interpreter, plan.runner)
        assert proc.pid in pids, (proc.pid, pids)
        print(f"[ok] find_script_instances found the unblocked instance (pid {proc.pid})")
        assert procs.terminate_pid(proc.pid) == 1
        proc.wait(timeout=5)
        proc = None
        print("[ok] terminate_pid closed it")

        # --- Phase 2: block it.
        runner = handlers.ensure_runner(plan, script)
        assert os.path.isfile(runner)
        print(f"[ok] ensure_runner -> {runner}")

        results = firewall.block_many([runner])
        assert results == [(runner, True, "")], results
        print("[ok] block_many() blocked the runner copy")

        state = firewall.query_state()
        assert {"Outbound", "Inbound"} <= state.get(pathutil.norm_key(runner), set())
        print("[ok] query_state() reports it as fully blocked")

        managed = firewall.list_managed_programs()
        assert any(pathutil.norm_key(p) == pathutil.norm_key(runner) for p in managed)
        owner = handlers.owner_of_program(runner)
        assert owner and pathutil.norm_key(owner) == pathutil.norm_key(script)
        print("[ok] list_managed_programs + owner_of_program round-trip to the original script")

        # --- Phase 3: run it blocked (via the isolated runner, the way "Run
        # Blocked" does) and confirm the UI's "is it running" check sees it,
        # while find_script_instances correctly leaves an already-isolated
        # instance alone (nothing to warn about - it's already blocked).
        proc = subprocess.Popen([runner, script])
        time.sleep(1.5)
        running = procs.running_keys()
        assert pathutil.norm_key(runner) in running
        print("[ok] running_keys() sees the isolated instance (drives the 'Running' status column)")
        pids_after = procs.find_script_instances(script, plan.interpreter, runner)
        assert proc.pid not in pids_after, (proc.pid, pids_after)
        print("[ok] find_script_instances correctly ignores the already-isolated instance")
        assert procs.terminate_pid(proc.pid) == 1
        proc.wait(timeout=5)
        proc = None
        print("[ok] terminate_pid closed the isolated instance")

        removed = firewall.unblock_many([runner])
        assert removed >= 1
        state2 = firewall.query_state()
        assert pathutil.norm_key(runner) not in state2
        print("[ok] unblock_many() removed the rules")

    finally:
        if proc is not None:
            proc.kill()
        firewall.unblock_many([runner] if runner else [])
        handlers.remove_runner(script)
        for f in os.listdir(tmp):
            try:
                os.remove(os.path.join(tmp, f))
            except OSError:
                pass
        os.rmdir(tmp)

    print("ALL MULTI-TYPE LIVE CHECKS PASSED")


if __name__ == "__main__":
    main()
