"""Unit tests for the pure (non-GUI, non-firewall) logic.

Run from the project root:  python -m unittest discover -s tests -t .
"""

import json
import os
import tempfile
import unittest

from netgag import config, firewall, handlers, hooklog, ifeo, nethook, pathutil
from netgag.ui import Entry


class RuleNameTests(unittest.TestCase):
    def test_deterministic_and_case_insensitive(self):
        a = pathutil.rule_name(r"C:\Apps\Foo\foo.exe", "OUT")
        b = pathutil.rule_name(r"c:\apps\foo\FOO.EXE", "OUT")
        self.assertEqual(a.lower(), b.lower())                 # same hash; stem casing is cosmetic
        self.assertEqual(a, pathutil.rule_name(r"C:\Apps\Foo\foo.exe", "OUT"))

    def test_direction_and_path_change_the_name(self):
        p = r"C:\Apps\foo.exe"
        self.assertNotEqual(pathutil.rule_name(p, "OUT"), pathutil.rule_name(p, "IN"))
        self.assertNotEqual(pathutil.rule_name(p, "OUT"), pathutil.rule_name(r"C:\Other\foo.exe", "OUT"))

    def test_name_has_no_wildcard_or_odd_characters(self):
        name = pathutil.rule_name(r"C:\x\we[ir]d *name?.exe", "OUT")
        self.assertRegex(name, r"^NetGag_OUT_[A-Za-z0-9_-]+_[0-9a-f]{10}$")

    def test_stem_falls_back_when_empty(self):
        self.assertEqual(pathutil.safe_stem("C:\\x\\"), "app")
        self.assertEqual(pathutil.safe_stem(r"C:\x\my app (v2).exe"), "my_app__v2_")


class ProtectionTests(unittest.TestCase):
    WIN = r"C:\Windows"

    def test_critical_system_binaries_are_protected(self):
        for p in (r"C:\Windows\System32\svchost.exe", r"C:\Windows\explorer.exe",
                  r"c:\windows\system32\LSASS.EXE"):
            self.assertTrue(pathutil.is_protected(p, self.WIN), p)

    def test_same_name_elsewhere_is_not_protected(self):
        self.assertFalse(pathutil.is_protected(r"D:\tools\svchost.exe", self.WIN))
        self.assertFalse(pathutil.is_protected(r"C:\Windows2\svchost.exe", self.WIN))

    def test_ordinary_program_is_not_protected(self):
        self.assertFalse(pathutil.is_protected(r"C:\Windows\System32\notepad.exe", self.WIN))


class MiscHelperTests(unittest.TestCase):
    def test_format_size(self):
        self.assertEqual(pathutil.format_size(None), "N/A")
        self.assertEqual(pathutil.format_size(512), "512 B")
        self.assertEqual(pathutil.format_size(1536), "1.5 KB")
        self.assertEqual(pathutil.format_size(5 * 1024 ** 2), "5.00 MB")

    def test_entry_normalizes_path(self):
        e = Entry("C:/Apps//foo/../bar/App.EXE")
        self.assertEqual(e.name, "App.EXE")
        self.assertEqual(e.key, pathutil.norm_key(r"c:\apps\bar\app.exe"))

    def test_find_executables(self):
        with tempfile.TemporaryDirectory() as root:
            sub = os.path.join(root, "sub")
            os.makedirs(sub)
            for rel in ("a.exe", "b.txt", os.path.join("sub", "c.EXE")):
                with open(os.path.join(root, rel), "wb"):
                    pass
            flat = {os.path.basename(p).lower() for p in pathutil.find_executables(root, recursive=False)}
            deep = {os.path.basename(p).lower() for p in pathutil.find_executables(root, recursive=True)}
            self.assertEqual(flat, {"a.exe"})
            self.assertEqual(deep, {"a.exe", "c.exe"})

    def test_find_files_multi_ext_and_prune(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "node_modules"))
            os.makedirs(os.path.join(root, "src"))
            for rel in ("a.py", "b.js", "c.txt", os.path.join("src", "d.py"),
                       os.path.join("node_modules", "junk.py")):
                with open(os.path.join(root, rel), "w") as fh:
                    fh.write("x")
            found = {os.path.relpath(p, root).lower() for p in
                    pathutil.find_files(root, recursive=True, exts=(".py", ".js"))}
            self.assertEqual(found, {"a.py", "b.js", os.path.join("src", "d.py").lower()})


class HandlersTests(unittest.TestCase):
    def test_exe_html_source_classification(self):
        self.assertEqual(handlers.classify(r"C:\x\app.exe").kind, "exe")
        self.assertEqual(handlers.classify(r"C:\x\page.html").kind, "html")
        self.assertEqual(handlers.classify(r"C:\x\main.cpp").kind, "source")

    def test_unsupported_and_custom_interpreter(self):
        plan = handlers.classify(r"C:\x\script.rb")
        self.assertEqual(plan.kind, "unsupported")
        self.assertTrue(plan.needs_interpreter)

        with tempfile.TemporaryDirectory() as d:
            fake_ruby = os.path.join(d, "ruby.exe")
            open(fake_ruby, "wb").close()
            cfg = {"interpreters": {".rb": fake_ruby}}
            plan2 = handlers.classify(r"C:\x\script.rb", cfg)
            self.assertEqual(plan2.kind, "script")
            self.assertEqual(plan2.interpreter, fake_ruby)
            self.assertTrue(plan2.runner.endswith("ruby.exe"))

    def test_python_family_resolves_to_real_interpreter(self):
        # This machine has Python installed (we are running under it).
        plan = handlers.classify(r"C:\x\script.py")
        self.assertEqual(plan.kind, "script")
        self.assertTrue(os.path.isfile(plan.interpreter))
        self.assertTrue(plan.pyvenv)
        self.assertNotEqual(pathutil.norm_key(plan.interpreter), pathutil.norm_key(plan.runner))

    def test_runner_dir_deterministic_per_path(self):
        with tempfile.TemporaryDirectory() as root:
            a = handlers.runner_dir(r"C:\x\a.py", root)
            b = handlers.runner_dir(r"C:\x\a.py", root)
            c = handlers.runner_dir(r"C:\x\b.py", root)
            self.assertEqual(a, b)
            self.assertNotEqual(a, c)

    def test_ensure_and_remove_runner_roundtrip(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as scripts:
            script = os.path.join(scripts, "hello.py")
            with open(script, "w") as fh:
                fh.write("print('hi')")
            plan = handlers.classify(script)
            plan = handlers.Plan(**{**plan.__dict__, "runner": os.path.join(
                handlers.runner_dir(script, root), os.path.basename(plan.interpreter))})
            runner = handlers.ensure_runner(plan, script)
            self.assertTrue(os.path.isfile(runner))
            self.assertTrue(os.path.isfile(os.path.join(os.path.dirname(runner), "pyvenv.cfg")))
            owner = handlers.owner_of_program(runner, root)
            self.assertEqual(pathutil.norm_key(owner), pathutil.norm_key(script))
            handlers.remove_runner(script, root)
            self.assertFalse(os.path.isfile(runner))

    def test_owner_of_program_rejects_paths_outside_runners_root(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertIsNone(handlers.owner_of_program(r"C:\Windows\System32\svchost.exe", root))

    def test_write_launcher_exe(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            exe = os.path.join(d, "app.exe")
            open(exe, "wb").close()
            plan = handlers.classify(exe)
            launcher = handlers.write_launcher(exe, plan, launcher_dir=out)
            self.assertTrue(os.path.isfile(launcher))
            with open(launcher) as fh:
                content = fh.read()
            self.assertIn("app.exe", content)

    def test_write_launcher_missing_file_raises(self):
        plan = handlers.Plan("exe", "Program")
        with self.assertRaises(handlers.RunnerError):
            handlers.write_launcher(r"C:\definitely\missing.exe", plan)

    def test_find_build_outputs(self):
        with tempfile.TemporaryDirectory() as root:
            src_dir = os.path.join(root, "src")
            bin_dir = os.path.join(root, "bin", "Debug")
            os.makedirs(src_dir)
            os.makedirs(bin_dir)
            src = os.path.join(src_dir, "tool.cpp")
            open(src, "w").close()
            exe = os.path.join(bin_dir, "tool.exe")
            open(exe, "wb").close()
            found = handlers.find_build_outputs(src)
            self.assertIn(pathutil.norm_path(exe), found)


class ConfigTests(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "config.json")
            cfg = config.load(path)                       # missing file -> defaults
            self.assertEqual(cfg, config.DEFAULTS)
            cfg["files"] = [r"C:\a.exe"]
            cfg["watched_folders"] = [{"path": r"C:\w", "recursive": False, "exts": [".exe"]}]
            config.save(cfg, path)
            self.assertEqual(config.load(path), cfg)

    def test_malformed_values_fall_back(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"files": "nope", "watched_folders": [1, {"path": 5}], "recursive": "yes",
                           "ignored": ["x", 3]}, fh)
            cfg = config.load(path)
            self.assertEqual(cfg["files"], [])
            self.assertEqual(cfg["watched_folders"], [])
            self.assertTrue(cfg["recursive"])
            self.assertEqual(cfg["ignored"], ["x"])

    def test_corrupt_file_returns_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertEqual(config.load(path), config.DEFAULTS)


class FirewallParsingTests(unittest.TestCase):
    def test_json_and_list_helpers(self):
        self.assertIsNone(firewall._json(""))
        self.assertEqual(firewall._as_list(None), [])
        self.assertEqual(firewall._as_list({"a": 1}), [{"a": 1}])
        self.assertEqual(firewall._as_list([1, 2]), [1, 2])
        with self.assertRaises(firewall.FirewallError):
            firewall._json("garbage")

    def test_query_state_reduces_rows(self):
        rows = [
            {"program": r"C:\A\a.exe", "direction": "Outbound", "action": "Block", "enabled": "True"},
            {"program": r"c:\a\A.EXE", "direction": "Inbound", "action": "Block", "enabled": "True"},
            {"program": r"C:\B\b.exe", "direction": "Outbound", "action": "Block", "enabled": "False"},
            {"program": r"C:\C\c.exe", "direction": "Outbound", "action": "Allow", "enabled": "True"},
            {"program": "Any", "direction": "Outbound", "action": "Block", "enabled": "True"},
        ]
        original = firewall._query_rows
        firewall._query_rows = lambda: rows
        try:
            state = firewall.query_state()
            managed = firewall.list_managed_programs()
        finally:
            firewall._query_rows = original
        self.assertEqual(state, {pathutil.norm_key(r"C:\A\a.exe"): {"Outbound", "Inbound"}})
        self.assertEqual(len(managed), 3)      # A (deduplicated), B and C; "Any" ignored


class HookGlueTests(unittest.TestCase):
    """Non-elevated coverage for the fake-offline hook's glue code. The hook
    itself (actual injection/interception) is only provable elevated - see
    tests/smoke_nethook.py - but everything here needs no admin rights."""

    def test_hook_supported_by_kind(self):
        self.assertTrue(handlers.hook_supported(handlers.classify(r"C:\x\app.exe")))
        self.assertTrue(handlers.hook_supported(handlers.classify(r"C:\x\script.py")))
        self.assertFalse(handlers.hook_supported(handlers.classify(r"C:\x\page.html")))
        self.assertFalse(handlers.hook_supported(handlers.classify(r"C:\x\main.cpp")))

    def test_build_command_line_exe(self):
        plan = handlers.classify(r"C:\Program Files\App\app.exe")
        self.assertEqual(handlers.build_command_line(r"C:\Program Files\App\app.exe", plan),
                         '"C:\\Program Files\\App\\app.exe"')

    def test_build_command_line_script_requires_existing_runner(self):
        plan = handlers.classify(r"C:\x\script.py")
        with self.assertRaises(handlers.RunnerError):
            handlers.build_command_line(r"C:\x\script.py", plan)   # runner not built yet

        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as scripts:
            script = os.path.join(scripts, "hello.py")
            with open(script, "w") as fh:
                fh.write("print('hi')")
            plan = handlers.classify(script)
            plan = handlers.Plan(**{**plan.__dict__, "runner": os.path.join(
                handlers.runner_dir(script, root), os.path.basename(plan.interpreter))})
            handlers.ensure_runner(plan, script)
            cmdline = handlers.build_command_line(script, plan)
            self.assertIn(plan.runner, cmdline)
            self.assertIn(script, cmdline)
            handlers.remove_runner(script, root)

    def test_html_not_supported_by_build_command_line(self):
        plan = handlers.classify(r"C:\x\page.html")
        with self.assertRaises(handlers.RunnerError):
            handlers.build_command_line(r"C:\x\page.html", plan)

    def test_dll_bundled_and_locatable(self):
        # Doesn't inject anything - just confirms the packaged/dev-tree DLL
        # is where nethook.py will look for it.
        path = nethook.dll_path()
        self.assertTrue(path, "hooknet64.dll not found - run native\\build.ps1")
        self.assertTrue(os.path.isfile(path))


class HookLogTests(unittest.TestCase):
    def test_parses_patch_and_counts_lines(self):
        lines = [
            "[pid 111] hooknet64.dll DllMain DLL_PROCESS_ATTACH\n",
            "[pid 111] patched ws2_32.dll!connect\n",
            "[pid 111] patched wininet.dll!InternetGetConnectedState\n",
            "[pid 222] patched ws2_32.dll!getaddrinfo\n",
            "[pid 111] blocked-call counts: connect=3 WSAConnect=0 getaddrinfo=1 GetAddrInfoW=0 "
            "InternetGetConnectedState=2 InternetCheckConnectionA=0 InternetCheckConnectionW=0 "
            "GetAdaptersAddresses=0 GetAdaptersInfo=0 GetProcAddress_intercepted=0\n",
        ]
        self.assertEqual(hooklog.attached_pids(lines), {111})
        self.assertEqual(hooklog.patched_functions_for_pid(111, lines),
                         {"ws2_32.dll!connect", "wininet.dll!InternetGetConnectedState"})
        self.assertEqual(hooklog.patched_functions_for_pid(222, lines), {"ws2_32.dll!getaddrinfo"})
        self.assertEqual(hooklog.patched_functions_for_pid(999, lines), set())
        counts = hooklog.activity_counts_for_pid(111, lines)
        self.assertEqual(counts["connect"], 3)
        self.assertEqual(counts["InternetGetConnectedState"], 2)
        self.assertEqual(hooklog.activity_counts_for_pid(999, lines), {})

    def test_empty_log_is_harmless(self):
        self.assertEqual(hooklog.attached_pids([]), set())
        self.assertEqual(hooklog.patched_functions_for_pid(1, []), set())
        self.assertEqual(hooklog.activity_counts_for_pid(1, []), {})


class IfeoGatingTests(unittest.TestCase):
    def test_generic_and_protected_names_refused(self):
        for path in (r"C:\Python313\python.exe", r"D:\anything\node.exe",
                     r"C:\Windows\System32\svchost.exe", r"C:\x\cmd.exe"):
            self.assertTrue(ifeo.is_generic_name(path) or pathutil.is_protected(path), path)
            with self.assertRaises(ifeo.IfeoError):
                ifeo.enable(path)

    def test_uniquely_named_program_is_allowed_by_the_name_check(self):
        # Doesn't actually touch the registry - just confirms the gate itself
        # doesn't reject an ordinary, uniquely-named program.
        self.assertFalse(ifeo.is_generic_name(r"C:\Games\MyGame.exe"))
        self.assertFalse(pathutil.is_protected(r"C:\Games\MyGame.exe"))


class BundledNativeBinaryTests(unittest.TestCase):
    """Non-elevated: just confirms the extra native helpers used by the
    self-test and auto-hook features are present in the dev tree."""

    def test_nettest_and_ifeo_stub_present(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(nethook.__file__)))
        self.assertTrue(os.path.isfile(os.path.join(base, "netgag", "nettest.exe")),
                        "run native\\build.ps1")
        self.assertTrue(os.path.isfile(os.path.join(base, "netgag", "ifeo_stub.exe")),
                        "run native\\build.ps1")


if __name__ == "__main__":
    unittest.main()
