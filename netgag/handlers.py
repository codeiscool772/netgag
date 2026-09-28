"""Support for files that are not .exe.

A firewall rule can only match a *program*, never a file.  So for scripts NetGag
gives every file its own private copy ("runner") of the interpreter - a hardlink,
so it costs no disk space - and blocks *that* copy.  The script is then started
through its runner, which means only this one script is cut off, not every other
script that uses the same interpreter.  (Verified for Python, Node.js, batch and
VBScript; other interpreters can be supplied by the user and are experimental.)

  * .exe                   blocked directly
  * .py .js .bat .vbs ...  per-file runner + firewall rule
  * .html                  cannot be firewalled per page: opened in an isolated
                           browser instance whose network is switched off (soft)
  * .cpp .rs .go ...       never run, so NetGag finds the compiled .exe instead
"""

import glob
import hashlib
import json
import logging
import ntpath
import os
import shutil
import subprocess
from dataclasses import dataclass, field

from . import config, pathutil

log = logging.getLogger(__name__)

CREATE_NO_WINDOW = 0x08000000

HTML_EXTS = (".html", ".htm", ".xhtml", ".mhtml")
SOURCE_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".rs", ".go",
               ".cs", ".vb", ".zig", ".nim", ".d", ".pas", ".f90")

BROWSER_FLAGS = (
    "--no-first-run", "--no-default-browser-check", "--new-window",
    "--disable-background-networking", "--disable-component-update", "--disable-sync",
    '--proxy-server="http://127.0.0.1:9"',   # nothing listens on the discard port
    '--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE localhost , EXCLUDE 127.0.0.1"',
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
)


class RunnerError(RuntimeError):
    """A runner/launcher could not be prepared."""


@dataclass(frozen=True)
class Family:
    key: str
    label: str
    exts: tuple
    args: tuple = ()          # arguments placed between the interpreter and the file
    siblings: bool = False    # also link the interpreter's neighbouring *.dll files
    pyvenv: bool = False      # Python: write a pyvenv.cfg so the copy finds its stdlib
    verify: tuple = ()        # arguments for a self-test of the finished runner


FAMILIES = (
    Family("python", "Python script", (".py", ".pyw"), siblings=True, pyvenv=True,
           verify=("-c", "pass")),
    Family("node", "Node.js script", (".js", ".mjs", ".cjs"), verify=("--version",)),
    Family("batch", "Batch script", (".bat", ".cmd"), args=("/c", "call"),
           verify=("/c", "exit 0")),
    Family("vbscript", "VBScript", (".vbs", ".vbe"), args=("//NoLogo",)),
)

# (label, extensions) groups offered when adding a whole folder.
FOLDER_GROUPS = (
    ("Programs (.exe)", (".exe",)),
    ("Python (.py, .pyw)", (".py", ".pyw")),
    ("Node.js (.js, .mjs, .cjs)", (".js", ".mjs", ".cjs")),
    ("Batch (.bat, .cmd)", (".bat", ".cmd")),
    ("VBScript (.vbs, .vbe)", (".vbs", ".vbe")),
    ("HTML pages (.html, .htm)", (".html", ".htm")),
)

SUPPORTED_EXTS = tuple(sorted(
    {".exe"} | set(HTML_EXTS) | set(SOURCE_EXTS) | {e for f in FAMILIES for e in f.exts}))


@dataclass
class Plan:
    """How NetGag deals with one file."""
    kind: str                       # exe | script | html | source | unsupported
    label: str
    interpreter: str = ""
    runner: str = ""
    args: tuple = ()
    env: dict = field(default_factory=dict)
    siblings: bool = False
    pyvenv: bool = False
    verify: tuple = ()
    gui: bool = False               # start without a console window
    problem: str = ""
    needs_interpreter: bool = False  # unknown type: ask the user for an interpreter


# --------------------------------------------------------------------- lookup
def _system32(name):
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", name)


def _is_store_stub(path):
    return "\\windowsapps\\" in path.lower()


def _which_all(name):
    seen = []
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(folder.strip('"'), name)
        if folder and os.path.isfile(candidate) and candidate not in seen:
            seen.append(candidate)
    return seen


def _read_cfg(path):
    values = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "=" in line:
                    key, _, value = line.partition("=")
                    values[key.strip().lower()] = value.strip()
    except OSError:
        pass
    return values


def unwrap_venv(python_exe):
    """(real interpreter, venv site-packages or None).

    A venv's python.exe is only a launcher that starts the base interpreter as a
    *child process*, so blocking it would block nothing.  We need the base one.
    """
    folder = ntpath.dirname(python_exe)
    for venv_dir in (folder, ntpath.dirname(folder)):
        cfg = ntpath.join(venv_dir, "pyvenv.cfg")
        if os.path.isfile(cfg):
            home = _read_cfg(cfg).get("home", "")
            base = ntpath.join(home, ntpath.basename(python_exe)) if home else ""
            if base and os.path.isfile(base):
                return base, ntpath.join(venv_dir, "Lib", "site-packages")
            return python_exe, None
    return python_exe, None


def _project_venv_python(script, exe_name):
    """Python of a .venv/venv/env folder next to the script (or up to 4 levels above)."""
    folder = ntpath.dirname(script)
    for _ in range(5):
        for name in (".venv", "venv", "env"):
            candidate = ntpath.join(folder, name, "Scripts", exe_name)
            if os.path.isfile(candidate) and os.path.isfile(ntpath.join(folder, name, "pyvenv.cfg")):
                return candidate
        parent = ntpath.dirname(folder)
        if parent == folder:
            break
        folder = parent
    return ""


def _resolve_python(script, ext):
    exe_name = "pythonw.exe" if ext == ".pyw" else "python.exe"
    candidates = []
    project = _project_venv_python(script, exe_name)
    if project:
        candidates.append(project)
    path_hits = [c for c in _which_all(exe_name) if not _is_store_stub(c)]
    # A plain install beats an arbitrary virtualenv that merely happens to be on PATH.
    path_hits.sort(key=lambda c: os.path.isfile(ntpath.join(ntpath.dirname(c), "pyvenv.cfg")) or
                   os.path.isfile(ntpath.join(ntpath.dirname(ntpath.dirname(c)), "pyvenv.cfg")))
    candidates += path_hits
    for cand in candidates:
        base, site = unwrap_venv(cand)
        if os.path.isfile(base) and not _is_store_stub(base):
            env = {"PYTHONPATH": site} if site and os.path.isdir(site) else {}
            return base, env
    return "", {}


def _resolve_family(family, script, ext):
    """(interpreter exe, extra env) - interpreter is '' if none could be found."""
    if family.key == "python":
        return _resolve_python(script, ext)
    if family.key == "node":
        for cand in _which_all("node.exe") + [os.path.join(os.environ.get("ProgramFiles", ""), "nodejs", "node.exe")]:
            if os.path.isfile(cand) and not _is_store_stub(cand):
                return cand, {}
        return "", {}
    if family.key == "batch":
        return os.environ.get("ComSpec") or _system32("cmd.exe"), {}
    if family.key == "vbscript":
        return _system32("cscript.exe"), {}
    return "", {}


def family_for(ext):
    for fam in FAMILIES:
        if ext in fam.exts:
            return fam
    return None


# ------------------------------------------------------------------- planning
def runners_root():
    return os.path.join(config.config_dir(), "runners")


def _digest(path):
    return hashlib.sha256(pathutil.norm_key(path).encode("utf-8")).hexdigest()[:10]


def runner_dir(path, root=None):
    return os.path.join(root or runners_root(), f"{pathutil.safe_stem(path)}-{_digest(path)}")


def classify(path, cfg=None, root=None):
    """Decide how *path* can be network-blocked."""
    cfg = cfg or {}
    ext = ntpath.splitext(path)[1].lower()
    if ext == ".exe":
        return Plan("exe", "Program")
    if ext in HTML_EXTS:
        return Plan("html", "HTML page")
    if ext in SOURCE_EXTS:
        return Plan("source", "Source code")

    custom = (cfg.get("interpreters") or {}).get(ext, "")
    family = family_for(ext)
    if custom and os.path.isfile(custom):
        interp, env, label = custom, {}, f"{ext} script (custom)"
        args, siblings, pyvenv, verify = (), True, False, ()
    elif family:
        interp, env = _resolve_family(family, path, ext)
        label, args, siblings = family.label, family.args, family.siblings
        pyvenv, verify = family.pyvenv, family.verify
        if not interp:
            return Plan("unsupported", label, needs_interpreter=True,
                        problem=f"No {family.label.split()[0]} interpreter was found on this PC.")
    else:
        what = f"{ext} files" if ext else "Files without an extension"
        return Plan("unsupported", ext or "File", needs_interpreter=bool(ext),
                    problem=f"NetGag doesn't know which program runs {what}.")

    sysroot = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    if os.path.normcase(ntpath.dirname(interp)).startswith(sysroot):
        siblings = False                       # never link half of System32
    return Plan("script", label, interpreter=interp,
                runner=ntpath.join(runner_dir(path, root), ntpath.basename(interp)),
                args=tuple(args), env=env, siblings=siblings, pyvenv=pyvenv, verify=tuple(verify),
                gui=ntpath.basename(interp).lower() in ("pythonw.exe", "wscript.exe"))


# -------------------------------------------------------------------- runners
def _link_or_copy(src, dst):
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def _same_file(a, b):
    try:
        if os.path.samefile(a, b):
            return True
        sa, sb = os.stat(a), os.stat(b)
        return sa.st_size == sb.st_size and int(sa.st_mtime) == int(sb.st_mtime)
    except OSError:
        return False


def _sync(src, dst):
    """Make *dst* a link (or copy) of *src*, replacing an outdated one."""
    if os.path.exists(dst):
        if _same_file(src, dst):
            return
        os.remove(dst)
    _link_or_copy(src, dst)


def ensure_runner(plan, script_path):
    """Create/refresh the private interpreter copy for a script and self-test it."""
    if plan.kind != "script":
        raise RunnerError("This file type does not use a runner.")
    if not os.path.isfile(plan.interpreter):
        raise RunnerError(f"Interpreter not found: {plan.interpreter}")
    folder = ntpath.dirname(plan.runner)
    try:
        os.makedirs(folder, exist_ok=True)
        _sync(plan.interpreter, plan.runner)
        home = ntpath.dirname(plan.interpreter)
        if plan.siblings:
            for dll in glob.glob(os.path.join(home, "*.dll")):
                _sync(dll, os.path.join(folder, os.path.basename(dll)))
        if plan.pyvenv:
            with open(os.path.join(folder, "pyvenv.cfg"), "w", encoding="utf-8") as fh:
                fh.write(f"home = {home}\ninclude-system-site-packages = true\n")
        with open(os.path.join(folder, "runner.json"), "w", encoding="utf-8") as fh:
            json.dump({"file": script_path, "interpreter": plan.interpreter}, fh, indent=2)
    except OSError as exc:
        raise RunnerError(f"Could not prepare the runner: {exc}") from exc

    if plan.verify:
        try:
            proc = subprocess.run([plan.runner, *plan.verify], capture_output=True, text=True,
                                  timeout=30, creationflags=CREATE_NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError(f"The runner copy of {ntpath.basename(plan.interpreter)} "
                              f"could not be started: {exc}") from exc
        if proc.returncode != 0:
            raise RunnerError("The runner copy failed its self-test: "
                              + (proc.stderr or proc.stdout).strip()[:300])
    return plan.runner


def remove_runner(script_path, root=None):
    shutil.rmtree(runner_dir(script_path, root), ignore_errors=True)


def remove_all_runners(root=None):
    shutil.rmtree(root or runners_root(), ignore_errors=True)


def owner_of_program(program, root=None):
    """If *program* is one of our runner copies, return the script it belongs to."""
    root_key = pathutil.norm_key(root or runners_root())
    if not pathutil.norm_key(program).startswith(root_key + "\\"):
        return None
    try:
        with open(os.path.join(ntpath.dirname(program), "runner.json"), "r", encoding="utf-8") as fh:
            owner = json.load(fh).get("file")
    except (OSError, ValueError):
        return None
    return owner if isinstance(owner, str) and owner else None


# ------------------------------------------------------------------ launching
def find_browser():
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local = os.environ.get("LOCALAPPDATA", "")
    for cand in (
        ntpath.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
        ntpath.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
        ntpath.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
        ntpath.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
        ntpath.join(local, "Google", "Chrome", "Application", "chrome.exe"),
    ):
        if os.path.isfile(cand):
            return cand
    return ""


def _q(text):
    """Escape for use inside a double-quoted cmd.exe string."""
    return text.replace("%", "%%")


def write_launcher(path, plan, launcher_dir=None):
    """Write a small .cmd that starts *path* network-blocked. Returns its path."""
    if not os.path.exists(path):
        raise RunnerError("The file no longer exists.")
    base = config.config_dir()
    folder = launcher_dir or os.path.join(base, "launchers")
    os.makedirs(folder, exist_ok=True)
    lines = ["@echo off", f'cd /d "{_q(ntpath.dirname(path))}"']

    if plan.kind == "exe":
        lines.append(f'start "" "{_q(path)}"')
    elif plan.kind == "html":
        browser = find_browser()
        if not browser:
            raise RunnerError("Neither Microsoft Edge nor Google Chrome was found.")
        profile = os.path.join(base, "profiles", _digest(path))
        uri = ntpath.normpath(path)
        uri = "file:///" + uri.replace("\\", "/").replace("%", "%25").replace(" ", "%20").replace("#", "%23")
        lines.append(f'start "" "{_q(browser)}" {" ".join(BROWSER_FLAGS)} '
                     f'--user-data-dir="{_q(profile)}" "{_q(uri)}"')
    elif plan.kind == "script":
        if not os.path.isfile(plan.runner):
            raise RunnerError("The runner does not exist yet - block the file first.")
        for key, value in plan.env.items():
            lines.append(f'set "{key}={_q(value)}"')
        call = f'"{_q(plan.runner)}" ' + "".join(f"{a} " for a in plan.args) + f'"{_q(path)}"'
        if plan.gui:
            lines.append("start \"\" " + call)
        else:
            lines += [call, "if errorlevel 1 pause"]
    else:
        raise RunnerError("This file cannot be launched by NetGag.")

    launcher = os.path.join(folder, f"{pathutil.safe_stem(path)}-{_digest(path)}.cmd")
    with open(launcher, "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return launcher


def launch_unelevated(launcher):
    """Start the launcher through Explorer so it runs WITHOUT NetGag's admin rights."""
    try:
        subprocess.Popen(["explorer.exe", launcher])
    except OSError as exc:
        raise RunnerError(f"Could not start the launcher: {exc}") from exc


# --------------------------------------------------------- fake-offline hook
def hook_supported(plan):
    """True if *plan* is something the native network hook can be applied to.

    HTML pages are excluded: a browser is a multi-process app (renderer/GPU/
    network-service subprocesses), and reliably hooking every one of them is
    out of scope - the browser flags in write_launcher() are the "soft"
    isolation used for HTML instead.
    """
    return plan.kind in ("exe", "script")


def build_command_line(path, plan):
    """The literal command line NetGag would use to start *path*."""
    if plan.kind == "exe":
        return f'"{path}"'
    if plan.kind == "script":
        if not os.path.isfile(plan.runner):
            raise RunnerError("The runner does not exist yet - block the file first.")
        parts = [f'"{plan.runner}"', *plan.args, f'"{path}"']
        return " ".join(parts)
    raise RunnerError("This file type does not support the network-hook launch mode.")


def launch_hooked(path, plan):
    """Start *path* with the native network hook injected, so it BELIEVES it
    has no network rather than merely having its connections blocked.

    Unlike launch_unelevated(), this runs the target WITH NetGag's own (admin)
    rights: the process doing the injecting must hold a handle to the target
    before it resumes, which means NetGag has to start it directly rather
    than handing it to Explorer to de-elevate. Returns the new pid.
    """
    from . import nethook
    if not os.path.exists(path):
        raise RunnerError("The file no longer exists.")
    cmdline = build_command_line(path, plan)
    try:
        pid, handle = nethook.create_suspended_and_inject(
            cmdline, cwd=ntpath.dirname(path), extra_env=plan.env or None)
    except nethook.HookError as exc:
        raise RunnerError(str(exc)) from exc
    import ctypes
    ctypes.windll.kernel32.CloseHandle(handle)
    return pid


def inject_running(pid):
    """Inject the native network hook into an already-running process."""
    from . import nethook
    try:
        nethook.inject(pid)
    except nethook.HookError as exc:
        raise RunnerError(str(exc)) from exc


# -------------------------------------------------------------- source files
_BUILD_SUBDIRS = ("", "bin", "build", "out", "Debug", "Release", "x64\\Debug", "x64\\Release",
                  "bin\\Debug", "bin\\Release", "cmake-build-debug", "cmake-build-release",
                  "target\\debug", "target\\release")


def _search_named(root, name, max_depth):
    name = name.lower()
    root_depth = root.rstrip("\\").count("\\")
    for current, dirs, files in os.walk(root):
        if current.count("\\") - root_depth >= max_depth:
            dirs[:] = []
        for f in files:
            if f.lower() == name:
                yield ntpath.join(current, f)


def find_build_outputs(source_path):
    """Compiled programs that plausibly belong to a source file (same name, near it)."""
    stem = ntpath.splitext(ntpath.basename(source_path))[0]
    name = stem + ".exe"
    folder = ntpath.dirname(source_path)
    bases = [folder, ntpath.dirname(folder), ntpath.dirname(ntpath.dirname(folder))]
    found = {}
    for base in bases:
        if not base or not os.path.isdir(base):
            continue
        for sub in _BUILD_SUBDIRS:
            cand = ntpath.join(base, sub, name)
            if os.path.isfile(cand):
                found.setdefault(pathutil.norm_key(cand), pathutil.norm_path(cand))
        for sub in ("bin", "build", "out", "target"):
            deep = ntpath.join(base, sub)
            if os.path.isdir(deep):
                for cand in _search_named(deep, name, 4):
                    found.setdefault(pathutil.norm_key(cand), pathutil.norm_path(cand))
    return list(found.values())
