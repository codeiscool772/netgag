## NetGag

Per-file network isolator for Windows. Pick programs, scripts or whole folders and NetGag
cuts their network access - either with Windows Firewall rules, or, for the real "the app
believes it's offline" effect, by injecting a native hook into the process. It can also
verify its own work, watch folders reactively instead of polling, surface real blocked
attempts from Windows' own logs, and optionally apply the fake-offline hook automatically
to a specific program every time it starts, from anywhere.

## Run / build

```powershell
python main.py                       # asks for Administrator rights (UAC)
pip install -r requirements-dev.txt
pyinstaller Netgag.spec              # -> dist\Netgag.exe (manifest requests admin)
```

Runtime is pure standard library - no third-party packages needed. The native pieces ship
prebuilt in `netgag\` (`hooknet64.dll`, `nettest.exe`, `ifeo_stub.exe`); you only need to
rebuild them if you change something under `native\` (see "Rebuilding the native components").

## Two ways to cut a program off

| | Firewall block (`Block Selected`) | Fake offline (`Run Offline`, `Fake Offline Now`) |
| --- | --- | --- |
| How | Windows Firewall rules (outbound + inbound, all profiles) | Injects `hooknet64.dll` into the process, patching its Import Address Table AND hooking `GetProcAddress`/`LoadLibrary*` so `connect`, `WSAConnect`, `getaddrinfo`, `GetAddrInfoW`, `InternetGetConnectedState`, `InternetCheckConnectionA/W`, `GetAdaptersAddresses` and `GetAdaptersInfo` all report "no network" - whether the target imports them statically, resolves them dynamically via `GetProcAddress`, or loads the module they live in only after the hook is already attached |
| What the app sees | A failed/refused connection | The same thing it would see if the machine were genuinely offline |
| Persists across restarts of the app | Yes - it's a firewall rule | No, unless paired with **Auto-Hook** (see below) |
| Runs the target... | however you started it | with NetGag's own admin rights (injection requires holding a handle to the target before it resumes - unlike `Run Blocked`, which starts things unelevated through Explorer) |
| Works on | anything the firewall can name a program for | 64-bit `.exe` and script processes only (not HTML - see below) |
| Status | solid, exercised by `tests/smoke_multitype.py` | mechanism proven end-to-end (`tests/smoke_nethook.py`), including the `GetProcAddress`/`LoadLibrary` hooks via the in-app self-test |

They compose: block a script first (creates its isolated runner), then use **Run Offline**
to launch it with both layers active - the firewall as a hard backstop, the hook for the
believable "offline" experience.

## Verifying it actually worked

- **Automatic, per launch:** every `Run Offline` / `Fake Offline Now` reads the hook's own
  activity log right after injecting and reports how many of the real network functions
  were confirmed patched in that specific process - not just that injection didn't raise.
- **Tools -> View Hook Activity Log:** per item you've started this session, which functions
  are patched and how many times it has actually *tried* to reach the network so far.
- **Tools -> Blocked-Connection Log (Security Audit):** opt-in - surfaces real Windows
  Event ID 5157 ("Windows Filtering Platform blocked a connection") entries for your
  firewall-blocked items, so you can see Windows actually catch something, not just that a
  rule exists. Turning the underlying audit policy on is a genuine system-wide change
  (every blocked connection on the machine gets logged, not just NetGag's), so the UI always
  asks first.
- **Tools -> Test NetGag's Blocking Mechanism:** runs the bundled `nettest.exe` through both
  mechanisms right now and reports pass/fail for each - the same proof `tests/smoke_multitype.py`
  and `tests/smoke_nethook.py` give a developer, packaged for a shipped install.

## Auto-Hook on every launch (Tools -> Auto-Hook, advanced)

Registers NetGag's stub as the target's Image File Execution Options `Debugger`, so Windows
runs the stub instead of the real program for **every** launch, by any means (double-click, a
shortcut, another program launching it) - not only when started through NetGag. The stub then
starts the real program suspended, injects the hook, resumes it, and forwards its exit code.

**This is filename-only, system-wide, and NetGag refuses to enable it for anything generic:**
IFEO keys by file name, not by folder or full path. Enabling it for `MyGame.exe` affects every
process anywhere on the machine literally named `MyGame.exe`. For a name shared by many
unrelated programs - any interpreter, shell, browser, or core Windows component - this would
hijack all of them, the opposite of NetGag's per-file precision everywhere else. `netgag/ifeo.py`
refuses these names outright (no override), on top of the same protected-process list used
everywhere else in the app.

## What it can target

| File type | How |
| --- | --- |
| `.exe` | Blocked/hooked directly by path. |
| `.py` `.pyw` `.js` `.mjs` `.cjs` `.bat` `.cmd` `.vbs` `.vbe` | NetGag gives the file its own private copy ("runner") of the interpreter - a hardlink, so no extra disk space - and blocks/hooks *that* copy. Only this one script loses network access, not every script that shares the interpreter. Any other extension can be pointed at a custom interpreter via **Tools -> Custom Interpreters**. |
| `.html` `.htm` `.xhtml` `.mhtml` | Neither a firewall rule nor the hook can target one browser tab (a browser is many cooperating processes). **Run Blocked** instead opens the page in an isolated browser profile with networking disabled at launch. Not supported by **Run Offline** / **Fake Offline Now** / Auto-Hook. |
| `.c` `.cpp` `.rs` `.go` `.cs` ... | Source code doesn't run by itself. Adding a source file makes NetGag look for its compiled `.exe` nearby (`bin/`, `build/`, `Debug/`, etc.) and add that instead. |

## Layout

| Path | Purpose |
| --- | --- |
| `main.py` | Entry point: elevation, logging, starts the GUI (also has a hidden `NETGAG_SELFTEST_NETHOOK=1` env-var diagnostic) |
| `netgag/ui.py` | Tk window, background-task runner, list management, folder-watch wiring |
| `netgag/handlers.py` | Classifies files, builds/tests interpreter runners, writes launch scripts, drives the fake-offline launch/injection |
| `netgag/nethook.py` | Injector for `hooknet64.dll` - `CreateRemoteThread` + `LoadLibraryW`, or suspended-then-inject for a fresh launch |
| `netgag/hooklog.py` | Parses the hook DLL's own activity log for real verification (not a guess) |
| `netgag/selftest.py` | In-app pass/fail proof of both mechanisms, using the bundled `nettest.exe` |
| `netgag/auditlog.py` | Opt-in reader for real Windows Filtering Platform blocked-connection events |
| `netgag/ifeo.py` | Auto-Hook registration via Image File Execution Options, with the generic-name refusal list |
| `netgag/folderwatch.py` | Reactive folder watching via `FindFirstChangeNotificationW` (no polling) |
| `netgag/firewall.py` | Windows Firewall via PowerShell NetSecurity cmdlets (batched, locale independent) |
| `netgag/procs.py` | Process listing/termination via the Win32 API, plus finding running script instances |
| `netgag/pathutil.py` | Path normalisation, rule names, protected-process list, file scanning |
| `netgag/config.py` | Settings in `%APPDATA%\NetGag\config.json` |
| `native/hookdll.c` | Source for the hook DLL - IAT patching, `GetProcAddress`/`LoadLibrary*` meta-hooks, activity log |
| `native/nettest.c` | Tiny real test target used by the self-test and the smoke tests - not a NetGag feature |
| `native/ifeo_stub.c` | The IFEO "Debugger" stub - forwards the real command line, injects, resumes, forwards the exit code |
| `native/build.ps1` | Rebuilds all three native binaries with MinGW-w64 GCC, copies them into `netgag\` |
| `tests/test_core.py` | `python -m unittest discover -s tests -t .` (no admin rights needed) |
| `tests/smoke_live.py` | Read-only live checks (GUI, process listing) - `python -m tests.smoke_live` |
| `tests/smoke_folderwatch.py` | Confirms reactive folder watching fires (and stops) correctly - no admin needed |
| `tests/smoke_multitype.py` | Live block/unblock of a real script runner - run **elevated** |
| `tests/smoke_nethook.py` | Proves the fake-offline hook against `native\nettest.exe` - run **elevated** |
| `backup/main_v1.py` | The original single-file version |

## Rebuilding the native components

Needs MinGW-w64 GCC (`scoop install gcc`):

```powershell
powershell -ExecutionPolicy Bypass -File native\build.ps1
```

Then rebuild `dist\Netgag.exe` with `pyinstaller Netgag.spec` so the new binaries get bundled.

`hookdll.c` writes a small activity log to `%TEMP%\netgag_hook_debug.log`: one line when it
attaches to a process, one line per distinct function successfully patched, and a periodic
summary of how many times each fake function has actually been called. This is what powers
the Activity Log view and the automatic per-launch verification, and is also what proved
during development that an apparent hook failure was actually a stale firewall rule and an
unrelated port-53 heuristic, not a bug in the hook itself. Harmless to delete any time.

## Behaviour notes

* Firewall rules are named `NetGag_*` and live in the firewall group `NetGag`. They persist
  across restarts; on startup NetGag re-imports existing rules (including script runners,
  matched back to their original script) into the list.
* Removing an item from the list also unblocks it and deletes its runner copy, if any.
* **Add Folder** lets you choose which file types to include and whether to keep watching
  the folder for new matching files - reactive (milliseconds) via `FindFirstChangeNotificationW`,
  with a 5-minute safety-net sweep in case a change notification is ever missed. Items you
  remove aren't re-added.
* Core Windows components (`svchost.exe`, `lsass.exe`, `explorer.exe`, ...) can never be added,
  blocked, terminated, hooked, or auto-hooked.
* Script support (firewall-runner, hook, and Auto-Hook) is tested for Python; Node.js, batch
  and VBScript share the same mechanism but haven't each been individually exercised the same
  way. A venv/virtualenv `python.exe` is automatically unwrapped to the real interpreter it
  launches, since blocking/hooking the venv shim alone would affect nothing.
* The hook re-scans a process's loaded modules for ~3 seconds after injection (covers the
  `CREATE_SUSPENDED` race before its own `LoadLibrary` hook is even in place), then hooks
  `LoadLibraryA/W/ExA/ExW` so any module loaded afterward is patched the instant it loads,
  with a 5-second periodic sweep remaining as a safety net for any loading path that bypasses
  those.
* Logs: `%APPDATA%\NetGag\netgag.log`.
