"""Windows Firewall access through PowerShell's NetSecurity cmdlets.

Why PowerShell instead of parsing `netsh` output: cmdlet objects are locale
independent (netsh output is translated on non-English Windows), and one
PowerShell process can handle a whole batch of programs instead of spawning
several netsh processes per file.  Data goes in as ASCII-escaped JSON on stdin,
so paths can never break out of the script (no quoting/injection issues).
"""

import base64
import json
import logging
import os
import subprocess

from . import pathutil

log = logging.getLogger(__name__)

CREATE_NO_WINDOW = 0x08000000
BATCH_SIZE = 20
DEFAULT_TIMEOUT = 180

_POWERSHELL = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
)


class FirewallError(RuntimeError):
    """Raised when PowerShell/Windows Firewall could not do what was asked."""


_PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
"""

# Emits one { Rule, Program } object per NetGag_* rule.  The application filter
# of a rule has InstanceID == rule Name, so one bulk call plus a hashtable join
# replaces one filter query per rule.
_LIST_RULES = r"""
function Get-NetGagRules {
  $rules = @(Get-NetFirewallRule -DisplayName 'NetGag_*' -ErrorAction SilentlyContinue)
  if ($rules.Count -eq 0) { return }
  $programs = @{}
  foreach ($f in @($rules | Get-NetFirewallApplicationFilter)) {
    $programs[[string]$f.InstanceID] = [string]$f.Program
  }
  foreach ($r in $rules) {
    [pscustomobject]@{ Rule = $r; Program = [string]$programs[[string]$r.Name] }
  }
}
"""

_BLOCK = _LIST_RULES + r"""
$payload = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
$existing = @(Get-NetGagRules)
$res = @(foreach ($i in @($payload.items)) {
  try {
    foreach ($e in $existing) {
      if ($e.Program -ieq $i.path) { $e.Rule | Remove-NetFirewallRule }
    }
    New-NetFirewallRule -DisplayName $i.outbound -Description $i.path -Group 'NetGag' -Direction Outbound -Action Block -Program $i.path -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName $i.inbound -Description $i.path -Group 'NetGag' -Direction Inbound -Action Block -Program $i.path -Profile Any -Enabled True | Out-Null
    [pscustomobject]@{ path = $i.path; ok = $true; error = '' }
  } catch {
    [pscustomobject]@{ path = $i.path; ok = $false; error = $_.Exception.Message }
  }
})
ConvertTo-Json -InputObject $res -Compress
"""

_UNBLOCK = _LIST_RULES + r"""
$payload = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
$targets = @($payload.paths)
$removed = 0
foreach ($e in @(Get-NetGagRules)) {
  foreach ($t in $targets) {
    if ($e.Program -ieq $t) { $e.Rule | Remove-NetFirewallRule; $removed++; break }
  }
}
ConvertTo-Json -InputObject @{ removed = $removed } -Compress
"""

_QUERY = _LIST_RULES + r"""
$out = @(foreach ($x in @(Get-NetGagRules)) {
  [pscustomobject]@{
    program = $x.Program
    direction = [string]$x.Rule.Direction
    action = [string]$x.Rule.Action
    enabled = [string]$x.Rule.Enabled
  }
})
ConvertTo-Json -InputObject $out -Compress
"""

_PURGE = r"""
$rules = @(Get-NetFirewallRule -DisplayName 'NetGag_*' -ErrorAction SilentlyContinue)
$n = $rules.Count
if ($n -gt 0) { $rules | Remove-NetFirewallRule }
ConvertTo-Json -InputObject @{ removed = $n } -Compress
"""


def _run(script, payload=None, timeout=DEFAULT_TIMEOUT):
    encoded = base64.b64encode((_PRELUDE + script).encode("utf-16-le")).decode("ascii")
    cmd = [_POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-EncodedCommand", encoded]
    # json.dumps escapes every non-ASCII character, so stdin is pure ASCII.
    stdin = json.dumps(payload).encode("ascii") if payload is not None else b""
    try:
        proc = subprocess.run(
            cmd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise FirewallError(f"PowerShell did not finish within {timeout} seconds.") from exc
    except OSError as exc:
        raise FirewallError(f"Could not start PowerShell: {exc}") from exc

    out = proc.stdout.decode("utf-8-sig", "replace").strip()
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        log.error("PowerShell failed (%s): %s", proc.returncode, err)
        raise FirewallError(err or f"PowerShell exited with code {proc.returncode}.")
    return out


def _json(out):
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError as exc:
        raise FirewallError(f"Unexpected PowerShell output: {out[:300]}") from exc


def _as_list(data):
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def block_many(paths, progress=None):
    """Block every path (outbound + inbound, all profiles).

    Returns [(path, ok, error_message)].  One failing item never aborts the rest.
    *progress(done, total)* is called after every batch.
    """
    paths = list(dict.fromkeys(paths))
    results = []
    for start in range(0, len(paths), BATCH_SIZE):
        chunk = paths[start:start + BATCH_SIZE]
        payload = {"items": [
            {"path": p,
             "outbound": pathutil.rule_name(p, "OUT"),
             "inbound": pathutil.rule_name(p, "IN")}
            for p in chunk
        ]}
        try:
            rows = _as_list(_json(_run(_BLOCK, payload)))
        except FirewallError as exc:
            results.extend((p, False, str(exc)) for p in chunk)
        else:
            by_path = {r.get("path"): r for r in rows}
            for p in chunk:
                row = by_path.get(p)
                if row is None:
                    results.append((p, False, "PowerShell returned no result for this item."))
                else:
                    results.append((p, bool(row.get("ok")), row.get("error") or ""))
        if progress:
            progress(min(start + BATCH_SIZE, len(paths)), len(paths))
    return results


def unblock_many(paths):
    """Remove NetGag rules for the given programs. Returns number of rules removed."""
    paths = list(dict.fromkeys(paths))
    if not paths:
        return 0
    data = _json(_run(_UNBLOCK, {"paths": paths}))
    return int((data or {}).get("removed", 0))


def _query_rows():
    return _as_list(_json(_run(_QUERY)))


def query_state():
    """Map norm_key(program) -> set of directions ('Outbound'/'Inbound') that are
    actively blocked by an enabled NetGag rule."""
    state = {}
    for row in _query_rows():
        program = row.get("program") or ""
        if not program or program.lower() == "any":
            continue
        if str(row.get("enabled")).lower() != "true" or str(row.get("action")).lower() != "block":
            continue
        state.setdefault(pathutil.norm_key(program), set()).add(str(row.get("direction")))
    return state


def list_managed_programs():
    """Every program that currently has a NetGag rule (used to restore the list)."""
    seen = {}
    for row in _query_rows():
        program = row.get("program") or ""
        if program and program.lower() != "any":
            seen.setdefault(pathutil.norm_key(program), pathutil.norm_path(program))
    return list(seen.values())


def purge_all():
    """Delete every NetGag_* rule. Returns the number of rules removed."""
    data = _json(_run(_PURGE))
    return int((data or {}).get("removed", 0))


# Public alias so other modules (procs) can run their own read-only PowerShell queries.
run_powershell = _run
