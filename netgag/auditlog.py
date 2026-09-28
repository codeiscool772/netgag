"""Optional: surfaces REAL blocked-connection attempts from Windows' own
Security event log (Event ID 5157, Windows Filtering Platform), instead of
just trusting that a firewall rule exists and is enabled.

This requires an audit policy subcategory that is OFF by default. Turning it
on is a genuine, system-wide side effect (every blocked connection on the
whole machine starts getting logged to the Security log, not just NetGag's
own tracked items), so NetGag never enables it silently - the UI asks first
and explains this plainly. Turning it back off is just as explicit.
"""

from . import firewall

_ENABLE_CMD = r"""
$out = & auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable 2>&1
ConvertTo-Json -InputObject @{ ok = ($LASTEXITCODE -eq 0); output = [string]($out -join "`n") } -Compress
"""

_DISABLE_CMD = r"""
$out = & auditpol /set /subcategory:"Filtering Platform Connection" /failure:disable 2>&1
ConvertTo-Json -InputObject @{ ok = ($LASTEXITCODE -eq 0); output = [string]($out -join "`n") } -Compress
"""

_STATUS_CMD = r"""
$out = (& auditpol /get /subcategory:"Filtering Platform Connection" 2>&1) -join "`n"
ConvertTo-Json -InputObject @{ enabled = [bool]($out -match "Failure") } -Compress
"""

_QUERY_CMD = r"""
$payload = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
$wanted = @($payload.paths)
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 500 -ErrorAction SilentlyContinue)
$rows = @(foreach ($e in $events) {
  $xml = [xml]$e.ToXml()
  $data = @{}
  foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
  if ($wanted -contains $data['Application']) {
    [pscustomobject]@{
      time = $e.TimeCreated.ToString('o')
      program = [string]$data['Application']
      destAddress = [string]$data['DestAddress']
      destPort = [string]$data['DestPort']
      protocol = [string]$data['Protocol']
    }
  }
})
ConvertTo-Json -InputObject $rows -Compress
"""


def is_enabled():
    """True if the 'Filtering Platform Connection' failure-audit subcategory is on."""
    data = firewall._json(firewall._run(_STATUS_CMD))
    return bool((data or {}).get("enabled"))


def enable():
    data = firewall._json(firewall._run(_ENABLE_CMD))
    if not (data or {}).get("ok"):
        raise firewall.FirewallError((data or {}).get("output") or "auditpol failed to enable the policy.")


def disable():
    data = firewall._json(firewall._run(_DISABLE_CMD))
    if not (data or {}).get("ok"):
        raise firewall.FirewallError((data or {}).get("output") or "auditpol failed to disable the policy.")


def recent_blocks(paths):
    """Recent Event 5157 rows whose Application matches one of *paths* exactly.

    Returns [] immediately (no PowerShell call) if *paths* is empty. Requires
    is_enabled() to be True to ever find anything - Windows only writes 5157
    once the audit subcategory above is turned on.
    """
    paths = list(paths)
    if not paths:
        return []
    data = firewall._json(firewall._run(_QUERY_CMD, {"paths": paths}))
    return firewall._as_list(data)
