# Rebuilds the native fake-offline hook DLL and its two helper native
# binaries with MinGW-w64 GCC (installed via `scoop install gcc`), then
# copies everything PyInstaller needs to bundle into netgag/.
#
# Usage:  powershell -ExecutionPolicy Bypass -File native\build.ps1

$ErrorActionPreference = "Stop"
$gcc = "$env:USERPROFILE\scoop\apps\gcc\current\bin\gcc.exe"
if (-not (Test-Path $gcc)) {
    $found = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($found) { $gcc = $found.Source }
    else { throw "gcc.exe not found. Install with: scoop install gcc" }
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here
try {
    Write-Host "Building hooknet64.dll ..."
    & $gcc -shared -O2 -municode -Wall -o hooknet64.dll hookdll.c -lws2_32 -liphlpapi -lwininet -luser32
    if ($LASTEXITCODE -ne 0) { throw "hooknet64.dll build failed" }

    Write-Host "Building nettest.exe (test harness for tests\smoke_nethook.py and the in-app self-test) ..."
    Get-Process nettest -ErrorAction SilentlyContinue | Stop-Process -Force
    & $gcc -O2 -mconsole -o nettest.exe nettest.c -lws2_32 -lwininet
    if ($LASTEXITCODE -ne 0) { throw "nettest.exe build failed" }

    Write-Host "Building ifeo_stub.exe (auto-hook launcher for Image File Execution Options) ..."
    & $gcc -O2 -mwindows -o ifeo_stub.exe ifeo_stub.c
    if ($LASTEXITCODE -ne 0) { throw "ifeo_stub.exe build failed" }

    Copy-Item hooknet64.dll, nettest.exe, ifeo_stub.exe ..\netgag\ -Force
    Write-Host "Done. Copied hooknet64.dll, nettest.exe, ifeo_stub.exe to ..\netgag\"
    Get-Item hooknet64.dll, nettest.exe, ifeo_stub.exe, ..\netgag\hooknet64.dll, ..\netgag\nettest.exe, ..\netgag\ifeo_stub.exe |
        Select-Object Name, Length, LastWriteTime
} finally {
    Pop-Location
}
