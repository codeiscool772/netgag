/* ifeo_stub.c - installed as the IFEO "Debugger" for one specific program
 * name (see netgag/ifeo.py - it refuses to register this for any name shared
 * by more than one real program, since IFEO keys by file name only).
 *
 * Windows invokes this INSTEAD of the real program, passing the ORIGINAL
 * command line (real exe path + its own args) as our own arguments. We start
 * the real target suspended, inject the network hook DLL, resume it, wait
 * for it to exit, and forward its exit code - so the illusion applies
 * automatically every time the program is started, by any means, without
 * going through NetGag itself.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static LPWSTR SkipFirstToken(LPWSTR cmd) {
    LPWSTR p = cmd;
    if (*p == L'"') {
        p++;
        while (*p && *p != L'"') p++;
        if (*p == L'"') p++;
    } else {
        while (*p && *p != L' ' && *p != L'\t') p++;
    }
    while (*p == L' ' || *p == L'\t') p++;
    return p;
}

static void InjectHook(HANDLE hProcess) {
    WCHAR dllPath[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ProgramData", dllPath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH - 32) return;
    lstrcatW(dllPath, L"\\NetGag\\hooknet64.dll");
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) return;  /* not installed: skip quietly */

    SIZE_T size = (lstrlenW(dllPath) + 1) * sizeof(WCHAR);
    LPVOID remote = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return;
    WriteProcessMemory(hProcess, remote, dllPath, size, NULL);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE loadLib = (LPTHREAD_START_ROUTINE)(void*)GetProcAddress(k32, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLib, remote, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 10000);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;
    LPWSTR full = GetCommandLineW();
    LPWSTR targetCmdLine = SkipFirstToken(full);
    if (!*targetCmdLine) return 1;

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    /* targetCmdLine points inside our OWN process's command-line buffer
     * (owned by us, writable), so CreateProcessW modifying it in place is fine
     * without a separate copy. */
    BOOL ok = CreateProcessW(NULL, targetCmdLine, NULL, NULL, TRUE,
                             CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!ok) return 1;

    InjectHook(pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    return (int)exitCode;
}
