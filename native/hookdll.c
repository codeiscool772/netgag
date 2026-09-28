/* hookdll.c - injected into a target process to make it believe it has no
 * network, instead of merely having its connections refused by a firewall.
 *
 * Technique: classic IAT (Import Address Table) patching, PLUS two "meta"
 * hooks that close the biggest gap in patching alone:
 *
 *   - LoadLibraryA/W/ExA/ExW are hooked so that the instant ANY module is
 *     loaded (not just the ones present at injection time), we patch its
 *     imports too - no more waiting for the next periodic re-scan.
 *   - GetProcAddress is hooked so that code which resolves connect(),
 *     getaddrinfo(), etc. DYNAMICALLY at runtime (instead of importing them
 *     statically, which plain IAT patching alone cannot see) gets handed
 *     our fake versions instead of the real ones.
 *
 * A slower periodic re-scan remains as a safety net for the rare loading
 * path that bypasses kernel32's LoadLibrary wrappers.
 *
 * Also keeps a small activity log (%TEMP%\netgag_hook_debug.log): one line
 * when the DLL attaches, one line per distinct function successfully
 * patched, and a periodic summary of how many times each fake function has
 * actually been CALLED by the target - a real "this app tried to reach the
 * network N times" feed, not just proof the patch was installed.
 *
 * 64-bit only. No exports are required to be called by anything: DllMain
 * does the work as soon as the DLL is loaded via LoadLibrary.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdarg.h>

static HMODULE g_selfModule = NULL;
static volatile LONG g_patchCount = 0;

/* Diagnostic-only: appends to %TEMP%\netgag_hook_debug.log so we can confirm,
 * from outside the target process, that the DLL really loaded and patched
 * something - independent of whatever the target itself observes (which can
 * be confused by an unrelated real firewall block, antivirus, etc). Safe to
 * leave in for now; remove once the mechanism is trusted. */
static void DebugLog(const char *fmt, ...) {
    char path[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("TEMP", path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    strcat(path, "\\netgag_hook_debug.log");
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = wvsprintfA(buf, fmt, args);
    va_end(args);
    DWORD written;
    WriteFile(h, buf, (DWORD)len, &written, NULL);
    CloseHandle(h);
}

typedef void (WSAAPI *WSASetLastError_t)(int);
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
typedef HMODULE (WINAPI *LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);

static WSASetLastError_t pWSASetLastError = NULL;
static LoadLibraryA_t pLoadLibraryA = NULL;
static LoadLibraryW_t pLoadLibraryW = NULL;
static LoadLibraryExA_t pLoadLibraryExA = NULL;
static LoadLibraryExW_t pLoadLibraryExW = NULL;
static GetProcAddress_t pGetProcAddress = NULL;

/* -------------------------------------------------- per-function call counts
 * (the "activity feed" - how many times the target actually tried each one,
 * not just whether we patched it). */
static volatile LONG g_calls_connect = 0;
static volatile LONG g_calls_WSAConnect = 0;
static volatile LONG g_calls_getaddrinfo = 0;
static volatile LONG g_calls_GetAddrInfoW = 0;
static volatile LONG g_calls_InternetGetConnectedState = 0;
static volatile LONG g_calls_InternetCheckConnectionA = 0;
static volatile LONG g_calls_InternetCheckConnectionW = 0;
static volatile LONG g_calls_GetAdaptersAddresses = 0;
static volatile LONG g_calls_GetAdaptersInfo = 0;
static volatile LONG g_calls_GetProcAddress_intercepted = 0;

/* Forward declarations - the meta hooks below need these before their real
 * definitions (which come after the hook table, since Hook_GetProcAddress's
 * definition needs the table itself). */
static void PatchModuleImportsFwd(HMODULE hMod);
static FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

/* ---------------------------------------------------------------- hooks */

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr *name, int namelen) {
    (void)s; (void)name; (void)namelen;
    InterlockedIncrement(&g_calls_connect);
    if (pWSASetLastError) pWSASetLastError(WSAENETUNREACH);
    return SOCKET_ERROR;
}

static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen,
                                   LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                                   LPQOS lpSQOS, LPQOS lpGQOS) {
    (void)s; (void)name; (void)namelen; (void)lpCallerData; (void)lpCalleeData;
    (void)lpSQOS; (void)lpGQOS;
    InterlockedIncrement(&g_calls_WSAConnect);
    if (pWSASetLastError) pWSASetLastError(WSAENETUNREACH);
    return SOCKET_ERROR;
}

static int WSAAPI Hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName,
                                    const ADDRINFOA *pHints, PADDRINFOA *ppResult) {
    (void)pNodeName; (void)pServiceName; (void)pHints;
    InterlockedIncrement(&g_calls_getaddrinfo);
    if (ppResult) *ppResult = NULL;
    return WSAHOST_NOT_FOUND;
}

static INT WSAAPI Hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
                                     const ADDRINFOW *pHints, PADDRINFOW *ppResult) {
    (void)pNodeName; (void)pServiceName; (void)pHints;
    InterlockedIncrement(&g_calls_GetAddrInfoW);
    if (ppResult) *ppResult = NULL;
    return WSAHOST_NOT_FOUND;
}

static BOOL WINAPI Hook_InternetGetConnectedState(LPDWORD lpdwFlags, DWORD dwReserved) {
    (void)dwReserved;
    InterlockedIncrement(&g_calls_InternetGetConnectedState);
    if (lpdwFlags) *lpdwFlags = 0;
    return FALSE;
}

static BOOL WINAPI Hook_InternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags, DWORD_PTR dwReserved) {
    (void)lpszUrl; (void)dwFlags; (void)dwReserved;
    InterlockedIncrement(&g_calls_InternetCheckConnectionA);
    return FALSE;
}

static BOOL WINAPI Hook_InternetCheckConnectionW(LPCWSTR lpszUrl, DWORD dwFlags, DWORD_PTR dwReserved) {
    (void)lpszUrl; (void)dwFlags; (void)dwReserved;
    InterlockedIncrement(&g_calls_InternetCheckConnectionW);
    return FALSE;
}

static ULONG WINAPI Hook_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved,
                                               PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer) {
    (void)Family; (void)Flags; (void)Reserved; (void)AdapterAddresses;
    InterlockedIncrement(&g_calls_GetAdaptersAddresses);
    if (SizePointer) *SizePointer = 0;
    return ERROR_NO_DATA;
}

static DWORD WINAPI Hook_GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer) {
    (void)AdapterInfo;
    InterlockedIncrement(&g_calls_GetAdaptersInfo);
    if (SizePointer) *SizePointer = 0;
    return ERROR_NO_DATA;
}

/* ---------------------------------------------------------- meta hooks */

static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR lpLibFileName) {
    HMODULE h = pLoadLibraryA ? pLoadLibraryA(lpLibFileName) : NULL;
    if (h) PatchModuleImportsFwd(h);
    return h;
}
static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR lpLibFileName) {
    HMODULE h = pLoadLibraryW ? pLoadLibraryW(lpLibFileName) : NULL;
    if (h) PatchModuleImportsFwd(h);
    return h;
}
static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE h = pLoadLibraryExA ? pLoadLibraryExA(lpLibFileName, hFile, dwFlags) : NULL;
    if (h) PatchModuleImportsFwd(h);
    return h;
}
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE h = pLoadLibraryExW ? pLoadLibraryExW(lpLibFileName, hFile, dwFlags) : NULL;
    if (h) PatchModuleImportsFwd(h);
    return h;
}

/* --------------------------------------------------------------- table */

typedef struct { const char *dll; const char *func; void *hook; } HookEntry;

static const HookEntry g_hooks[] = {
    {"ws2_32.dll",   "connect",                    (void*)Hook_connect},
    {"ws2_32.dll",   "WSAConnect",                 (void*)Hook_WSAConnect},
    {"ws2_32.dll",   "getaddrinfo",                (void*)Hook_getaddrinfo},
    {"ws2_32.dll",   "GetAddrInfoW",               (void*)Hook_GetAddrInfoW},
    {"wininet.dll",  "InternetGetConnectedState",  (void*)Hook_InternetGetConnectedState},
    {"wininet.dll",  "InternetCheckConnectionA",   (void*)Hook_InternetCheckConnectionA},
    {"wininet.dll",  "InternetCheckConnectionW",   (void*)Hook_InternetCheckConnectionW},
    {"iphlpapi.dll", "GetAdaptersAddresses",       (void*)Hook_GetAdaptersAddresses},
    {"iphlpapi.dll", "GetAdaptersInfo",            (void*)Hook_GetAdaptersInfo},
    /* Meta hooks: patched into every module that resolves things via kernel32,
     * i.e. almost everything. Each of these forwards to the REAL kernel32
     * implementation (resolved once, before any patching, via our own
     * never-patched IAT) and additionally does our own bookkeeping. */
    {"kernel32.dll", "LoadLibraryA",               (void*)Hook_LoadLibraryA},
    {"kernel32.dll", "LoadLibraryW",               (void*)Hook_LoadLibraryW},
    {"kernel32.dll", "LoadLibraryExA",             (void*)Hook_LoadLibraryExA},
    {"kernel32.dll", "LoadLibraryExW",             (void*)Hook_LoadLibraryExW},
    {"kernel32.dll", "GetProcAddress",             (void*)Hook_GetProcAddress},
};
#define HOOK_COUNT (sizeof(g_hooks) / sizeof(g_hooks[0]))
/* Only the first 9 entries are real network functions with a hook the target
 * itself notices; the rest are our own plumbing. Used for the activity-count
 * summary and for query_state-style reporting. */
#define REAL_HOOK_COUNT 9

static FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    /* High word of an ordinal-style "name" is always zero; a real string
     * pointer never looks like that (it's a valid, much larger address). */
    if (((ULONG_PTR)lpProcName >> 16) != 0) {
        for (size_t h = 0; h < REAL_HOOK_COUNT; h++) {
            HMODULE dll = GetModuleHandleA(g_hooks[h].dll);
            if (dll && dll == hModule && strcmp(lpProcName, g_hooks[h].func) == 0) {
                InterlockedIncrement(&g_calls_GetProcAddress_intercepted);
                DebugLog("[pid %lu] GetProcAddress(\"%s\") intercepted - handed the fake version\r\n",
                        GetCurrentProcessId(), g_hooks[h].func);
                return (FARPROC)g_hooks[h].hook;
            }
        }
    }
    return pGetProcAddress ? pGetProcAddress(hModule, lpProcName) : NULL;
}

/* -------------------------------------------------------- IAT patching */

static void PatchModuleImports(HMODULE hMod) {
    BYTE *base = (BYTE*)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;  /* 32-bit module: skip */

    IMAGE_DATA_DIRECTORY impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0) return;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir.VirtualAddress);
    for (; imp->Name != 0; imp++) {
        const char *dllName = (const char*)(base + imp->Name);
        for (size_t h = 0; h < HOOK_COUNT; h++) {
            if (_stricmp(dllName, g_hooks[h].dll) != 0) continue;

            ULONG_PTR origThunkRVA = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            IMAGE_THUNK_DATA64 *origThunk = (IMAGE_THUNK_DATA64*)(base + origThunkRVA);
            IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64*)(base + imp->FirstThunk);

            for (int i = 0; origThunk[i].u1.AddressOfData != 0; i++) {
                if (origThunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;  /* import-by-ordinal: skip */
                IMAGE_IMPORT_BY_NAME *byName =
                    (IMAGE_IMPORT_BY_NAME*)(base + origThunk[i].u1.AddressOfData);
                if (strcmp((const char*)byName->Name, g_hooks[h].func) != 0) continue;
                if (iat[i].u1.Function == (ULONGLONG)g_hooks[h].hook) continue;  /* already patched */

                DWORD oldProtect;
                if (VirtualProtect(&iat[i], sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect)) {
                    iat[i].u1.Function = (ULONGLONG)g_hooks[h].hook;
                    VirtualProtect(&iat[i], sizeof(ULONG_PTR), oldProtect, &oldProtect);
                    InterlockedIncrement(&g_patchCount);
                    if (h < REAL_HOOK_COUNT) {
                        DebugLog("[pid %lu] patched %s!%s\r\n",
                                GetCurrentProcessId(), g_hooks[h].dll, g_hooks[h].func);
                    }
                }
            }
        }
    }
}

static void PatchModuleImportsFwd(HMODULE hMod) { PatchModuleImports(hMod); }

static void ScanAndPatchAll(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    if (Module32First(hSnap, &me)) {
        do {
            if ((HMODULE)me.hModule == g_selfModule) continue;
            PatchModuleImports((HMODULE)me.hModule);
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
}

static void ResolveRealPointers(void) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (k32) {
        pLoadLibraryA = (LoadLibraryA_t)GetProcAddress(k32, "LoadLibraryA");
        pLoadLibraryW = (LoadLibraryW_t)GetProcAddress(k32, "LoadLibraryW");
        pLoadLibraryExA = (LoadLibraryExA_t)GetProcAddress(k32, "LoadLibraryExA");
        pLoadLibraryExW = (LoadLibraryExW_t)GetProcAddress(k32, "LoadLibraryExW");
        pGetProcAddress = (GetProcAddress_t)GetProcAddress(k32, "GetProcAddress");
    }
    HMODULE hWs2 = LoadLibraryA("ws2_32.dll");
    if (hWs2) pWSASetLastError = (WSASetLastError_t)GetProcAddress(hWs2, "WSASetLastError");
}

static void LogActivitySummaryIfChanged(void) {
    static LONG last[REAL_HOOK_COUNT] = {0};
    LONG cur[REAL_HOOK_COUNT] = {
        g_calls_connect, g_calls_WSAConnect, g_calls_getaddrinfo, g_calls_GetAddrInfoW,
        g_calls_InternetGetConnectedState, g_calls_InternetCheckConnectionA,
        g_calls_InternetCheckConnectionW, g_calls_GetAdaptersAddresses, g_calls_GetAdaptersInfo,
    };
    int changed = 0;
    for (int i = 0; i < REAL_HOOK_COUNT; i++) if (cur[i] != last[i]) changed = 1;
    if (!changed) return;
    DebugLog("[pid %lu] blocked-call counts: connect=%ld WSAConnect=%ld getaddrinfo=%ld "
            "GetAddrInfoW=%ld InternetGetConnectedState=%ld InternetCheckConnectionA=%ld "
            "InternetCheckConnectionW=%ld GetAdaptersAddresses=%ld GetAdaptersInfo=%ld "
            "GetProcAddress_intercepted=%ld\r\n",
            GetCurrentProcessId(), cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7], cur[8],
            g_calls_GetProcAddress_intercepted);
    for (int i = 0; i < REAL_HOOK_COUNT; i++) last[i] = cur[i];
}

static DWORD WINAPI WorkerThread(LPVOID param) {
    (void)param;
    DebugLog("[pid %lu] hooknet64.dll worker thread started\r\n", GetCurrentProcessId());
    ResolveRealPointers();
    DebugLog("[pid %lu] WSASetLastError resolved: %s\r\n",
            GetCurrentProcessId(), pWSASetLastError ? "yes" : "no");

    /* Fast initial passes: catches modules that finish loading shortly after
     * injection (this is what covers the CREATE_SUSPENDED race, before the
     * LoadLibrary hook itself is even in place to catch things reactively). */
    for (int i = 0; i < 30; i++) {
        ScanAndPatchAll();
        Sleep(100);
    }
    DebugLog("[pid %lu] fast scan phase done, total patches so far: %ld\r\n",
            GetCurrentProcessId(), g_patchCount);
    /* Slow ongoing passes for the life of the process: a safety net for any
     * loading path that bypasses the LoadLibrary hook above (rare - most
     * userland module loads go through it). Also emits the activity summary. */
    for (;;) {
        ScanAndPatchAll();
        LogActivitySummaryIfChanged();
        Sleep(5000);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)lpReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_selfModule = hinstDLL;
        DebugLog("[pid %lu] hooknet64.dll DllMain DLL_PROCESS_ATTACH\r\n", GetCurrentProcessId());
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE h = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}

/* Exported so the DLL has a proper export table (purely cosmetic - LoadLibrary
 * runs DllMain regardless of exports - and gives the injector something to
 * sanity-check the right module loaded). */
__declspec(dllexport) void NetGagHookMarker(void) {}
