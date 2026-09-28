/* nettest.c - tiny target used by tests/smoke_nethook.py to prove the hook
 * DLL genuinely intercepts network calls, rather than trusting it blindly.
 *
 * Prints one line per check as VALUE=... so the test harness can parse it,
 * then blocks on stdin so the test can decide when to let it exit (gives the
 * injector time to attach before anything here runs, and keeps the process
 * alive long enough for a "still running" check).
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Wait for the injector to attach before making any network calls. */
    char line[64];
    fgets(line, sizeof(line), stdin);

    /* connect() to a real public host on port 443 (ordinary HTTPS traffic -
     * unlike port 53, this shouldn't trip any DNS-tunneling-style heuristic
     * in local security software). */
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = inet_addr("1.1.1.1");
    int rc = connect(s, (struct sockaddr*)&addr, sizeof(addr));
    printf("CONNECT_RC=%d ERR=%d\n", rc, rc == SOCKET_ERROR ? WSAGetLastError() : 0);
    closesocket(s);

    /* getaddrinfo() for a real hostname. */
    struct addrinfo *res = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    int gai = getaddrinfo("www.example.com", NULL, &hints, &res);
    printf("GETADDRINFO_RC=%d\n", gai);
    if (res) freeaddrinfo(res);

    /* InternetGetConnectedState(). */
    DWORD flags = 0xFFFFFFFF;
    BOOL online = InternetGetConnectedState(&flags, 0);
    printf("INTERNET_STATE=%d\n", online);

    fflush(stdout);
    fgets(line, sizeof(line), stdin);   /* wait again so the test can check "still running" */
    return 0;
}
