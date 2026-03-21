#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <iostream>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// --- Definitions ---
typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);
typedef int (WSAAPI* connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int (WSAAPI* wsaconnect_t)(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

send_t pOriginalSend = NULL;
recv_t pOriginalRecv = NULL;
connect_t pOriginalConnect = NULL;
wsaconnect_t pOriginalWSAConnect = NULL;

BYTE origSendBytes[5], origRecvBytes[5], origConnectBytes[5], origWSAConnectBytes[5];

// --- Helper Functions ---
void WriteToMemory(void* target, void* data, int len) {
    DWORD old;
    VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, data, len);
    VirtualProtect(target, len, old, &old);
}

void PutHook(void* target, void* hook, BYTE* backup) {
    if (!target) return;
    if (backup) memcpy(backup, target, 5);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)hook - (DWORD)target - 5;
    WriteToMemory(target, jmp, 5);
}

void RemoveHook(void* target, BYTE* backup) {
    if (!target || !backup) return;
    WriteToMemory(target, backup, 5);
}

// --- Debug Output ---
void DebugPrint(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    std::cout << "[Proxy-Debug] " << buf << std::endl;
}

// --- Redirect Logic ---
void RedirectIfGamePort(const struct sockaddr* name, const char* funcName) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    unsigned short port = ntohs(addr->sin_port);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);

    if (port >= 5000 && port <= 30000) {
        DebugPrint("%s: Redirecting %s:%d -> 127.0.0.1:6991", funcName, ip, port);
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6991);
    } else {
        DebugPrint("%s: Ignoring %s:%d (Not a game port)", funcName, ip, port);
    }
}

// --- Hook Functions ---
int WSAAPI MyConnectHook(SOCKET s, const struct sockaddr* name, int namelen) {
    RedirectIfGamePort(name, "connect");
    RemoveHook(pOriginalConnect, origConnectBytes);
    int res = pOriginalConnect(s, name, namelen);
    PutHook(pOriginalConnect, (void*)MyConnectHook, NULL);
    return res;
}

int WSAAPI MyWSAConnectHook(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    RedirectIfGamePort(name, "WSAConnect");
    RemoveHook(pOriginalWSAConnect, origWSAConnectBytes);
    int res = pOriginalWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    PutHook(pOriginalWSAConnect, (void*)MyWSAConnectHook, NULL);
    return res;
}

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    if (len == 269) DebugPrint("Send: Bypassing Gepard (269 bytes)");
    RemoveHook(pOriginalSend, origSendBytes);
    int res = pOriginalSend(s, buf, len, flags);
    PutHook(pOriginalSend, (void*)MySendHook, NULL);
    return res;
}

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {
    RemoveHook(pOriginalRecv, origRecvBytes);
    int res = pOriginalRecv(s, buf, len, flags);
    PutHook(pOriginalRecv, (void*)MyRecvHook, NULL);
    if (res == 2760) DebugPrint("Recv: Bypassing Gepard (2760 bytes)");
    return res;
}

void StartHooking() {
    // สร้าง Console สำหรับ Debug
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    DebugPrint("Hooking System Started...");

    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");
    pOriginalConnect = (connect_t)GetProcAddress(hWs2, "connect");
    pOriginalWSAConnect = (wsaconnect_t)GetProcAddress(hWs2, "WSAConnect");

    PutHook(pOriginalSend, (void*)MySendHook, origSendBytes);
    PutHook(pOriginalRecv, (void*)MyRecvHook, origRecvBytes);
    PutHook(pOriginalConnect, (void*)MyConnectHook, origConnectBytes);
    PutHook(pOriginalWSAConnect, (void*)MyWSAConnectHook, origWSAConnectBytes);
    
    DebugPrint("All Hooks Installed Successfully!");
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartHooking, NULL, 0, NULL);
    }
    return TRUE;
}
