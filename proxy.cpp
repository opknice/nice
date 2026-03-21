#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

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

// Helper สำหรับเขียน Memory แบบปลอดภัย
void WriteToMemory(void* target, void* data, int len) {
    DWORD old;
    VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, data, len);
    VirtualProtect(target, len, old, &old);
}

// --- Hook Connect/WSAConnect Logic ---
void RedirectIfGamePort(const struct sockaddr* name) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    unsigned short port = ntohs(addr->sin_port);
    // ดักเฉพาะพอร์ต Login/Zone ของ RO (ปกติ 6900, 6121 หรือตามเซิร์ฟเวอร์)
    if (port == 6900 || port == 6121) {
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6991);
    }
}

int WSAAPI MyConnectHook(SOCKET s, const struct sockaddr* name, int namelen) {
    RedirectIfGamePort(name);
    WriteToMemory(pOriginalConnect, origConnectBytes, 5);
    int res = pOriginalConnect(s, name, namelen);
    
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyConnectHook - (DWORD)pOriginalConnect - 5;
    WriteToMemory(pOriginalConnect, jmp, 5);
    return res;
}

int WSAAPI MyWSAConnectHook(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    RedirectIfGamePort(name);
    WriteToMemory(pOriginalWSAConnect, origWSAConnectBytes, 5);
    int res = pOriginalWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyWSAConnectHook - (DWORD)pOriginalWSAConnect - 5;
    WriteToMemory(pOriginalWSAConnect, jmp, 5);
    return res;
}

// --- Send Hook: Bypass Gepard 269 bytes ---
int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    if (len == 269) { // Gepard Heartbeat/Verification
        WriteToMemory(pOriginalSend, origSendBytes, 5);
        int res = pOriginalSend(s, buf, len, flags);
        BYTE jmp[5] = { 0xE9 };
        *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
        WriteToMemory(pOriginalSend, jmp, 5);
        return res;
    }
    // ปกติให้ OpenKore จัดการ
    WriteToMemory(pOriginalSend, origSendBytes, 5);
    int res = pOriginalSend(s, buf, len, flags);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    WriteToMemory(pOriginalSend, jmp, 5);
    return res;
}

// --- Recv Hook: Bypass Gepard 2760 bytes ---
int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {
    WriteToMemory(pOriginalRecv, origRecvBytes, 5);
    int res = pOriginalRecv(s, buf, len, flags);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    WriteToMemory(pOriginalRecv, jmp, 5);

    if (res == 2760) return res; // Pass-through Gepard data
    return res;
}

void StartHooking() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");
    pOriginalConnect = (connect_t)GetProcAddress(hWs2, "connect");
    pOriginalWSAConnect = (wsaconnect_t)GetProcAddress(hWs2, "WSAConnect");

    // ติดตั้ง Hook
    auto install = [](void* target, void* hook, BYTE* backup) {
        if (!target) return;
        memcpy(backup, target, 5);
        BYTE jmp[5] = { 0xE9 };
        *(DWORD*)(jmp + 1) = (DWORD)hook - (DWORD)target - 5;
        WriteToMemory(target, jmp, 5);
    };

    install(pOriginalSend, MySendHook, origSendBytes);
    install(pOriginalRecv, MyRecvHook, origRecvBytes);
    install(pOriginalConnect, MyConnectHook, origConnectBytes);
    install(pOriginalWSAConnect, MyWSAConnectHook, origWSAConnectBytes);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartHooking, NULL, 0, NULL);
    }
    return TRUE;
}
