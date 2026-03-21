#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);
typedef int (WSAAPI* connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int (WSAAPI* wsaconnect_t)(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

send_t pOriginalSend = NULL;
recv_t pOriginalRecv = NULL;
connect_t pOriginalConnect = NULL;
wsaconnect_t pOriginalWSAConnect = NULL;

BYTE origSendBytes[5], origRecvBytes[5], origConnectBytes[5], origWSAConnectBytes[5];

void WriteLog(const char* type, const char* buf, int len) {
    FILE* f;
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_analysis.log", "a") == 0) {
        time_t now = time(0);
        struct tm ltm;
        localtime_s(&ltm, &now);
        unsigned short opcode = (len >= 2) ? *(unsigned short*)(buf) : 0; 
        fprintf(f, "[%02d:%02d:%02d] [%s] ID: %04X | Len: %d\n", ltm.tm_hour, ltm.tm_min, ltm.tm_sec, type, opcode, len);
        fclose(f);
    }
}

// ฟังก์ชันช่วยติดตั้ง Hook แบบปลอดภัย
void PutHook(void* target, void* hook, BYTE* backup) {
    DWORD old;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old);
    if (backup) memcpy(backup, target, 5);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)hook - (DWORD)target - 5;
    memcpy(target, jmp, 5);
    VirtualProtect(target, 5, old, &old);
}

void RemoveHook(void* target, BYTE* backup) {
    DWORD old;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, backup, 5);
    VirtualProtect(target, 5, old, &old);
}

// --- Hooks ---
int WSAAPI MyConnectHook(SOCKET s, const struct sockaddr* name, int namelen) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    if (ntohs(addr->sin_port) == 6900 || ntohs(addr->sin_port) == 6121) {
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6991);
    }
    RemoveHook(pOriginalConnect, origConnectBytes);
    int res = pOriginalConnect(s, (const struct sockaddr*)addr, namelen);
    PutHook(pOriginalConnect, MyConnectHook, NULL);
    return res;
}

int WSAAPI MyWSAConnectHook(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    if (ntohs(addr->sin_port) == 6900 || ntohs(addr->sin_port) == 6121) {
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6991);
    }
    RemoveHook(pOriginalWSAConnect, origWSAConnectBytes);
    int res = pOriginalWSAConnect(s, (const struct sockaddr*)addr, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    PutHook(pOriginalWSAConnect, MyWSAConnectHook, NULL);
    return res;
}

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    if (len == 269) { // Bypass Gepard
        RemoveHook(pOriginalSend, origSendBytes);
        int res = pOriginalSend(s, buf, len, flags);
        PutHook(pOriginalSend, MySendHook, NULL);
        return res;
    }
    WriteLog("C->S", buf, len);
    RemoveHook(pOriginalSend, origSendBytes);
    int res = pOriginalSend(s, buf, len, flags);
    PutHook(pOriginalSend, MySendHook, NULL);
    return res;
}

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {
    RemoveHook(pOriginalRecv, origRecvBytes);
    int res = pOriginalRecv(s, buf, len, flags);
    PutHook(pOriginalRecv, MyRecvHook, NULL);
    if (res > 0) {
        if (res == 2760) return res; // Bypass Gepard
        WriteLog("S->C", buf, res);
    }
    return res;
}

void StartHooking() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");
    pOriginalConnect = (connect_t)GetProcAddress(hWs2, "connect");
    pOriginalWSAConnect = (wsaconnect_t)GetProcAddress(hWs2, "WSAConnect");

    PutHook(pOriginalSend, MySendHook, origSendBytes);
    PutHook(pOriginalRecv, MyRecvHook, origRecvBytes);
    PutHook(pOriginalConnect, MyConnectHook, origConnectBytes);
    PutHook(pOriginalWSAConnect, MyWSAConnectHook, origWSAConnectBytes);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0);
    return TRUE;
}
