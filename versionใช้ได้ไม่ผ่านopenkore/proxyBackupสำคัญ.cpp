#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

// --- Definitions ---
typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);

send_t pOriginalSend = NULL;
recv_t pOriginalRecv = NULL;
BYTE origSendBytes[5], origRecvBytes[5];

// --- Helper: แปลง OpCode เป็นข้อความ ---
const char* GetOpName(unsigned short opcode) {
    switch (opcode) {
        case 0x0078: return "WALK";
        case 0x008D: return "ATTACK";
        case 0x0093: return "USE_SKILL";
        case 0x0064: return "CHAT_SEND";
        case 0x0080: return "ITEM_PICKUP";
        case 0x00A7: return "ITEM_USE";
        default: return "UNKNOWN";
    }
}

// --- Logger Function ---
void WriteLog(const char* type, const char* buf, int len) {
    FILE* f;
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_analysis.log", "a") == 0) {
        time_t now = time(0);
        struct tm ltm;
        localtime_s(&ltm, &now);

        // ดึง OpCode (2 bytes แรกหลังจาก Length หรือตามโครงสร้าง RO)
        // ปกติ RO: [OpCode 2 bytes][Data...] หรือ [Len 2 bytes][OpCode 2 bytes]
        unsigned short opcode = *(unsigned short*)(buf); 
        
        fprintf(f, "[%02d:%02d:%02d] [%s] ID: %04X (%s) | Len: %d | Hex: ", 
                ltm.tm_hour, ltm.tm_min, ltm.tm_sec, type, opcode, GetOpName(opcode), len);
        
        for (int i = 0; i < len; i++) fprintf(f, "%02X ", (unsigned char)buf[i]);
        fprintf(f, "\n");
        fclose(f);
    }
}

// --- Hooks ---
int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    WriteLog("C->S", buf, len);
    // Trampoline logic (Inline Hook)
    DWORD old;
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalSend, origSendBytes, 5);
    int res = pOriginalSend(s, buf, len, flags);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmp, 5);
    VirtualProtect(pOriginalSend, 5, old, &old);
    return res;
}

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {
    int res = 0;
    // เรียกของจริงก่อนเพื่อให้ได้ Data มาใน buf
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5);
    res = pOriginalRecv(s, buf, len, flags);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res > 0) WriteLog("S->C", buf, res);
    return res;
}

// --- Injection Setup ---
void StartHooking() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");

    DWORD old;
    // Hook Send
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(origSendBytes, pOriginalSend, 5);
    BYTE jmpS[5] = { 0xE9 };
    *(DWORD*)(jmpS + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmpS, 5);

    // Hook Recv
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(origRecvBytes, pOriginalRecv, 5);
    BYTE jmpR[5] = { 0xE9 };
    *(DWORD*)(jmpR + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmpR, 5);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0);
    return TRUE;
}