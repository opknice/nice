#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

// --- Function Types ---
typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);

send_t pOriginalSend = NULL;
recv_t pOriginalRecv = NULL;
BYTE origSendBytes[5], origRecvBytes[5];

// --- Live Parser: แปลผล Packet เป็นข้อความ ---
void ParseAndPrint(const char* dir, const char* buf, int len) {
    if (len < 2) return;
    unsigned short opcode = *(unsigned short*)(buf);

    // ตั้งค่าสี Console (เขียว = ส่ง, แดง = รับ)
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (strcmp(dir, "SEND") == 0) SetConsoleTextAttribute(hConsole, 10); // Green
    else SetConsoleTextAttribute(hConsole, 12); // Red

    printf("[%s] ", dir);
    
    switch (opcode) {
        case 0x0085: // เดิน (Move)
            printf("ACTION: Walking to X:%d Y:%d\n", buf[2], buf[4]); 
            break;
        case 0x0089: // โจมตี (Attack)
            printf("ACTION: Attacking Target ID: %02X%02X%02X\n", (unsigned char)buf[2], (unsigned char)buf[3], (unsigned char)buf[4]);
            break;
        case 0x00F3: // ใช้สกิล (Skill Use)
            printf("ACTION: Using Skill ID: %d\n", *(unsigned short*)(buf + 2));
            break;
        case 0x0064: // พิมพ์แชท (Chat)
            printf("CHAT: %s\n", buf + 4);
            break;
        case 0x0110: // เซิร์ฟเวอร์แจ้งเลือดลด (Damage)
            printf("EVENT: Damage Dealt/Taken!\n");
            break;
        default:
            printf("ID: %04X | Len: %d\n", opcode, len);
            break;
    }
    SetConsoleTextAttribute(hConsole, 7); // กลับเป็นสีขาวปกติ
}

// --- Hook Wrapper (เทคนิคเดิมที่สำเร็จ) ---
int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    ParseAndPrint("SEND", buf, len);
    DWORD old;
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalSend, origSendBytes, 5);
    int res = pOriginalSend(s, buf, len, flags);
    BYTE jmp = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmp, 5);
    VirtualProtect(pOriginalSend, 5, old, &old);
    return res;
}

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5);
    int res = pOriginalRecv(s, buf, len, flags);
    BYTE jmp = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res > 0) ParseAndPrint("RECV", buf, res);
    return res;
}

void StartHooking() {
    // สร้างหน้าต่าง Console แยก
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    printf("=== BambooRO Live Packet Monitor ===\n");

    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");

    DWORD old;
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(origSendBytes, pOriginalSend, 5);
    BYTE jmpS = { 0xE9 };
    *(DWORD*)(jmpS + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmpS, 5);

    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(origRecvBytes, pOriginalRecv, 5);
    BYTE jmpR = { 0xE9 };
    *(DWORD*)(jmpR + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmpR, 5);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID lp) {
    if (r == DLL_PROCESS_ATTACH) CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0);
    return TRUE;
}
