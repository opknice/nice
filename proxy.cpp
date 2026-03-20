#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);

send_t pOriginalSend = NULL;
recv_t pOriginalRecv = NULL;

// เปลี่ยนเป็น Array ขนาด 5 เพื่อเก็บ Byte ต้นฉบับ
BYTE origSendBytes[5], origRecvBytes[5];

// --- เพิ่มระบบ Hex Dump (ดูไส้ใน Packet) ---
void HexDump(const char* buf, int len) {
    for (int i = 0; i < len; i += 16) {
        printf("  %04X: ", i);
        for (int j = 0; j < 16; j++) {
            if (i + j < len) printf("%02X ", (unsigned char)buf[i + j]);
            else printf("   ");
        }
        printf(" ");
        for (int j = 0; j < 16; j++) {
            if (i + j < len) {
                unsigned char c = buf[i + j];
                printf("%c", (isprint(c) ? c : '.')); // แสดงเป็นตัวอักษรถ้าอ่านออก
            }
        }
        printf("\n");
        if (i > 128) { printf("  ... (too long)\n"); break; } // ตัดจบถ้าปลาตัวใหญ่เกิน
    }
}

void ParseAndPrint(const char* dir, const char* buf, int len) {
    if (len < 2) return;
    
    // ดึง OpCode แบบ Little Endian (มาตรฐาน RO)
    unsigned short opcode = *(unsigned short*)(buf);

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (strcmp(dir, "SEND") == 0) SetConsoleTextAttribute(hConsole, 11); // Cyan
    else SetConsoleTextAttribute(hConsole, 14); // Yellow

    printf("\n[%s] ID: %04X | Len: %d\n", dir, opcode, len);
    HexDump(buf, len); // แสดงข้อมูลดิบเพื่อหาชื่อ Map หรือ Monster
    
    // บันทึกลงไฟล์ Log ด้วยเพื่อวิเคราะห์ภายหลัง
    FILE* f;
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_deep_log.txt", "a") == 0) {
        fprintf(f, "[%s] ID:%04X Len:%d\n", dir, opcode, len);
        fclose(f);
    }
    
    SetConsoleTextAttribute(hConsole, 7);
}

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    ParseAndPrint("SEND", buf, len);
    DWORD old;
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalSend, origSendBytes, 5); // กู้คืนเพื่อส่งจริง
    int res = pOriginalSend(s, buf, len, flags);
    
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmp, 5); // ใส่ Hook กลับ
    VirtualProtect(pOriginalSend, 5, old, &old);
    return res;
}

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5);
    int res = pOriginalRecv(s, buf, len, flags);
    
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res > 0) ParseAndPrint("RECV", buf, res);
    return res;
}

void StartHooking() {
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    printf("=== BambooRO Live Monitor ===\n");

    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) return;

    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");

    DWORD old;
    if (pOriginalSend) {
        VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origSendBytes, pOriginalSend, 5);
        BYTE jmpS[5] = { 0xE9 };
        *(DWORD*)(jmpS + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
        memcpy(pOriginalSend, jmpS, 5);
        VirtualProtect(pOriginalSend, 5, old, &old);
    }

    if (pOriginalRecv) {
        VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origRecvBytes, pOriginalRecv, 5);
        BYTE jmpR[5] = { 0xE9 };
        *(DWORD*)(jmpR + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
        memcpy(pOriginalRecv, jmpR, 5);
        VirtualProtect(pOriginalRecv, 5, old, &old);
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID lp) {
    if (r == DLL_PROCESS_ATTACH) CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0);
    return TRUE;
}
