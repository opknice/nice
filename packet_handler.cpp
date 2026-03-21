#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>  // <--- เพิ่มบรรทัดนี้เข้าไปครับ
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

// --- Definitions ---
typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);

send_t pOriginalSend = NULL;
recv_t pOriginalRecv = NULL;
BYTE origSendBytes[5], origRecvBytes[5];

// --- [NEW] Packet Configuration (XOR & Shuffle) ---
// หมายเหตุ: ค่าเหล่านี้ต้องหาจากการส่อง Memory ของเกม หรือเทียบจาก rAthena
unsigned int g_XOR_Key = 0x5D6F2A1B; 
unsigned char g_Shuffle_Table[256]; // ต้องใช้ค่าจริงเพื่อสลับตำแหน่ง Byte

// --- [NEW] Function: Remap Server ID ---
unsigned short RemapID(unsigned short serverID) {
    // แก้ปัญหา UNKNOWN โดยการ Map เลขที่เซิร์ฟเวอร์ส่งมา กลับเป็นเลขมาตรฐาน
    // ตัวอย่าง: ถ้าเซิร์ฟเวอร์ใช้ 0x3B01 แทนการเดิน (0x0085)
    switch (serverID) {
        case 0x3B01: return 0x0085; // WALK
        case 0x3C01: return 0x0089; // ATTACK
        case 0x3D01: return 0x0093; // SKILL
        default: return serverID;
    }
}

// --- [NEW] Function: Multi-byte Rolling XOR ---
void DecryptBuffer(unsigned char* buf, int len) {
    // ถอดรหัสข้อมูลแบบ Rolling เพื่อให้ข้อมูลที่ถูก Shuffle กลับมาอ่านออก
    for (int i = 0; i < len; i++) {
        buf[i] ^= (unsigned char)((g_XOR_Key >> (i % 4 * 8)) & 0xFF);
    }
}

const char* GetOpName(unsigned short opcode) {
    unsigned short cleanID = RemapID(opcode);
    switch (cleanID) {
        case 0x0085: return "WALK";
        case 0x0089: return "ATTACK";
        case 0x0093: return "USE_SKILL";
        case 0x0064: return "CHAT_SEND";
        case 0x0080: return "ITEM_PICKUP";
        case 0x00A7: return "ITEM_USE";
        default: return "UNKNOWN";
    }
}

void WriteLog(const char* type, const char* buf, int len) {
    FILE* f;
    // สร้างชื่อไฟล์ตามเวลาปัจจุบัน (log_$time.log)
    char fileName[100];
    time_t now = time(0);
    struct tm ltm;
    localtime_s(&ltm, &now);
    sprintf_s(fileName, "C:\\Users\\Public\\log_%02d%02d%02d.log", ltm.tm_hour, ltm.tm_min, ltm.tm_sec);

    if (fopen_s(&f, fileName, "a") == 0) {
        // ก๊อปปี้ข้อมูลมาถอดรหัสก่อนบันทึก
        unsigned char* tempBuf = (unsigned char*)malloc(len);
        memcpy(tempBuf, buf, len);
        
        // --- ขั้นตอนการแกะข้อมูล ---
        // 1. ถอดรหัส XOR
        DecryptBuffer(tempBuf, len);
        
        // 2. ดึง OpCode หลังจากถอดรหัสแล้ว
        unsigned short rawOpcode = *(unsigned short*)(tempBuf);
        unsigned short cleanOpcode = RemapID(rawOpcode);
        
        fprintf(f, "[%02d:%02d:%02d] [%s] RAW:%04X -> REMAP:%04X (%s) | Len:%d\n", 
                ltm.tm_hour, ltm.tm_min, ltm.tm_sec, type, rawOpcode, cleanOpcode, GetOpName(cleanOpcode), len);
        
        fprintf(f, "  Hex: ");
        for (int i = 0; i < len; i++) fprintf(f, "%02X ", tempBuf[i]);
        fprintf(f, "\n---\n");
        
        fclose(f);
        free(tempBuf);
    }
}

// --- Hooks Logic (เหมือนเดิมแต่เรียกใช้ WriteLog ตัวใหม่) ---
int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    WriteLog("C->S", buf, len);
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
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5);
    int res = pOriginalRecv(s, buf, len, flags);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res > 0) WriteLog("S->C", buf, res);
    return res;
}

void StartHooking() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");

    DWORD old;
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(origSendBytes, pOriginalSend, 5);
    BYTE jmpS[5] = { 0xE9 };
    *(DWORD*)(jmpS + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmpS, 5);

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
