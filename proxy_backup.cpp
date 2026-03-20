#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// เก็บข้อมูลต้นฉบับเพื่อกู้คืน (Trampoline)
BYTE originalBytes[5];
void* pSendAddr = NULL;

// ฟังก์ชัน "สายลับ" ดักจับ Packet
int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    // 1. บันทึกข้อมูล Packet เป็น Hex ลงไฟล์
    FILE* f;
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_packets.txt", "a") == 0) {
        fprintf(f, "[SEND] Size: %d | Data: ", len);
        for (int i = 0; i < len; i++) {
            fprintf(f, "%02X ", (unsigned char)buf[i]);
        }
        fprintf(f, "\n");
        fclose(f);
    }

    // 2. ปลด Hook ชั่วคราวเพื่อส่งข้อมูลจริง (ไม่งั้นจะเกิด Loop)
    DWORD oldProtect;
    VirtualProtect(pSendAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pSendAddr, originalBytes, 5);
    
    int result = send(s, buf, len, flags); // ส่งข้อมูลจริงไป Server

    // 3. ใส่ Hook กลับเข้าไปใหม่เพื่อรอ Packet ถัดไป
    BYTE jump[5] = { 0xE9 };
    DWORD relativeAddr = (DWORD)MySendHook - (DWORD)pSendAddr - 5;
    memcpy(jump + 1, &relativeAddr, 4);
    memcpy(pSendAddr, jump, 5);
    VirtualProtect(pSendAddr, 5, oldProtect, &oldProtect);

    return result;
}

void DoHookWork() {
    HMODULE hWs2 = NULL;
    while (hWs2 == NULL) {
        hWs2 = GetModuleHandleA("ws2_32.dll");
        Sleep(500);
    }

    pSendAddr = (void*)GetProcAddress(hWs2, "send");

    if (pSendAddr) {
        // สำรองข้อมูล 5 Byte แรก
        DWORD oldProtect;
        VirtualProtect(pSendAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(originalBytes, pSendAddr, 5);

        // เขียนคำสั่ง JMP (Jump) ไปที่ฟังก์ชัน MySendHook ของเรา
        BYTE jump[5] = { 0xE9 };
        DWORD relativeAddr = (DWORD)MySendHook - (DWORD)pSendAddr - 5;
        memcpy(jump + 1, &relativeAddr, 4);
        memcpy(pSendAddr, jump, 5);

        VirtualProtect(pSendAddr, 5, oldProtect, &oldProtect);

        FILE* f;
        if (fopen_s(&f, "C:\\Users\\Public\\bamboo_stealth.txt", "a") == 0) {
            fprintf(f, "[*] Packet Hook Active at: %p\n", pSendAddr);
            fclose(f);
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DoHookWork, NULL, 0, NULL);
    }
    return TRUE;
}
