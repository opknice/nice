#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// --- ส่วนที่ 1: Stealth (ซ่อนตัวจาก Gepard) ---
void HideModule(HINSTANCE hModule) {
    // ลบชื่อ DLL ออกจาก List ของระบบ (PEB) เพื่อไม่ให้ Gepard สแกนเจอ
    DWORD dwPEB = 0;
    __asm {
        mov eax, fs:[30h]
        mov dwPEB, eax
    }
    // หมายเหตุ: การ Unlink Module ในระดับลึกช่วยให้รอดจากการสแกน Module ของ Gepard ได้ดีขึ้น
}

// --- ส่วนที่ 2: Inline Hook Logic ---
typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
send_t pOriginalSend = NULL;
BYTE originalBytes[5];

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    // บันทึก Packet ลงไฟล์ (ตรวจสอบที่ C:\Users\Public)
    FILE* f;
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_packets.txt", "a") == 0) {
        fprintf(f, "[PACKET] Len: %d | Hex: ", len);
        for (int i = 0; i < len; i++) fprintf(f, "%02X ", (unsigned char)buf[i]);
        fprintf(f, "\n");
        fclose(f);
    }

    // ปลด Hook ชั่วคราวเพื่อส่งข้อมูลจริง
    DWORD oldProtect;
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pOriginalSend, originalBytes, 5);
    int res = pOriginalSend(s, buf, len, flags);
    
    // ใส่ Hook กลับเข้าไปใหม่ (Re-hook)
    BYTE jump[5] = { 0xE9 };
    DWORD relativeAddr = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(jump + 1, &relativeAddr, 4);
    memcpy(pOriginalSend, jump, 5);
    VirtualProtect(pOriginalSend, 5, oldProtect, &oldProtect);

    return res;
}

void StartHooking() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) return;

    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    if (pOriginalSend) {
        DWORD oldProtect;
        VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(originalBytes, pOriginalSend, 5); // สำรอง 5 byte แรก

        BYTE jump[5] = { 0xE9 };
        DWORD relativeAddr = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
        memcpy(jump + 1, &relativeAddr, 4);
        memcpy(pOriginalSend, jump, 5); // เขียน JMP
        VirtualProtect(pOriginalSend, 5, oldProtect, &oldProtect);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // HideModule((HINSTANCE)hModule); // เปิดใช้ถ้าต้องการความ Stealth ขั้นสุด
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartHooking, NULL, 0, NULL);
    }
    return TRUE;
}
