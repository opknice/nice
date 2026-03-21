#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>

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

// แก้ไขจาก BYTE เป็น BYTE[5] ทั้งหมด
BYTE origSendBytes[5];
BYTE origRecvBytes[5];
BYTE origConnectBytes[5];
BYTE origWSAConnectBytes[5];

// --- Logger Function ---
void WriteLog(const char* type, const char* buf, int len) {
    FILE* f;
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_analysis.log", "a") == 0) {
        time_t now = time(0);
        struct tm ltm;
        localtime_s(&ltm, &now);

        // ดึง OpCode (2 bytes แรก)
        unsigned short opcode = (len >= 2) ? *(unsigned short*)(buf) : 0; 
        
        fprintf(f, "[%02d:%02d:%02d] [%s] ID: %04X | Len: %d | Hex: ", 
                ltm.tm_hour, ltm.tm_min, ltm.tm_sec, type, opcode, len);
        
        for (int i = 0; i < len; i++) fprintf(f, "%02X ", (unsigned char)buf[i]);
        fprintf(f, "\n");
        fclose(f);
    }
}

// --- Hook Connect: เลี้ยวไปหาบอทที่ 6991 ---
int WSAAPI MyConnectHook(SOCKET s, const struct sockaddr* name, int namelen) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    unsigned short port = ntohs(addr->sin_port);

    if (port == 6900 || port == 6121) {
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6991);
    }

    DWORD old;
    VirtualProtect(pOriginalConnect, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalConnect, origConnectBytes, 5); // ปลด Hook
    
    int res = pOriginalConnect(s, (const struct sockaddr*)addr, namelen);
    
    BYTE jmp[5] = { 0xE9 }; // ประกาศ array ให้ถูก
    *(DWORD*)(jmp + 1) = (DWORD)MyConnectHook - (DWORD)pOriginalConnect - 5;
    memcpy(pOriginalConnect, jmp, 5); // ใส่ Hook กลับ (ต้องใช้ jmp)
    
    VirtualProtect(pOriginalConnect, 5, old, &old);
    return res;
}

// --- Hook Send: ข้อมูลจาก Client (เกม) ไป Server ---
int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    // *** กฎเหล็ก: ถ้าความยาวคือ 269 (Gepard Response) ให้ปล่อยผ่านทันที ***
    if (len == 269) {
        WriteLog("GEPARD-C->S-BYPASS", buf, len);
        
        DWORD old;
        VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(pOriginalSend, origSendBytes, 5);
        int res = pOriginalSend(s, buf, len, flags); // ส่งจริงไปหา Server
        
        BYTE jmp[5] = { 0xE9 };
        *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
        memcpy(pOriginalSend, jmp, 5);
        VirtualProtect(pOriginalSend, 5, old, &old);
        
        return res; // จบการทำงานตรงนี้ บอทจะไม่เห็น Packet นี้
    }

    // Packet ปกติ (เดิน/ตี) ให้บันทึก Log และผ่านบอทตามปกติ
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

// --- Hook Recv: ข้อมูลจาก Server มาที่ Client (เกม) ---
int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5);
    int res = pOriginalRecv(s, buf, len, flags);
    
    
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res > 0) {
        // *** กฎเหล็ก: ถ้าความยาวคือ 2760 (Gepard Challenge) ให้ปล่อยผ่านทันที ***
        if (res == 2760) {
            WriteLog("GEPARD-S->C-BYPASS", buf, res);
            return res; // ส่งต่อให้เกมประมวลผลเอง บอทจะไม่เห็น
        }
        WriteLog("S->C", buf, res);
    }
    return res;
}

int WSAAPI MyWSAConnectHook(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    unsigned short port = ntohs(addr->sin_port);

    // เลี้ยวเฉพาะพอร์ตเกม (6900/6121) ไปหาบอท 6991
    if (port == 6900 || port == 6121) {
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6991);
    }

    DWORD old;
    VirtualProtect(pOriginalWSAConnect, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalWSAConnect, origWSAConnectBytes, 5);
    int res = pOriginalWSAConnect(s, (const struct sockaddr*)addr, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyWSAConnectHook - (DWORD)pOriginalWSAConnect - 5;
    memcpy(pOriginalWSAConnect, jmp, 5);
    VirtualProtect(pOriginalWSAConnect, 5, old, &old);
    return res;
}

// ส่วนที่ประกาศ Hooks ใน StartHooking ให้แก้เป็นแบบนี้จะชัวร์ที่สุดครับ
void StartHooking() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");
    pOriginalConnect = (connect_t)GetProcAddress(hWs2, "connect");
    pOriginalWSAConnect = (wsaconnect_t)GetProcAddress(hWs2, "WSAConnect");

    DWORD old;

    // Hook Connect
    if (pOriginalConnect) {
        VirtualProtect(pOriginalConnect, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origConnectBytes, pOriginalConnect, 5); // ตอนนี้ origConnectBytes เป็น array [5] แล้ว
        BYTE jmp[5] = { 0xE9 };
        *(DWORD*)(jmp + 1) = (DWORD)MyConnectHook - (DWORD)pOriginalConnect - 5;
        memcpy(pOriginalConnect, jmp, 5);
        VirtualProtect(pOriginalConnect, 5, old, &old);
    }

    // Hook Send
    if (pOriginalSend) {
        VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origSendBytes, pOriginalSend, 5);
        BYTE jmp[5] = { 0xE9 };
        *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
        memcpy(pOriginalSend, jmp, 5);
        VirtualProtect(pOriginalSend, 5, old, &old);
    }

    // Hook Recv
    if (pOriginalRecv) {
        VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origRecvBytes, pOriginalRecv, 5);
        BYTE jmp[5] = { 0xE9 };
        *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
        memcpy(pOriginalRecv, jmp, 5);
        VirtualProtect(pOriginalRecv, 5, old, &old);
    }
        // เพิ่มการติดตั้ง Hook WSAConnect
    if (pOriginalWSAConnect) {
        DWORD old;
        VirtualProtect(pOriginalWSAConnect, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origWSAConnectBytes, pOriginalWSAConnect, 5);
        BYTE jmpW[5] = { 0xE9 };
        *(DWORD*)(jmpW + 1) = (DWORD)MyWSAConnectHook - (DWORD)pOriginalWSAConnect - 5;
        memcpy(pOriginalWSAConnect, jmpW, 5);
        VirtualProtect(pOriginalWSAConnect, 5, old, &old);
    }
}


BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0);
    }
    return TRUE;
}
