#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

// เพิ่มที่ส่วนประกาศ (Definitions)
typedef int (WSAAPI* wsaconnect_t)(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
wsaconnect_t pOriginalWSAConnect = NULL;
BYTE origWSAConnectBytes[5];

// --- Definitions ---
typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);

send_t pOriginalSend = NULL;
recv_t pOriginalRecv = NULL;
BYTE origSendBytes[5], origRecvBytes[5];

typedef int (WSAAPI* connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
connect_t pOriginalConnect = NULL;
BYTE origConnectBytes[5];

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

        unsigned short opcode = (len >= 2) ? *(unsigned short*)(buf) : 0; // เช็ค len ก่อน
        
        fprintf(f, "[%02d:%02d:%02d] [%s] ID: %04X (%s) | Len: %d | Hex: ", 
                ltm.tm_hour, ltm.tm_min, ltm.tm_sec, type, opcode, GetOpName(opcode), len);
        
        for (int i = 0; i < len; i++) fprintf(f, "%02X ", (unsigned char)buf[i]);
        fprintf(f, "\n");
        fclose(f);
    }
}

int WSAAPI MyConnectHook(SOCKET s, const struct sockaddr* name, int namelen) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    unsigned short port = ntohs(addr->sin_port);

    // --- กฎการคัดกรอง ---
    // เลี้ยวเฉพาะพอร์ต Login (6900) หรือพอร์ต Zone (6121) เท่านั้น
    if (port == 6900 || port == 6121) {
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6901);
    } 
    // พอร์ตอื่นๆ (เช่น พอร์ต License ของ Gepard หรือพอร์ตเว็บ) ให้ปล่อยไปหา Server จริง
    else {
        // ไม่ต้องทำอะไร ปล่อยให้ pOriginalConnect ทำงานด้วยค่าเดิม
    }

    return pOriginalConnect(s, (const struct sockaddr*)addr, namelen);
}

// ฟังก์ชัน Hook สำหรับ WSAConnect
int WSAAPI MyWSAConnectHook(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    unsigned short port = ntohs(addr->sin_port);

    // เลี้ยวเฉพาะพอร์ตเกมเท่านั้น
    if (port == 6900 || port == 6121) {
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6901);
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
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5); // ปลด Hook เพื่อเรียกฟังก์ชันจริง
    
    int res = pOriginalRecv(s, buf, len, flags);
    
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5); // ใส่ Hook กลับคืน
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res > 0) {
        unsigned short opcode = *(unsigned short*)(buf);
        // ถ้าเจอ Packet Gepard ให้ Log ไว้แต่ไม่ต้องส่งต่อให้บอท (คืนค่า 0 หรือทำลายทิ้ง)
        if (opcode == 0x9E87) {
            WriteLog("GEPARD-BYPASS", buf, res);
            // ถ้าอยากซ่อนจากบอท 100% ให้ทำกระบวนการซ่อน buffer แต่เบื้องต้นปล่อยให้เกมรันไปก่อนได้ครับ
        }
        WriteLog("S->C", buf, res);
    }
    return res;
}


// --- Injection Setup ---
void StartHooking() {
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");
    pOriginalConnect = (connect_t)GetProcAddress(hWs2, "connect");
    pOriginalWSAConnect = (wsaconnect_t)GetProcAddress(hWs2, "WSAConnect"); // ดึง Address ของ WSAConnect

    DWORD old;

    // 1. Hook WSAConnect (สำคัญสำหรับ Ghost Launcher)
    if (pOriginalWSAConnect) {
        VirtualProtect(pOriginalWSAConnect, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origWSAConnectBytes, pOriginalWSAConnect, 5);
        BYTE jmpW[5] = { 0xE9 };
        *(DWORD*)(jmpW + 1) = (DWORD)MyWSAConnectHook - (DWORD)pOriginalWSAConnect - 5;
        memcpy(pOriginalWSAConnect, jmpW, 5);
        VirtualProtect(pOriginalWSAConnect, 5, old, &old);
    }

    // 2. Hook Connect
    if (pOriginalConnect) {
        VirtualProtect(pOriginalConnect, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origConnectBytes, pOriginalConnect, 5);
        BYTE jmpC[5] = { 0xE9 };
        *(DWORD*)(jmpC + 1) = (DWORD)MyConnectHook - (DWORD)pOriginalConnect - 5;
        memcpy(pOriginalConnect, jmpC, 5);
        VirtualProtect(pOriginalConnect, 5, old, &old);
    }

    // 3. Hook Send
    if (pOriginalSend) {
        VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origSendBytes, pOriginalSend, 5); // สำรอง 5 bytes แรก
        BYTE jmpS[5] = { 0xE9 };
        *(DWORD*)(jmpS + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
        memcpy(pOriginalSend, jmpS, 5); // เขียน JMP
        VirtualProtect(pOriginalSend, 5, old, &old);
    }

    // 4. Hook Recv
    if (pOriginalRecv) {
        VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(origRecvBytes, pOriginalRecv, 5); // สำรอง 5 bytes แรก
        BYTE jmpR[5] = { 0xE9 };
        *(DWORD*)(jmpR + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
        memcpy(pOriginalRecv, jmpR, 5); // เขียน JMP
        VirtualProtect(pOriginalRecv, 5, old, &old);
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0);
    return TRUE;
}
