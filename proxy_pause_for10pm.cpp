#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

// ============================================================
// Forward exports -> version_orig.dll
// ============================================================
#pragma comment(linker, "/export:GetFileVersionInfoA=version_orig.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=version_orig.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=version_orig.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=version_orig.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=version_orig.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=version_orig.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=version_orig.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=version_orig.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=version_orig.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=version_orig.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=version_orig.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=version_orig.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=version_orig.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=version_orig.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=version_orig.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=version_orig.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=version_orig.VerQueryValueW")

#define PROXY_VERSION "v10-GPA"  // GPA = GetProcAddress hook
#define CONFIG_PORT   25787
#define RO_GAME_PORT  6700

// ============================================================
// Credentials + endpoint state
// ============================================================
char g_AuthToken[64]={0}, g_AID[32]={0}, g_GID[32]={0}, g_WorldName[64]={0};
volatile int g_lastEndpoint=0;
#define EP_USERCONFIG 1
#define EP_CHARCONFIG 2
#define EP_CHARSAVE   3
static SOCKET g_gameSocket = INVALID_SOCKET;

// ============================================================
// Port discovery
// ============================================================
static int g_seenPorts[64]={0}, g_seenCount=0;
static int GetPeerInfo(SOCKET s,char* ipBuf,int ipLen){
    struct sockaddr_in a; int al=sizeof(a);
    if(getpeername(s,(struct sockaddr*)&a,&al)==0){
        unsigned char* ip=(unsigned char*)&a.sin_addr.s_addr;
        if(ipBuf) _snprintf_s(ipBuf,ipLen,_TRUNCATE,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
        return ntohs(a.sin_port);
    }
    if(ipBuf) ipBuf[0]='\0'; return 0;
}
static void RecordPort(int port,const char* ip){
    for(int i=0;i<g_seenCount;i++) if(g_seenPorts[i]==port) return;
    if(g_seenCount<64) g_seenPorts[g_seenCount++]=port;
    FILE* f; if(fopen_s(&f,"C:\\Users\\Public\\bamboo_ports.txt","a")==0){
        fprintf(f,"[NEW PORT] %s:%d\n",ip,port); fclose(f);}
}
static void BuildLogPath(int port,char* buf,int len){
    if(port==CONFIG_PORT) _snprintf_s(buf,len,_TRUNCATE,"C:\\Users\\Public\\bamboo_packets.txt");
    else _snprintf_s(buf,len,_TRUNCATE,"C:\\Users\\Public\\bamboo_port_%d.txt",port);
}
static void LogRaw(const char* path,const char* dir,const char* ip,int port,const char* d,int l){
    FILE* f; if(fopen_s(&f,path,"a")==0){
        fprintf(f,"[%s] %s:%d Size:%d | ",dir,ip,port,l);
        for(int i=0;i<l;i++) fprintf(f,"%02X ",(unsigned char)d[i]);
        fprintf(f,"\n"); fclose(f);}
}

// ============================================================
// HTTP helpers
// ============================================================
static int ExtractField(const char* buf,int len,const char* name,char* out,int outMax){
    char pat[128]; _snprintf_s(pat,sizeof(pat),_TRUNCATE,"name=\"%s\"\r\n\r\n",name);
    int plen=(int)strlen(pat);
    for(int i=0;i<=len-plen;i++) if(memcmp(buf+i,pat,plen)==0){
        int s=i+plen,e=s;
        while(e<len-1&&!(buf[e]=='\r'&&buf[e+1]=='\n'))e++;
        int vlen=e-s; if(vlen<=0||vlen>=outMax) return 0;
        memcpy(out,buf+s,vlen); out[vlen]='\0'; return 1;
    }
    return 0;
}
static void SaveCredentials(){
    FILE* f; if(fopen_s(&f,"C:\\Users\\Public\\bamboo_creds.txt","w")==0){
        fprintf(f,"AID=%s\nGID=%s\nAuthToken=%s\nWorldName=%s\n",g_AID,g_GID,g_AuthToken,g_WorldName);
        fclose(f);}
}
static void SaveJson(int ep,const char* buf,int len){
    const char* fp=ep==EP_USERCONFIG?"C:\\Users\\Public\\bamboo_userconfig.json":
                  (ep==EP_CHARCONFIG||ep==EP_CHARSAVE)?"C:\\Users\\Public\\bamboo_charconfig.json":NULL;
    if(!fp) return;
    FILE* f; if(fopen_s(&f,fp,"w")==0){fwrite(buf,1,len,f);fclose(f);}
}

// ============================================================
// Shared packet processing
// ============================================================
static void ProcessSend(SOCKET s,const char* buf,int len){
    char ip[32]={0}; int port=GetPeerInfo(s,ip,sizeof(ip));
    if(port<=0) return;
    RecordPort(port,ip);
    char path[MAX_PATH]; BuildLogPath(port,path,sizeof(path));
    LogRaw(path,"SEND",ip,port,buf,len);
    if(port==RO_GAME_PORT){ g_gameSocket=s; return; }
    if(port!=CONFIG_PORT) return;
    if(len>4&&memcmp(buf,"POST",4)==0){
        if(memcmp(buf+5,"/userconfig/load",16)==0) g_lastEndpoint=EP_USERCONFIG;
        else if(memcmp(buf+5,"/charconfig/load",16)==0) g_lastEndpoint=EP_CHARCONFIG;
        else if(memcmp(buf+5,"/charconfig/save",16)==0) g_lastEndpoint=EP_CHARSAVE;
        else g_lastEndpoint=0;
    }
    char t[64]={0},a[32]={0},g2[32]={0},w[64]={0};
    if(ExtractField(buf,len,"AID",a,sizeof(a))&&a[0]) memcpy(g_AID,a,sizeof(g_AID));
    if(ExtractField(buf,len,"GID",g2,sizeof(g2))&&g2[0]) memcpy(g_GID,g2,sizeof(g_GID));
    if(ExtractField(buf,len,"WorldName",w,sizeof(w))&&w[0]) memcpy(g_WorldName,w,sizeof(g_WorldName));
    if(ExtractField(buf,len,"AuthToken",t,sizeof(t))&&t[0]&&strcmp(g_AuthToken,t)!=0){
        memcpy(g_AuthToken,t,sizeof(g_AuthToken)); SaveCredentials();
        FILE* f; if(fopen_s(&f,"C:\\Users\\Public\\bamboo_stealth.txt","a")==0){
            fprintf(f,"[*] AuthToken: %s  AID: %s  GID: %s\n",g_AuthToken,g_AID,g_GID);
            fclose(f);}
    }
}
static void ProcessRecv(SOCKET s,const char* buf,int len){
    char ip[32]={0}; int port=GetPeerInfo(s,ip,sizeof(ip));
    if(port<=0||len<=0) return;
    RecordPort(port,ip);
    char path[MAX_PATH]; BuildLogPath(port,path,sizeof(path));
    LogRaw(path,"RECV",ip,port,buf,len);
    if(port==RO_GAME_PORT){ g_gameSocket=s; return; }
    if(port==CONFIG_PORT&&buf[0]=='{'){
        SaveJson(g_lastEndpoint,buf,len);
        FILE* f; if(fopen_s(&f,"C:\\Users\\Public\\bamboo_stealth.txt","a")==0){
            const char* en=g_lastEndpoint==EP_USERCONFIG?"userconfig":
                           g_lastEndpoint==EP_CHARCONFIG?"charconfig":
                           g_lastEndpoint==EP_CHARSAVE?"charsave":"?";
            fprintf(f,"[*] JSON saved (%s) %d bytes\n",en,len); fclose(f);}
        g_lastEndpoint=0;
    }
}

// ============================================================
// Hook function stubs — เหล่านี้คือสิ่งที่จะถูกส่งกลับแทน
// เมื่อ Gepard/game เรียก GetProcAddress(ws2_32, "send") ฯลฯ
//
// สถาปัตยกรรม:
//   Gepard → Hook_GetProcAddress("send") → คืน Hook_send
//   Gepard บันทึก Hook_send ไว้เป็น function pointer
//   Gepard เรียก Hook_send(s, buf, len, flags)
//   Hook_send → ProcessSend → เรียก ws2_32.send จริงๆ
// ============================================================

// Direct pointers ไปยัง ws2_32 functions (ข้าม Gepard ทั้งหมด)
typedef int  (WSAAPI* pfn_send)   (SOCKET,const char*,int,int);
typedef int  (WSAAPI* pfn_recv)   (SOCKET,char*,int,int);
typedef int  (WSAAPI* pfn_WSASend)(SOCKET,LPWSABUF,DWORD,LPDWORD,DWORD,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int  (WSAAPI* pfn_WSARecv)(SOCKET,LPWSABUF,DWORD,LPDWORD,LPDWORD,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int  (WSAAPI* pfn_connect)(SOCKET,const struct sockaddr*,int);

static pfn_send    real_send    = NULL;
static pfn_recv    real_recv    = NULL;
static pfn_WSASend real_WSASend = NULL;
static pfn_WSARecv real_WSARecv = NULL;
static pfn_connect real_connect = NULL;

int WSAAPI Hook_send(SOCKET s,const char* buf,int len,int flags){
    ProcessSend(s,buf,len);
    return real_send(s,buf,len,flags);
}
int WSAAPI Hook_recv(SOCKET s,char* buf,int len,int flags){
    int r=real_recv(s,buf,len,flags);
    if(r>0) ProcessRecv(s,buf,r);
    return r;
}
int WSAAPI Hook_WSASend(SOCKET s,LPWSABUF lpB,DWORD c,LPDWORD sent,DWORD f,
                        LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE comp){
    for(DWORD i=0;i<c;i++) if(lpB[i].buf&&lpB[i].len>0)
        ProcessSend(s,lpB[i].buf,(int)lpB[i].len);
    return real_WSASend(s,lpB,c,sent,f,ov,comp);
}
int WSAAPI Hook_WSARecv(SOCKET s,LPWSABUF lpB,DWORD c,LPDWORD recvd,LPDWORD f,
                        LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE comp){
    int r=real_WSARecv(s,lpB,c,recvd,f,ov,comp);
    if(r==0&&!ov&&recvd&&*recvd>0)
        for(DWORD i=0;i<c;i++) if(lpB[i].buf)
            ProcessRecv(s,lpB[i].buf,(int)*recvd);
    return r;
}
int WSAAPI Hook_connect(SOCKET s,const struct sockaddr* name,int namelen){
    if(name&&name->sa_family==AF_INET){
        const struct sockaddr_in* a=(const struct sockaddr_in*)name;
        unsigned char* ip=(unsigned char*)&a->sin_addr.s_addr;
        int port=ntohs(a->sin_port);
        FILE* f; if(fopen_s(&f,"C:\\Users\\Public\\bamboo_connect.txt","a")==0){
            fprintf(f,"[CONNECT] sock=%llu -> %d.%d.%d.%d:%d%s\n",
                    (unsigned long long)s,ip[0],ip[1],ip[2],ip[3],port,
                    port==RO_GAME_PORT?" *** RO ***":"");
            fclose(f);}
        RecordPort(port,"");
        if(port==RO_GAME_PORT) g_gameSocket=s;
    }
    return real_connect(s,name,namelen);
}

// ============================================================
// Hook_GetProcAddress — แกนหลักของ v10
//
// เมื่อ Gepard/game เรียก GetProcAddress(hWs2, "send") ฯลฯ
// เราตรวจ function name แล้วคืน Hook_* แทนที่จะคืน address จริง
// Gepard จะบันทึก Hook_* ไว้และเรียกผ่าน Hook_* ตลอด
// ดังนั้นทุก packet ที่ Gepard ส่ง/รับจะผ่าน hooks ของเรา
// ============================================================
typedef FARPROC (WINAPI* pfn_GetProcAddress)(HMODULE, LPCSTR);
static pfn_GetProcAddress real_GetProcAddress = NULL;

FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName){
    // ป้องกัน crash จาก ordinal import (lpProcName เป็น number ไม่ใช่ string)
    if((ULONG_PTR)lpProcName <= 0xFFFF) 
        return real_GetProcAddress(hModule, lpProcName);

    // ตรวจว่า module ที่ถามเป็น ws2_32.dll หรือเปล่า
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if(hModule == hWs2){
        // คืน hook function แทน real function
        if(strcmp(lpProcName,"send")    ==0){ 
            FILE* f; if(fopen_s(&f,"C:\\Users\\Public\\bamboo_stealth.txt","a")==0){
                fprintf(f,"[*] GetProcAddress intercepted: ws2_32.%s → Hook\n",lpProcName);
                fclose(f);}
            return (FARPROC)Hook_send;
        }
        if(strcmp(lpProcName,"recv")    ==0) return (FARPROC)Hook_recv;
        if(strcmp(lpProcName,"WSASend") ==0) return (FARPROC)Hook_WSASend;
        if(strcmp(lpProcName,"WSARecv") ==0) return (FARPROC)Hook_WSARecv;
        if(strcmp(lpProcName,"connect") ==0) return (FARPROC)Hook_connect;
    }

    return real_GetProcAddress(hModule, lpProcName);
}

// ============================================================
// PatchIAT — แทนที่ pointer ใน Import Address Table
// ใช้สำหรับ patch GetProcAddress ใน IAT ของ gepard.dll
// (GetProcAddress อยู่ใน IAT ของ gepard.dll เพราะเป็น static import จาก kernel32)
// ============================================================
static void* PatchIAT(HMODULE hMod,const char* dllName,const char* fnName,void* newFn){
    if(!hMod||!newFn) return NULL;
    BYTE* base=(BYTE*)hMod;
    IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)base;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt=(IMAGE_NT_HEADERS*)(base+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE) return NULL;
    DWORD impRVA=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(!impRVA) return NULL;
    IMAGE_IMPORT_DESCRIPTOR* imp=(IMAGE_IMPORT_DESCRIPTOR*)(base+impRVA);
    for(;imp->Name;imp++){
        if(_stricmp((const char*)(base+imp->Name),dllName)!=0) continue;
        IMAGE_THUNK_DATA* ot=(IMAGE_THUNK_DATA*)(base+imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA* t =(IMAGE_THUNK_DATA*)(base+imp->FirstThunk);
        for(;ot->u1.AddressOfData;ot++,t++){
            if(IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME* bn=(IMAGE_IMPORT_BY_NAME*)(base+ot->u1.AddressOfData);
            if(strcmp((char*)bn->Name,fnName)!=0) continue;
            void* old=(void*)t->u1.Function;
            DWORD p; VirtualProtect(&t->u1.Function,sizeof(void*),PAGE_EXECUTE_READWRITE,&p);
            t->u1.Function=(ULONG_PTR)newFn;
            VirtualProtect(&t->u1.Function,sizeof(void*),p,&p);
            return old;
        }
    }
    return NULL;
}

// ============================================================
// Setup
// ============================================================
void DoHookWork(){
    LoadLibraryA("version_orig.dll");

    HMODULE hWs2=NULL, hK32=NULL;
    while(!hWs2||!hK32){
        hWs2=GetModuleHandleA("ws2_32.dll");
        hK32=GetModuleHandleA("kernel32.dll");
        Sleep(100);
    }

    // เก็บ real function pointers โดยตรงจาก ws2_32
    real_send    =(pfn_send)   GetProcAddress(hWs2,"send");
    real_recv    =(pfn_recv)   GetProcAddress(hWs2,"recv");
    real_WSASend =(pfn_WSASend)GetProcAddress(hWs2,"WSASend");
    real_WSARecv =(pfn_WSARecv)GetProcAddress(hWs2,"WSARecv");
    real_connect =(pfn_connect)GetProcAddress(hWs2,"connect");
    real_GetProcAddress=(pfn_GetProcAddress)GetProcAddress(hK32,"GetProcAddress");

    FILE* f; if(fopen_s(&f,"C:\\Users\\Public\\bamboo_stealth.txt","a")==0){
        fprintf(f,"[*] Proxy %s started\n",PROXY_VERSION);
        fprintf(f,"[*] ws2_32=%p send=%p WSASend=%p\n",(void*)hWs2,(void*)real_send,(void*)real_WSASend);
        fprintf(f,"[*] GetProcAddress=%p\n",(void*)real_GetProcAddress);
        fclose(f);}

    // รอ gepard.dll โหลด (อาจโหลดหลังจาก DLL ของเรา)
    HMODULE hGep=NULL;
    for(int retry=0;retry<40&&!hGep;retry++){
        hGep=GetModuleHandleA("gepard.dll");
        Sleep(250); // รอ max 10 วินาที
    }

    if(hGep){
        if(fopen_s(&f,"C:\\Users\\Public\\bamboo_stealth.txt","a")==0){
            fprintf(f,"[*] gepard.dll @ %p — patching GetProcAddress in IAT\n",(void*)hGep);
            fclose(f);}

        // Patch GetProcAddress ใน IAT ของ gepard.dll
        // เมื่อ Gepard เรียก GetProcAddress(ws2_32,"send") จะได้ Hook_send แทน
        void* oldGPA=PatchIAT(hGep,"kernel32.dll","GetProcAddress",(void*)Hook_GetProcAddress);

        if(fopen_s(&f,"C:\\Users\\Public\\bamboo_stealth.txt","a")==0){
            if(oldGPA){
                // เก็บ real_GetProcAddress จาก gepard's IAT เพื่อความถูกต้อง
                real_GetProcAddress=(pfn_GetProcAddress)oldGPA;
                fprintf(f,"[*] Patched GetProcAddress in gepard.dll IAT ✓ old=%p\n",oldGPA);
            } else {
                fprintf(f,"[!] GetProcAddress NOT found in gepard.dll IAT — trying KernelBase\n");
                // บางระบบ GetProcAddress อยู่ใน KernelBase.dll แทน kernel32.dll
                oldGPA=PatchIAT(hGep,"KernelBase.dll","GetProcAddress",(void*)Hook_GetProcAddress);
                if(oldGPA){
                    real_GetProcAddress=(pfn_GetProcAddress)oldGPA;
                    fprintf(f,"[*] Patched GetProcAddress via KernelBase ✓\n");
                } else {
                    fprintf(f,"[!] GetProcAddress patch FAILED in gepard.dll\n");
                }
            }
            fclose(f);}
    } else {
        if(fopen_s(&f,"C:\\Users\\Public\\bamboo_stealth.txt","a")==0){
            fprintf(f,"[!] gepard.dll NOT FOUND after 10s wait\n"); fclose(f);}
    }

    // Patch GetProcAddress ใน IAT ของ game exe เองด้วย (defense in depth)
    HMODULE hExe=GetModuleHandleA(NULL);
    void* r;
    r=PatchIAT(hExe,"kernel32.dll","GetProcAddress",(void*)Hook_GetProcAddress);
    if(!r) r=PatchIAT(hExe,"KernelBase.dll","GetProcAddress",(void*)Hook_GetProcAddress);
    if(fopen_s(&f,"C:\\Users\\Public\\bamboo_stealth.txt","a")==0){
        fprintf(f,"[*] GetProcAddress in game exe IAT: %s\n",r?"patched":"not found (ok)");
        fprintf(f,"[*] Setup complete\n"); fclose(f);}
}

BOOL APIENTRY DllMain(HMODULE hModule,DWORD reason,LPVOID){
    if(reason==DLL_PROCESS_ATTACH){
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)DoHookWork,NULL,0,NULL);
    }
    return TRUE;
}
