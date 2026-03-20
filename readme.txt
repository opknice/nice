เป็นการ hooking patch game โดยใช้ proxy.cpp และ index ในการดักจับ traffic

cd "C:\Users\User\Downloads\sidebyside"

cl.exe /LD proxy.cpp /Fe:version.dll




หา dump files : Run idle Client.exe
dumpbin /IMPORTS "C:\Users\User\Downloads\BambooRO_v6\BambooRO_v6\BamBoo_Client.exe" > imports.txt