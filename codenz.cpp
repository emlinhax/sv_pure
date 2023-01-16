#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include "xorstr.h"

HANDLE hCsgo = 0;

BYTE clientstate_sig[] = { 0x00, 0x00, 0x00, 0x00, 0x83, 0xB8, 0x08, 0x01, 0x00, 0x00, 0x02, 0x0F, 0x9D, 0xC0, 0xC3 };
const char* clientstate_mask = "????xxxxxxxxxxx";

BYTE CCWS_sig[] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x02, 0x7D, 0x10, 0x8B, 0x0D };
const char* CCWS_mask = "????xxx????xxxxx";

HANDLE get_process_by_name(PCSTR name)
{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process))
    {
        do
        {
            if (std::string(process.szExeFile) == std::string(name))
            {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid != 0)
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    return NULL;
}

auto get_module_info(std::string module, size_t* size) -> DWORD 
{
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hCsgo));
    auto entry = MODULEENTRY32{};
    entry.dwSize = sizeof(entry);

    while (Module32Next(snapshot, &entry)) {
        if (!strcmp(entry.szModule, module.c_str())) {
            CloseHandle(snapshot);
            *size = (size_t)entry.modBaseSize;
            return reinterpret_cast<DWORD>(entry.modBaseAddr);
        }
    }

    return 0;
}

uintptr_t pattern_scan(uintptr_t start, size_t range, BYTE pattern[], const char* msk)
{
    BYTE* memory = (BYTE*)malloc(range);
    if (!ReadProcessMemory(hCsgo, (LPCVOID)start, memory, range, nullptr))
        return -1;

    int ptrnlen = (DWORD)strlen(msk);
    int currentIdx = 0;
    for (int i = 0; i < range - ptrnlen; i++)
    {
        currentIdx++;
        bool lastMatched = true;
        for (int j = 0; j < ptrnlen; j++)
        {
            if ((msk[j] != '?' && memory[i + j] != pattern[j]) || !lastMatched)
            {
                lastMatched = false;
                continue;
            }

            if (j == ptrnlen - 1)
                return i;
        }
    }

    return -1;
}

uintptr_t pattern_scan_in_module(std::string sModule, BYTE* pattern, const char* msk) 
{
    size_t size;
    DWORD base = get_module_info(sModule, &size);
    uintptr_t result = pattern_scan(base, size, pattern, msk);
    return result;
}

uintptr_t find_code_cave(const char* cModuleName, size_t iSize) 
{
    size_t modSize = 0;
    DWORD modBase = get_module_info(cModuleName, &modSize);
    BYTE* moduleContent = (BYTE*)malloc(modSize);

    ReadProcessMemory(hCsgo, (LPCVOID)modBase, moduleContent, modSize - 1, 0);

    for (int i = 0; i < modSize; i++)
    {
        bool found = true;
        for (int j = 0; j < iSize + 1; j++)
        {
            if (moduleContent[i + j] != 0x00)
                found = false;
        }

        if (found == true)
            return ((uintptr_t)modBase + i);
    }

    return 0x0;
}


using fSleep = void(WINAPI*)(DWORD milliseconds);
struct shellcode_packet {
    DWORD hEngine;      //baseaddr of engine.dll
    DWORD piClienstate; //pointer to clientstate.
    DWORD piCCWSOffset; //offset from clientstate to m_bCheckCRCsWithServer
    fSleep pSleep;      //pointer to Sleep function in user32
};

void shellcode(shellcode_packet* pkt)
{
    DWORD pClienstate = *(DWORD*)(pkt->hEngine + pkt->piClienstate);
    DWORD oCCWSOffset = *(DWORD*)(pkt->hEngine + pkt->piCCWSOffset);

    while (true)
    {
        uintptr_t dwClientState = *(uintptr_t*)(pClienstate);
        if (*(BOOL*)(dwClientState + oCCWSOffset) == 1)
            *(BOOL*)(dwClientState + oCCWSOffset) = 0;

        pkt->pSleep(1);
    }
}

int main(int argc, char* argv[])
{
    size_t trash;
    DWORD trash2; 

    system("start csgo.exe -steam -game neo/csgo");
    Sleep(5000);
    while (hCsgo == NULL)
    {
        system(XOR("cls")); //mimimi cry about it. its only every 500ms
        printf(XOR("Waiting for csgo...\n"));
        hCsgo = get_process_by_name(XOR("csgo.exe"));
        Sleep(500);
    }

    DWORD hEngine = get_module_info(XOR("engine.dll"), &trash);
    while (hEngine == 0) { hEngine = get_module_info(XOR("engine.dll"), &trash); };

    printf(XOR("Scanning...\n"));
    DWORD piClienstate = pattern_scan_in_module(XOR("engine.dll"), clientstate_sig, clientstate_mask);
    DWORD piCCWSOffset = pattern_scan_in_module(XOR("engine.dll"), CCWS_sig, CCWS_mask);
    if (piClienstate == -1 || piCCWSOffset == -1)
    {
        printf(XOR("Failed to find offsets!\n"));
        CloseHandle(hCsgo);
        Sleep(1000);
        return -1;
    }

    //initialize shellcode_packet
    shellcode_packet pkt{ 0 };
    pkt.hEngine = hEngine;
    pkt.piClienstate = piClienstate;
    pkt.piCCWSOffset = piCCWSOffset;
    pkt.pSleep = Sleep;

    //allocate it inside csgo with the correct parameters
    BYTE* pShellcodePacket = reinterpret_cast<BYTE*>(VirtualAllocEx(hCsgo, nullptr, sizeof(shellcode_packet), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    WriteProcessMemory(hCsgo, pShellcodePacket, &pkt, sizeof(shellcode_packet), nullptr);

    //find a codecave
    size_t iCodecaveSize = 100; //REMEMBER TO CHANGE THIS WHEN MODIFYING THE SHELLCODE
    uintptr_t pCodecave = find_code_cave("KERNELBASE.dll", iCodecaveSize);
    printf(XOR("Found codecave at: %p\n"), pCodecave);

    //write the shellcode to the codecave
    VirtualProtectEx(hCsgo, (LPVOID)pCodecave, iCodecaveSize, PAGE_EXECUTE_READWRITE, &trash2);
    WriteProcessMemory(hCsgo, (LPVOID)pCodecave, shellcode, iCodecaveSize, 0);
    VirtualProtectEx(hCsgo, (LPVOID)pCodecave, iCodecaveSize, PAGE_EXECUTE_READ, &trash2);
    printf(XOR("Injected shellcode!\n"));

    //invoke the shellcode in the codecave
    CreateRemoteThread(hCsgo, 0, 0, (LPTHREAD_START_ROUTINE)pCodecave, pShellcodePacket, 0, 0);

    printf(XOR("Done!\n"));
    Sleep(1000);
    CloseHandle(hCsgo);
}
