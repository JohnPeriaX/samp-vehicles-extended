#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>

//#define DEBUG

HMODULE samp_dll = nullptr;


void Log(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

uint8_t* FindPattern(
    uint8_t* base,
    size_t size,
    const uint8_t* pattern,
    const char* mask)
{
    size_t patternLen = strlen(mask);

    for (size_t i = 0; i <= size - patternLen; ++i)
    {
        bool found = true;

        for (size_t j = 0; j < patternLen; ++j)
        {
            if (mask[j] == 'x' && base[i + j] != pattern[j])
            {
                found = false;
                break;
            }
        }

        if (found)
            return base + i;
    }

    return nullptr;
}


void PatchVehicleIdLimit()
{

    Log("SAMP Vehicle ID patch");

    uint8_t* moduleBase = reinterpret_cast<uint8_t*>(samp_dll);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBase + dos->e_lfanew);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);

    uint8_t* textBase = nullptr;
    size_t textSize = 0;

    for(int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if(memcmp(section[i].Name, ".text", 5) == 0)
        {
            textBase = moduleBase + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }

    if(textBase == nullptr || textSize == 0)
    {
        Log(".text section not found");
        return;
    }

    Log("[+] .text section at 0x%p (size: 0x%X)", textBase, (unsigned)textSize);


    uint8_t pattern[] = {
        0x3D, 0x90, 0x01, 0x00, 0x00,
        0x0F, 0x8C, 0x00, 0x00, 0x00, 0x00,
        0x3D, 0x63, 0x02, 0x00, 0x00,
        0x0F, 0x8F, 0x00, 0x00, 0x00, 0x00
    };

    const char* mask = "xxxxxx????xxxxx????";

    uint8_t* match = FindPattern(textBase, textSize, pattern, mask);
    if (!match)
    {
        Log("instruction pattern not found");
        return;
    }

    Log("[+] Pattern found at 0x%p", match);

    uint8_t* jgInstruction = match + 16;

    Log("[+] 'jg' instruction at 0x%p", jgInstruction);
    Log("[+] Bytes before patch: %02X %02X %02X %02X %02X %02X",
        jgInstruction[0], jgInstruction[1], jgInstruction[2],
        jgInstruction[3], jgInstruction[4], jgInstruction[5]);

    if (jgInstruction[0] != 0x0F || jgInstruction[1] != 0x8F)
    {
        Log("instruction mismatch, aborting patch");
        return;
    }

    DWORD oldProtect;

    if(!VirtualProtect(jgInstruction, 6, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        Log("VirtualProtect failed, cannot patch instruction");
        return;
    }

    for(int i = 0; i < 6; i++)
    {
        jgInstruction[i] = 0x90;
    }

    VirtualProtect(jgInstruction, 6, oldProtect, &oldProtect);

    Log("Patch applied succesfully");

    Log("Bytes after patch: %02X %02X %02X %02X %02X %02X",
        jgInstruction[0], jgInstruction[1], jgInstruction[2],
        jgInstruction[3], jgInstruction[4], jgInstruction[5]);

}

void PatchSaa()
{
    Log("Patching samp.dll to avoid overwriting .dat and .cfg files");
    uint8_t* moduleBase = reinterpret_cast<uint8_t*>(samp_dll);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBase+ dos->e_lfanew);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);

    uint8_t* textBase = nullptr;
    size_t textSize = 0;

    for(int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if(memcmp(section[i].Name, ".text", 5) == 0)
        {
            textBase = moduleBase + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }

    const uint8_t pattern[] = 
    {
        0x83, 
        0xC4, 
        0x04, 
        0x50, 
        0xFF, 
        0x57, 
        0x0C, 
        0x83, 
        0xF8, 
        0xFF, 
        0x74, 
        0x66, 
        0x50, 
        0xE8, 
        0x6C, 
        0xFA, 
        0xFF, 
        0xFF, 
        0x56, 
        0x8B, 
        0xF8, 
        0xE8, 
        0x04, 
        0xFE, 
        0xFF, 
        0xFF, 
        0x83, 
        0xC4, 
        0x08, 
        0x8D
    };
    static const char mask[] = "xxxxxxxxxx?xx????xxxx????xxxx";


    uint8_t* match_point = FindPattern(textBase, textSize, pattern, mask);

    if(!match_point)
    {
        Log(".saa patch: Pattern not found");
        return;
    }

    Log(".saa patch: Pattern found at 0x%p", match_point);


    uint8_t* theInstruction = match_point + 10;

    if(theInstruction[0] != 0x74)
    {
        Log(".saa patch: Instruction mismatch, aborting");
        return;
    }

    DWORD oldProtect;

    if(!VirtualProtect(theInstruction, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        Log(".saa patch: VirtualProtect failed!");
        return;
    }
    theInstruction[0] = 0xEB;

    VirtualProtect(theInstruction, 1, oldProtect, &oldProtect);

    Log("Patch applied succesfully!");
    Log("Byte after patch: %02X", theInstruction[0]);
}


DWORD WINAPI PatchThread(LPVOID)
{
    #ifdef DEBUG
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    SetConsoleTitleA("SA-MP Debug Console");
    Log("Console initialized");
    #endif


    Sleep(100);
    PatchSaa();

    Sleep(100);
    PatchVehicleIdLimit();
    
    return 0;
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    samp_dll = GetModuleHandleA("samp.dll");
    if(samp_dll)
    {
        if (reason == DLL_PROCESS_ATTACH)
        {
            DisableThreadLibraryCalls(hinst);
            CreateThread(nullptr, 0, PatchThread, nullptr, 0, nullptr);
        }
    }
    return TRUE;
}
