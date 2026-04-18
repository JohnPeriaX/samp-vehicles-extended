//
// samp_patch.cpp  —  SA-MP 0.3.7-R3 vehicle-limit + SAA patch
//
// Strategy: hook LoadLibraryA/W so we intercept the exact moment
// samp.dll is mapped into the process, then patch before it runs
// any init code that uses the vehicle-ID limits.
//
// Build (MinGW 32-bit):
//   i686-w64-mingw32-g++ -shared -o samp_patch.asi samp_patch.cpp
//       -O2 -std=c++17 -static -static-libgcc -static-libstdc++ -lkernel32
//
// Place samp_patch.asi in the GTA San Andreas root folder.
//

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

// ── Config ────────────────────────────────────────────────────────────────────
static const uint32_t NEW_LIMIT = 26000;
// ─────────────────────────────────────────────────────────────────────────────

// ── Verified RVAs from samp.dll 0.3.7-R3 (ImageBase 0x10000000) ──────────────
//   Main check:  cmp eax,0x190 / jl / cmp eax,0x263 / jg
static const uint32_t RVA_MAIN_CMP_IMM  = 0x0000E40E;
static const uint32_t RVA_MAIN_JG       = 0x0000E412;
//   Pool-getter checks x4
static const uint32_t RVA_POOL_CMP[4]   = { 0x000A5462, 0x000A5502, 0x000A55A2, 0x000A5642 };
static const uint32_t RVA_POOL_JG[4]    = { 0x000A5466, 0x000A5506, 0x000A55A6, 0x000A5646 };
//   SAA / file-overwrite:  je -> jmp
//static const uint32_t RVA_SAA_JE        = 0x0006240C;
// ─────────────────────────────────────────────────────────────────────────────

static decltype(&LoadLibraryA)   pfn_LoadLibraryA   = nullptr;
static decltype(&LoadLibraryW)   pfn_LoadLibraryW   = nullptr;
static decltype(&LoadLibraryExA) pfn_LoadLibraryExA = nullptr;
static decltype(&LoadLibraryExW) pfn_LoadLibraryExW = nullptr;

static bool g_patched = false;

// ── Patch helpers ─────────────────────────────────────────────────────────────

static void WriteBytes(void* addr, const void* src, size_t len)
{
    DWORD old;
    VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, src, len);
    VirtualProtect(addr, len, old, &old);
}

static bool VerifyAndWrite(uint8_t* base, uint32_t rva,
                           const uint8_t* expected, size_t expLen,
                           const uint8_t* patch,    size_t patchLen,
                           const char* label)
{
    uint8_t* ptr = base + rva;
    if (memcmp(ptr, expected, expLen) != 0)
    {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "[samp_patch] SKIP %s @ RVA 0x%X – bytes mismatch\n", label, rva);
        OutputDebugStringA(msg);
        return false;
    }
    WriteBytes(ptr, patch, patchLen);
    char msg[256];
    snprintf(msg, sizeof(msg), "[samp_patch] OK   %s @ RVA 0x%X\n", label, rva);
    OutputDebugStringA(msg);
    return true;
}

static void PatchSamp(HMODULE hSamp)
{
    if (g_patched) return;
    g_patched = true;

    uint8_t* base = reinterpret_cast<uint8_t*>(hSamp);

    char msg[128];
    snprintf(msg, sizeof(msg), "[samp_patch] Patching samp.dll @ 0x%p\n", base);
    OutputDebugStringA(msg);

    // SAA: je -> jmp
    /*{
        uint8_t exp[1] = { 0x74 }, pat[1] = { 0xEB };
        VerifyAndWrite(base, RVA_SAA_JE, exp, 1, pat, 1, "SAA je->jmp");
    }*/

    // Main cmp immediate
    {
        uint8_t exp[4] = { 0x63, 0x02, 0x00, 0x00 };
        uint8_t pat[4]; memcpy(pat, &NEW_LIMIT, 4);
        VerifyAndWrite(base, RVA_MAIN_CMP_IMM, exp, 4, pat, 4, "main cmp imm");
    }

    // Main jg -> NOP x6
    {
        uint8_t exp[2] = { 0x0F, 0x8F };
        uint8_t pat[6] = { 0x90,0x90,0x90,0x90,0x90,0x90 };
        VerifyAndWrite(base, RVA_MAIN_JG, exp, 2, pat, 6, "main jg NOP");
    }

    // Pool getters x4
    for (int i = 0; i < 4; ++i)
    {
        char lbl[64];

        snprintf(lbl, sizeof(lbl), "pool[%d] cmp imm", i);
        uint8_t exp_c[4] = { 0x63, 0x02, 0x00, 0x00 };
        uint8_t pat_c[4]; memcpy(pat_c, &NEW_LIMIT, 4);
        VerifyAndWrite(base, RVA_POOL_CMP[i], exp_c, 4, pat_c, 4, lbl);

        snprintf(lbl, sizeof(lbl), "pool[%d] jg NOP", i);
        uint8_t exp_j[1] = { 0x7F };
        uint8_t pat_j[2] = { 0x90, 0x90 };
        VerifyAndWrite(base, RVA_POOL_JG[i], exp_j, 1, pat_j, 2, lbl);
    }

    OutputDebugStringA("[samp_patch] Done.\n");
}

// ── IAT hook helpers ──────────────────────────────────────────────────────────

static bool IsSampDll(const char* name)
{
    if (!name) return false;
    const char* last = name;
    for (const char* p = name; *p; ++p)
        if (*p == '\\' || *p == '/') last = p + 1;
    return _stricmp(last, "samp.dll") == 0;
}

static bool IsSampDllW(const wchar_t* name)
{
    if (!name) return false;
    const wchar_t* last = name;
    for (const wchar_t* p = name; *p; ++p)
        if (*p == L'\\' || *p == L'/') last = p + 1;
    return _wcsicmp(last, L"samp.dll") == 0;
}

static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR name)
{
    HMODULE h = pfn_LoadLibraryA(name);
    if (h && IsSampDll(name)) PatchSamp(h);
    return h;
}

static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR name)
{
    HMODULE h = pfn_LoadLibraryW(name);
    if (h && IsSampDllW(name)) PatchSamp(h);
    return h;
}

static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR name, HANDLE hf, DWORD fl)
{
    HMODULE h = pfn_LoadLibraryExA(name, hf, fl);
    if (h && IsSampDll(name)) PatchSamp(h);
    return h;
}

static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR name, HANDLE hf, DWORD fl)
{
    HMODULE h = pfn_LoadLibraryExW(name, hf, fl);
    if (h && IsSampDllW(name)) PatchSamp(h);
    return h;
}

static void HookIAT(HMODULE hMod, const char* importDll,
                    const char* funcName, void* newFunc)
{
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    DWORD impRVA = nt->OptionalHeader
                     .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRVA) return;

    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + impRVA);
    for (; desc->Name; ++desc)
    {
        if (_stricmp(reinterpret_cast<const char*>(base + desc->Name), importDll) != 0)
            continue;

        auto* orig = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
        auto* iat  = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);

        for (; orig->u1.AddressOfData; ++orig, ++iat)
        {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;
            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                            base + orig->u1.AddressOfData);
            if (strcmp(reinterpret_cast<const char*>(ibn->Name), funcName) != 0)
                continue;

            DWORD old;
            VirtualProtect(&iat->u1.Function, sizeof(DWORD), PAGE_READWRITE, &old);
            iat->u1.Function = reinterpret_cast<ULONG_PTR>(newFunc);
            VirtualProtect(&iat->u1.Function, sizeof(DWORD), old, &old);
            return;
        }
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

static DWORD WINAPI InitThread(LPVOID)
{
    // Already loaded?
    HMODULE hSamp = GetModuleHandleA("samp.dll");
    if (hSamp) { PatchSamp(hSamp); return 0; }

    // Hook IAT of gta_sa.exe so we catch the LoadLibrary call for samp.dll
    HMODULE hExe = GetModuleHandleA(nullptr);

    pfn_LoadLibraryA   = LoadLibraryA;
    pfn_LoadLibraryW   = LoadLibraryW;
    pfn_LoadLibraryExA = LoadLibraryExA;
    pfn_LoadLibraryExW = LoadLibraryExW;

    HookIAT(hExe, "kernel32.dll", "LoadLibraryA",   Hook_LoadLibraryA);
    HookIAT(hExe, "kernel32.dll", "LoadLibraryW",   Hook_LoadLibraryW);
    HookIAT(hExe, "kernel32.dll", "LoadLibraryExA", Hook_LoadLibraryExA);
    HookIAT(hExe, "kernel32.dll", "LoadLibraryExW", Hook_LoadLibraryExW);

    OutputDebugStringA("[samp_patch] IAT hooked, waiting for samp.dll...\n");

    // Fallback poll (60s) in case samp.dll loads via non-IAT path
    for (int i = 0; i < 600 && !g_patched; ++i)
    {
        Sleep(100);
        HMODULE h = GetModuleHandleA("samp.dll");
        if (h) { OutputDebugStringA("[samp_patch] fallback poll hit\n"); PatchSamp(h); }
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    return TRUE;
}
