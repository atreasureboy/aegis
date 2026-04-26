/*
 * pe.h — Shared PE parsing utilities for Windows C code.
 *
 * Uses raw byte offsets instead of typed IMAGE_* structures for
 * cross-compiler portability (works with both MSVC and MinGW-w64).
 *
 * ARCH-3: Deduplicated from agent/asm/indirect_syscall.c, agent/asm/spoofcall.c,
 *         agent/sleep/ekko.c, agent/spoof/stack_spoof.c.
 */
#ifndef AEGIS_PE_H
#define AEGIS_PE_H

#include <windows.h>

/* pe_is_valid — quick sanity check on DOS header */
static __inline int pe_is_valid(const unsigned char *base) {
    return base && base[0] == 'M' && base[1] == 'Z';
}

/* pe_find_section — find section by name, writes rva/size. Returns 0 on success, -1 on failure. */
static __inline int pe_find_section(const unsigned char *base, const char *name,
                                     unsigned int *outRVA, unsigned int *outSize) {
    if (!pe_is_valid(base)) return -1;

    int e_lfanew = *(const int *)(base + 0x3C);
    unsigned char *nt = (unsigned char *)(base + e_lfanew);

    /* PE signature */
    if (nt[0] != 'P' || nt[1] != 'E') return -1;

    /* NumberOfSections at nt+6 (COFF header +2) */
    unsigned short numSections = *(unsigned short *)(nt + 6);
    /* SizeOfOptionalHeader at nt+20 (COFF header +16) */
    unsigned short sizeOfOptHeader = *(unsigned short *)(nt + 20);

    /* Section table starts after NT signature (4) + COFF header (20) + OptionalHeader */
    unsigned char *secTable = nt + 4 + 20 + sizeOfOptHeader;

    for (unsigned short i = 0; i < numSections; i++) {
        unsigned char *sec = secTable + (i * 40);
        /* Match section name (max 8 bytes) */
        int match = 1;
        for (int j = 0; j < 8; j++) {
            if (sec[j] != name[j]) { match = 0; break; }
            if (name[j] == '\0') break;
        }
        if (match) {
            *outRVA  = *(unsigned int *)(sec + 12); /* VirtualAddress */
            *outSize = *(unsigned int *)(sec + 8);  /* VirtualSize */
            return 0;
        }
    }
    return -1;
}

/* pe_get_module_base — get HMODULE of current module via GetModuleHandleEx */
static __inline HMODULE pe_get_module_base(void) {
    HMODULE hMod = NULL;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)pe_get_module_base, &hMod))
        return NULL;
    return hMod;
}

#endif /* AEGIS_PE_H */
