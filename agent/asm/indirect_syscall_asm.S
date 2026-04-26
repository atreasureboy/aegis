//go:build windows && amd64 && cgo

/*
 * indirect_syscall_asm.S — Pure GAS assembly for indirect syscall on x64 Windows.
 *
 * Compiled by MinGW-w64 GCC as part of CGO build.
 *
 * Two entry points:
 *   indirect_syscall_asm  — up to 4 syscall args (≤4 params after ssn)
 *   indirect_syscall_do   — up to 11 syscall args (supports NtCreateThreadEx etc.)
 *
 * Windows x64 calling convention on entry (from C caller):
 *   rcx = param1 (syscallNum)
 *   rdx = param2 (a1)
 *   r8  = param3 (a2)
 *   r9  = param4 (a3)
 *   [rsp+0x20] = param5  (a4)
 *   [rsp+0x28] = param6  (a5)
 *   [rsp+0x30] = param7  (a6)
 *   ...
 *
 * Windows NT syscall convention (what kernel expects):
 *   eax  = SSN
 *   r10  = syscall arg1   (NOT rcx — syscall clobbers rcx with RIP)
 *   rdx  = syscall arg2
 *   r8   = syscall arg3
 *   r9   = syscall arg4
 *   [rsp+0x28] = syscall arg5  (note: offset 0x28, not 0x20)
 *   [rsp+0x30] = syscall arg6
 *   ...
 *
 * The register shuffle (C args → syscall args):
 *   eax  ← ecx  (SSN from param1)
 *   r10  ← rdx  (a1  from param2)
 *   rdx  ← r8   (a2  from param3)
 *   r8   ← r9   (a3  from param4)
 *   r9   ← [rsp+0x20] (a4 from param5)
 *   [rsp+0x28] = a5 — already in the right place for the kernel ✓
 *   [rsp+0x30] = a6 — already in the right place for the kernel ✓
 *   ...
 *
 * Gadget address is loaded from the global variable syscall_gadget (defined in .c file).
 * For indirect_syscall_do the gadget is passed as the last C parameter instead,
 * because indirect_syscall_do is called from C with a local gadget copy.
 */

#if defined(_WIN64)

.extern syscall_gadget

.text

/* -----------------------------------------------------------------------
 * indirect_syscall_asm — fast path for syscalls with ≤4 arguments.
 *
 * C signature:
 *   long long indirect_syscall_asm(uint ssn, u64 a1, u64 a2, u64 a3, u64 a4);
 *   (a4 arrives at [rsp+0x20], the 5th Windows x64 parameter slot)
 * ----------------------------------------------------------------------- */
.globl indirect_syscall_asm
indirect_syscall_asm:
    movl  %ecx, %eax           /* eax  = SSN                        */
    movq  %rdx, %r10           /* r10  = a1  (param2 rdx)           */
    movq  %r8,  %rdx           /* rdx  = a2  (param3 r8)            */
    movq  %r9,  %r8            /* r8   = a3  (param4 r9)            */
    movq  0x20(%rsp), %r9      /* r9   = a4  (param5 stack slot)    */
    movq  syscall_gadget(%rip), %r11
    jmp   *%r11
    movl  $-1, %eax
    ret


/* -----------------------------------------------------------------------
 * indirect_syscall_do — full-width path for syscalls with up to 11 args.
 *
 * C signature:
 *   long long indirect_syscall_do(
 *       uint ssn,
 *       u64 a1,  u64 a2,  u64 a3,  u64 a4,   // params 2-5
 *       u64 a5,  u64 a6,  u64 a7,  u64 a8,   // params 6-9  → [rsp+0x28..0x48]
 *       u64 a9,  u64 a10, u64 a11,            // params 10-12 → [rsp+0x50..0x60]
 *       u64 gadget                             // param 13    → [rsp+0x68]
 *   );
 *
 * Stack layout on entry (after C caller's CALL pushes return addr):
 *   [rsp+0x00] = return address
 *   [rsp+0x08] = shadow[rcx]
 *   [rsp+0x10] = shadow[rdx]
 *   [rsp+0x18] = shadow[r8]
 *   [rsp+0x20] = a4      (param5)
 *   [rsp+0x28] = a5      (param6)  ← kernel syscall arg5
 *   [rsp+0x30] = a6      (param7)  ← kernel syscall arg6
 *   [rsp+0x38] = a7      (param8)  ← kernel syscall arg7
 *   [rsp+0x40] = a8      (param9)  ← kernel syscall arg8
 *   [rsp+0x48] = a9      (param10) ← kernel syscall arg9
 *   [rsp+0x50] = a10     (param11) ← kernel syscall arg10
 *   [rsp+0x58] = a11     (param12) ← kernel syscall arg11
 *   [rsp+0x60] = gadget  (param13)
 *
 * After register shuffle, syscall args 5-11 are already at the correct
 * stack offsets ([rsp+0x28..0x58]) as required by the NT syscall ABI.
 * ----------------------------------------------------------------------- */
.globl indirect_syscall_do
indirect_syscall_do:
    movl  %ecx, %eax           /* eax  = SSN                        */
    movq  %rdx, %r10           /* r10  = a1  (param2 rdx)           */
    movq  %r8,  %rdx           /* rdx  = a2  (param3 r8)            */
    movq  %r9,  %r8            /* r8   = a3  (param4 r9)            */
    movq  0x20(%rsp), %r9      /* r9   = a4  (param5 stack)         */
    /* a5..a11 already sit at [rsp+0x28..0x58] — kernel reads them  */
    movq  0x60(%rsp), %r11     /* r11  = gadget (param13 stack)     */
    jmp   *%r11
    movl  $-1, %eax
    ret

#endif
