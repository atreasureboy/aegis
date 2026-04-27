//go:build windows && amd64

#include <windows.h>

// BOF Beacon 输出回调（Go 函数由 CGO 调用）
extern void beacon_output(int type, char* data, int len);

LPVOID bof_alloc(SIZE_T size) {
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

BOOL bof_protect(LPVOID addr, SIZE_T size, DWORD protect, PDWORD oldProtect) {
    return VirtualProtect(addr, size, protect, oldProtect);
}

BOOL bof_free(LPVOID addr) {
    return VirtualFree(addr, 0, MEM_RELEASE);
}

void bof_call_entry(LPVOID entry, char* args, int args_len) {
    if (entry && args) {
        ((void(*)(char*, int))(entry))(args, args_len);
    }
}

// BeaconPrintf stub for BOF compatibility
void BeaconPrintf(int type, char* fmt, ...) {
    // Simple stub: BOFs that call BeaconPrintf will get no output.
    // Real output goes through beacon_output via __imp_BeaconOutput.
}

// Beacon API wrappers — forward to Go implementations via _impl symbols.
// These are the actual function addresses returned to BOFs.
extern int  beacon_use_token_impl(HANDLE token);
extern int  beacon_revert_token_impl(void);
extern int  beacon_is_admin_impl(void);
extern void beacon_cleanup_process_impl(HANDLE process);
extern void beacon_get_spawn_to_impl(char* buf, int buf_len);

int beacon_use_token(HANDLE token)       { return beacon_use_token_impl(token); }
int beacon_revert_token(void)            { return beacon_revert_token_impl(); }
int beacon_is_admin(void)                { return beacon_is_admin_impl(); }
void beacon_cleanup_process(HANDLE h)    { beacon_cleanup_process_impl(h); }
void beacon_get_spawn_to(char* b, int l) { beacon_get_spawn_to_impl(b, l); }
