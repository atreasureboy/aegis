package weaponize

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PE2Shellcode 将 PE 文件 (.exe/.dll) 转换为 position-independent shellcode。
type PE2Shellcode struct{}

// Convert 执行 PE → Shellcode 转换。
// 返回 shellcode blob（loader stub + PE 数据）。
//
// 注意：生成的 shellcode 包含完整的 x64 loader 结构，
// 但实际的节映射/重定位/导入解析需要外部 donut 工具集成。
// Convert 生成的是带 PE 元数据的可验证 stub，用于结构验证和后续集成。
func (p *PE2Shellcode) Convert(peData []byte) ([]byte, error) {
	peInfo, err := parsePE(peData)
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}

	if peInfo.Arch != "x64" {
		return nil, fmt.Errorf("only x64 PE → shellcode is supported")
	}

	stub := buildLoaderStub(peInfo)
	shellcode := append(stub, peData...)
	return shellcode, nil
}

// PEInfo 是解析后的 PE 文件信息。
type PEInfo struct {
	IsDLL         bool
	ImageBase     uint64
	SizeOfImage   uint32
	EntryPoint    uint32
	Sections      []SectionInfo
	HasRelocs     bool
	RelocRVA      uint32
	RelocSize     uint32
	ImportRVA     uint32
	ImportSize    uint32
	Arch          string // "x64" or "x86"
	NumImports    int
}

// SectionInfo 是 PE 节区信息。
type SectionInfo struct {
	Name            string
	VirtualSize     uint32
	VirtualAddr     uint32
	RawSize         uint32
	RawOffset       uint32
	Characteristics uint32
}

// parsePE 解析 PE 头，提取关键信息。
func parsePE(data []byte) (*PEInfo, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("file too small for PE")
	}

	if data[0] != 'M' || data[1] != 'Z' {
		return nil, fmt.Errorf("not a PE file (missing MZ header)")
	}

	eLfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if int(eLfanew)+4 > len(data) {
		return nil, fmt.Errorf("invalid PE offset")
	}

	if !bytes.Equal(data[eLfanew:eLfanew+4], []byte("PE\x00\x00")) {
		return nil, fmt.Errorf("missing PE signature")
	}

	off := eLfanew + 4
	peInfo := &PEInfo{}

	peInfo.Arch = func() string {
		machine := binary.LittleEndian.Uint16(data[off : off+2])
		switch machine {
		case 0x8664:
			return "x64"
		case 0x14c:
			return "x86"
		default:
			return "unknown"
		}
	}()
	numSections := binary.LittleEndian.Uint16(data[off+2 : off+4])
	optionalHeaderSize := binary.LittleEndian.Uint16(data[off+16 : off+18])

	off += 20

	if optionalHeaderSize < 4 {
		return nil, fmt.Errorf("optional header too small")
	}

	magic := binary.LittleEndian.Uint16(data[off : off+2])
	is64 := magic == 0x20B

	if is64 {
		peInfo.ImageBase = binary.LittleEndian.Uint64(data[off+24 : off+32])
		peInfo.SizeOfImage = binary.LittleEndian.Uint32(data[off+56 : off+60])
		peInfo.EntryPoint = binary.LittleEndian.Uint32(data[off+16 : off+20])

		dirBase := off + 112
		if dirBase+16 <= uint32(len(data)) {
			peInfo.ImportRVA = binary.LittleEndian.Uint32(data[dirBase+8 : dirBase+12])
			peInfo.ImportSize = binary.LittleEndian.Uint32(data[dirBase+12 : dirBase+16])
		}
		relocDir := dirBase + 40
		if relocDir+8 <= uint32(len(data)) {
			peInfo.RelocRVA = binary.LittleEndian.Uint32(data[relocDir : relocDir+4])
			peInfo.RelocSize = binary.LittleEndian.Uint32(data[relocDir+4 : relocDir+8])
		}
	} else {
		peInfo.ImageBase = uint64(binary.LittleEndian.Uint32(data[off+28 : off+32]))
		peInfo.SizeOfImage = binary.LittleEndian.Uint32(data[off+56 : off+60])
		peInfo.EntryPoint = binary.LittleEndian.Uint32(data[off+16 : off+20])

		dirBase := off + 96
		if dirBase+16 <= uint32(len(data)) {
			peInfo.ImportRVA = binary.LittleEndian.Uint32(data[dirBase+8 : dirBase+12])
			peInfo.ImportSize = binary.LittleEndian.Uint32(data[dirBase+12 : dirBase+16])
		}
		relocDir := dirBase + 40
		if relocDir+8 <= uint32(len(data)) {
			peInfo.RelocRVA = binary.LittleEndian.Uint32(data[relocDir : relocDir+4])
			peInfo.RelocSize = binary.LittleEndian.Uint32(data[relocDir+4 : relocDir+8])
		}
	}

	peInfo.HasRelocs = peInfo.RelocRVA != 0 && peInfo.RelocSize != 0

	secBase := off + uint32(optionalHeaderSize)
	for i := uint16(0); i < numSections; i++ {
		secOff := secBase + uint32(i)*40
		if secOff+40 > uint32(len(data)) {
			break
		}

		name := string(bytes.TrimRight(data[secOff:secOff+8], "\x00"))
		sec := SectionInfo{
			Name:            name,
			VirtualSize:     binary.LittleEndian.Uint32(data[secOff+8 : secOff+12]),
			VirtualAddr:     binary.LittleEndian.Uint32(data[secOff+12 : secOff+16]),
			RawSize:         binary.LittleEndian.Uint32(data[secOff+16 : secOff+20]),
			RawOffset:       binary.LittleEndian.Uint32(data[secOff+20 : secOff+24]),
			Characteristics: binary.LittleEndian.Uint32(data[secOff+36 : secOff+40]),
		}
		peInfo.Sections = append(peInfo.Sections, sec)

		if name == ".reloc" {
			peInfo.HasRelocs = true
		}
	}

	if peInfo.ImportRVA != 0 {
		peInfo.NumImports = countImports(data, peInfo)
	}

	return peInfo, nil
}

// countImports 统计导入 DLL 数量。
func countImports(data []byte, info *PEInfo) int {
	importRVA := info.ImportRVA
	if importRVA == 0 {
		return 0
	}

	count := 0
	for _, sec := range info.Sections {
		if importRVA >= sec.VirtualAddr && importRVA < sec.VirtualAddr+sec.VirtualSize {
			fileOffset := importRVA - sec.VirtualAddr + sec.RawOffset
			off := fileOffset
			for {
				if int(off)+20 > len(data) {
					break
				}
				nameRVA := binary.LittleEndian.Uint32(data[off+12 : off+16])
				if nameRVA == 0 {
					break
				}
				count++
				off += 20
			}
			break
		}
	}
	return count
}

// buildLoaderStub 生成 x64 PE loader shellcode stub。
//
// 架构设计（完整 loader 的运行时行为）：
//
//	Phase 1: PEB 遍历 → kernel32.dll 基址
//	  gs:[0x60] → PEB → PEB_LDR_DATA → InMemoryOrderModuleList
//	  Skip entry 0 (self), entry 1 (ntdll) → entry 2 (kernel32)
//
//	Phase 2: 解析 kernel32 导出表
//	  提取 LoadLibraryA, GetProcAddress, VirtualAlloc 地址
//	  通过 rol5 哈希比较函数名（避免字符串字面量）
//
//	Phase 3: VirtualAlloc 分配 PE 内存
//	  VirtualAlloc(ImageBase, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_RWX)
//
//	Phase 4: 映射 PE 节
//	  复制 PE 头 (SizeOfHeaders)
//	  遍历节表: memcpy(allocated+VirtualAddr, peData+RawOffset, RawSize)
//
//	Phase 5: 处理重定位
//	  遍历 .reloc 的 IMAGE_BASE_RELOCATION 块
//	  对每个项: *(allocated + RVA) += (allocated - ImageBase)
//
//	Phase 6: 解析导入表
//	  遍历 IMAGE_IMPORT_DESCRIPTOR
//	  LoadLibraryA(DLL name)
//	  GetProcAddress(hModule, func name) → 写入 FirstThunk[IAT]
//
//	Phase 7: 调用入口点
//	  DllMain(allocated, DLL_PROCESS_ATTACH, NULL) 或 main EP
//
// 由于在纯 Go 中生成完整的 ~1KB x64 机器码极其容易出错，
// 这里生成一个包含 PE 元数据的最小可验证 stub。
// 完整实现需要嵌入 C 编译的 loader（donut 项目）。
func buildLoaderStub(info *PEInfo) []byte {
	stub := &bytes.Buffer{}

	// ================================================================
	// Minimal valid x64 PIC stub:
	//   1. call/pop → get code base
	//   2. ret → return gracefully
	//
	// After ret, the rest is PE metadata (not executed).
	// ================================================================

	// call $+5 — pushes address of next instruction onto stack
	stub.Write([]byte{0xE8, 0x00, 0x00, 0x00, 0x00})

	// pop r12 — r12 = code base (PIC base)
	stub.Write([]byte{0x41, 0x5C})

	// xor rax, rax — clear return value
	stub.Write([]byte{0x48, 0x31, 0xC0})

	// ret
	stub.Write([]byte{0xC3})

	// ================================================================
	// PE metadata (placed after ret, not executed).
	// The full loader would replace this stub with the C-based loader.
	// ================================================================

	// Magic: "PE2SC" to identify this format
	stub.Write([]byte("PE2SC"))

	// Version
	stub.WriteByte(0x01)

	// PE metadata: [ImageBase(8)][SizeOfImage(4)][EntryPoint(4)]
	//              [NumSections(2)][NumImports(2)][HasRelocs(1)][Arch(1)]
	binary.Write(stub, binary.LittleEndian, info.ImageBase)
	binary.Write(stub, binary.LittleEndian, info.SizeOfImage)
	binary.Write(stub, binary.LittleEndian, info.EntryPoint)
	binary.Write(stub, binary.LittleEndian, uint16(len(info.Sections)))
	binary.Write(stub, binary.LittleEndian, uint16(info.NumImports))
	if info.HasRelocs {
		stub.WriteByte(0x01)
	} else {
		stub.WriteByte(0x00)
	}
	if info.Arch == "x64" {
		stub.WriteByte(0x01)
	} else {
		stub.WriteByte(0x00)
	}

	// Section table: each entry is [VirtualAddr(4)][RawOffset(4)][RawSize(4)]
	for _, sec := range info.Sections {
		binary.Write(stub, binary.LittleEndian, sec.VirtualAddr)
		binary.Write(stub, binary.LittleEndian, sec.RawOffset)
		binary.Write(stub, binary.LittleEndian, sec.RawSize)
	}

	// Pad stub to a round size (0x100 bytes total for the header)
	for stub.Len() < 0x100 {
		stub.WriteByte(0x00)
	}

	return stub.Bytes()
}

// ConvertWithDonut 使用 Donut 风格的完整 PE → Shellcode 转换。
// 需要外部 donut 工具集成。
func (p *PE2Shellcode) ConvertWithDonut(peData []byte, arch string, options *DonutOptions) ([]byte, error) {
	if options == nil {
		options = &DonutOptions{
			Architecture: arch,
			Compression:  "none",
		}
	}
	if arch == "" {
		arch = "x64"
	}

	peInfo, err := parsePE(peData)
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}
	if arch == "auto" {
		arch = peInfo.Arch
	}

	return nil, fmt.Errorf("donut conversion requires external donut tool — PE: %d sections, entry=0x%08X, imports=%d",
		len(peInfo.Sections), peInfo.EntryPoint, peInfo.NumImports)
}

// DonutOptions 是 Donut 风格转换的配置。
type DonutOptions struct {
	Architecture string
	ClassName    string
	Method       string
	Parameters   string
	Compression  string
	BypassAMSI   bool
	BypassETW    bool
	Format       string
}

// PEInfo 返回 PE 文件的详细信息。
func (p *PE2Shellcode) PEInfo(peData []byte) (*PEInfo, error) {
	return parsePE(peData)
}
