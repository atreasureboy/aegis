// Package bof 提供 COFF/BOF 解析和加载。
package bof

import (
	"encoding/binary"
	"fmt"
)

// COFFFile 是完整的 COFF 文件解析结果。
type COFFFile struct {
	Header    *COFFHeader
	Sections  []*COFFSection
	Symbols   []*COFFSymbol
	StringTable []byte
}

// COFFHeader 是 COFF 文件头（20 bytes）。
type COFFHeader struct {
	Machine              uint16 // 0x8664 = x64, 0x14c = x86
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// COFFSection 是 COFF 节表（40 bytes each）。
type COFFSection struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
	Data                 []byte
}

// COFFSymbol 是 COFF 符号表（18 bytes each）。
type COFFSymbol struct {
	Name           [8]byte
	Value          uint32
	SectionNumber  int16
	Type           uint16
	StorageClass   uint8
	NumberOfAuxSymbols uint8
}

// COFFRelocation 是重定位条目（10 bytes each）。
type COFFRelocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

// RelocationType x64 重定位类型。
type RelocationType uint16

const (
	IMAGE_REL_AMD64_ABSOLUTE RelocationType = 0x0000
	IMAGE_REL_AMD64_ADDR64   RelocationType = 0x0001
	IMAGE_REL_AMD64_ADDR32   RelocationType = 0x0002
	IMAGE_REL_AMD64_ADDR32NB RelocationType = 0x0003
	IMAGE_REL_AMD64_REL32    RelocationType = 0x0004
	IMAGE_REL_AMD64_REL32_1  RelocationType = 0x0005
	IMAGE_REL_AMD64_REL32_2  RelocationType = 0x0006
	IMAGE_REL_AMD64_REL32_3  RelocationType = 0x0007
	IMAGE_REL_AMD64_REL32_4  RelocationType = 0x0008
	IMAGE_REL_AMD64_REL32_5  RelocationType = 0x0009
)

// ParseCOFF 解析 COFF 文件。
func ParseCOFF(data []byte) (*COFFFile, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short for COFF header")
	}

	header := &COFFHeader{
		Machine:              binary.LittleEndian.Uint16(data[0:2]),
		NumberOfSections:     binary.LittleEndian.Uint16(data[2:4]),
		TimeDateStamp:        binary.LittleEndian.Uint32(data[4:8]),
		PointerToSymbolTable: binary.LittleEndian.Uint32(data[8:12]),
		NumberOfSymbols:      binary.LittleEndian.Uint32(data[12:16]),
		SizeOfOptionalHeader: binary.LittleEndian.Uint16(data[16:18]),
		Characteristics:      binary.LittleEndian.Uint16(data[18:20]),
	}

	offset := 20
	coff := &COFFFile{Header: header}

	for i := uint16(0); i < header.NumberOfSections; i++ {
		if offset+40 > len(data) {
			return nil, fmt.Errorf("data too short for section %d", i)
		}

		sec := &COFFSection{}
		copy(sec.Name[:], data[offset:offset+8])
		sec.VirtualSize = binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		sec.VirtualAddress = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		sec.SizeOfRawData = binary.LittleEndian.Uint32(data[offset+16 : offset+20])
		sec.PointerToRawData = binary.LittleEndian.Uint32(data[offset+20 : offset+24])
		sec.PointerToRelocations = binary.LittleEndian.Uint32(data[offset+24 : offset+28])
		sec.NumberOfRelocations = binary.LittleEndian.Uint16(data[offset+28 : offset+30])
		sec.Characteristics = binary.LittleEndian.Uint32(data[offset+36 : offset+40])

		if sec.PointerToRawData > 0 && sec.SizeOfRawData > 0 {
			// Check for uint32 overflow and bounds
			if sec.PointerToRawData >= uint32(len(data)) {
				return nil, fmt.Errorf("section %d PointerToRawData (%d) exceeds file size (%d)", i, sec.PointerToRawData, len(data))
			}
			end := sec.PointerToRawData + sec.SizeOfRawData
			if end < sec.PointerToRawData {
				return nil, fmt.Errorf("section %d PointerToRawData+SizeOfRawData overflows", i)
			}
			if end > uint32(len(data)) {
				end = uint32(len(data))
			}
			sec.Data = data[sec.PointerToRawData:end]
		}

		coff.Sections = append(coff.Sections, sec)
		offset += 40
	}

	if header.PointerToSymbolTable > 0 && header.NumberOfSymbols > 0 {
		symOffset := header.PointerToSymbolTable
		for i := uint32(0); i < header.NumberOfSymbols; i++ {
			if symOffset+18 > uint32(len(data)) {
				break
			}

			sym := &COFFSymbol{}
			copy(sym.Name[:], data[symOffset:symOffset+8])
			sym.Value = binary.LittleEndian.Uint32(data[symOffset+8 : symOffset+12])
			sym.SectionNumber = int16(binary.LittleEndian.Uint16(data[symOffset+12 : symOffset+14]))
			sym.Type = binary.LittleEndian.Uint16(data[symOffset+14 : symOffset+16])
			sym.StorageClass = data[symOffset+16]
			sym.NumberOfAuxSymbols = data[symOffset+17]

			coff.Symbols = append(coff.Symbols, sym)
			symOffset += 18

			for j := uint8(0); j < sym.NumberOfAuxSymbols; j++ {
				symOffset += 18
				i++
			}
		}
	}

	coff.StringTable = parseStringTable(data, header.PointerToSymbolTable, header.NumberOfSymbols)

	return coff, nil
}

// GetSymbolName 从符号表获取名称（支持字符串表）。
func (c *COFFFile) GetSymbolName(sym *COFFSymbol) string {
	if sym.Name[0] == 0 {
		offset := binary.LittleEndian.Uint32(sym.Name[1:5])
		start := offset + 4
		if int(start) < len(c.StringTable) {
			end := start
			for end < uint32(len(c.StringTable)) && c.StringTable[end] != 0 {
				end++
			}
			return string(c.StringTable[start:end])
		}
		return ""
	}
	for i, b := range sym.Name {
		if b == 0 {
			return string(sym.Name[:i])
		}
	}
	return string(sym.Name[:])
}

// CalculateMemorySize 计算加载 COFF 所需的总内存大小。
func (c *COFFFile) CalculateMemorySize() uint32 {
	var total uint32
	for _, sec := range c.Sections {
		end := sec.VirtualAddress + sec.VirtualSize
		if end > total {
			total = end
		}
	}
	return total
}

func parseStringTable(data []byte, pointerToSymbolTable uint32, numSymbols uint32) []byte {
	if pointerToSymbolTable == 0 || numSymbols == 0 {
		return nil
	}
	// P2-1: Guard against uint32 overflow in offset calculation
	symbolTableSize := uint64(numSymbols) * 18
	strTableOffset := uint64(pointerToSymbolTable) + symbolTableSize
	if strTableOffset >= uint64(len(data)) {
		return nil
	}
	return data[strTableOffset:]
}
