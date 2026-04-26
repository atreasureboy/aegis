package shared

import (
	"encoding/binary"
	"fmt"
)

// ExtractIDAT 从 PNG 数据中提取第一个 IDAT chunk 数据。
func ExtractIDAT(pngData []byte) ([]byte, error) {
	pos := 8 // Skip PNG signature

	for pos < len(pngData)-4 {
		if pos+4 > len(pngData) {
			break
		}
		length := binary.BigEndian.Uint32(pngData[pos:])
		pos += 4

		if pos+4 > len(pngData) {
			break
		}
		chunkType := string(pngData[pos : pos+4])
		pos += 4

		if pos+int(length) > len(pngData) {
			break
		}
		chunkData := pngData[pos : pos+int(length)]
		pos += int(length)

		// Skip CRC
		pos += 4

		if chunkType == "IDAT" {
			return chunkData, nil
		}
	}

	return nil, fmt.Errorf("IDAT chunk not found")
}

// ExtractLSB 从像素数据中提取 LSB 比特（跳过每行 filter byte）。
func ExtractLSB(pixels []byte, width int) []byte {
	bits := make([]byte, 0, len(pixels)*3/4)
	rowBytes := width * 3

	for i := 0; i < len(pixels); {
		// Skip filter byte
		i++
		// Read one row of pixels
		end := i + rowBytes
		if end > len(pixels) {
			end = len(pixels)
		}
		for j := i; j < end; j++ {
			bits = append(bits, pixels[j]&1)
		}
		i = end
	}

	return bits
}

// BitsToBytes 将比特流重组为字节。
func BitsToBytes(bits []byte) []byte {
	n := len(bits) / 8
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b = (b << 1) | bits[i*8+j]
		}
		result[i] = b
	}
	return result
}

// BytesToBits 将字节流转为比特（MSB first）。
func BytesToBits(data []byte) []byte {
	bits := make([]byte, 0, len(data)*8)
	for _, b := range data {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>uint(i))&1)
		}
	}
	return bits
}

// ReadPNGWidth 从 PNG 数据解析 IHDR chunk 获取宽度。
func ReadPNGWidth(pngData []byte) int {
	if len(pngData) < 20 {
		return 800
	}
	return int(binary.BigEndian.Uint32(pngData[16:20]))
}
