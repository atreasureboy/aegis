package modules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Time constant shared across modules.
const timeRFC3339 = "2006-01-02T15:04:05Z"

// UploadModule 处理文件上传（Server → Agent）。
// 参数格式: "base64_encoded_data destination_path"
func UploadModule(args string) (string, string, int) {
	parts := strings.SplitN(args, " ", 2)
	if len(parts) < 2 {
		return "", "usage: upload <base64_data> <destination_path>", 1
	}

	// F-P1-1: Path traversal prevention — reject paths with ".." components
	cleanPath := filepath.Clean(parts[1])
	if strings.Contains(cleanPath, "..") {
		return "", "upload rejected: path contains '..' (traversal not allowed)", 1
	}

	// F-P1-2: Limit upload size to 50MB to prevent OOM
	data, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Sprintf("base64 decode error: %v", err), 1
	}
	const maxUploadSize = 50 * 1024 * 1024
	if len(data) > maxUploadSize {
		return "", fmt.Sprintf("upload too large: %d bytes (max %d)", len(data), maxUploadSize), 1
	}

	err = os.WriteFile(cleanPath, data, 0644)
	if err != nil {
		return "", fmt.Sprintf("write error: %v", err), 1
	}

	return fmt.Sprintf("uploaded %d bytes to %s", len(data), cleanPath), "", 0
}

// DownloadModule 处理文件下载（Agent → Server）。
// 参数格式: "file_path"
func DownloadModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: download <file_path>", 1
	}

	f, err := os.Open(args)
	if err != nil {
		return "", fmt.Sprintf("open error: %v", err), 1
	}
	defer f.Close()

	// A-P1-14: Limit download size to 50MB to prevent OOM
	const maxDownloadSize = 50 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(f, maxDownloadSize))
	if err != nil {
		return "", fmt.Sprintf("read error: %v", err), 1
	}
	if len(data) >= maxDownloadSize {
		return "", fmt.Sprintf("file too large (>= %d bytes), truncated", maxDownloadSize), 1
	}

	// 返回 base64 编码的内容
	return base64.StdEncoding.EncodeToString(data), "", 0
}

// ChmodModule 修改文件权限（仅 Linux/macOS）。
func ChmodModule(args string) (string, string, int) {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: chmod <mode> <path>", 1
	}

	// Parse mode (e.g., "755")
	var mode int
	fmt.Sscanf(parts[0], "%o", &mode)

	err := os.Chmod(parts[1], os.FileMode(mode))
	if err != nil {
		return "", fmt.Sprintf("chmod error: %v", err), 1
	}

	return fmt.Sprintf("changed %s to %o", parts[1], mode), "", 0
}

// MkdirModule 创建目录。
func MkdirModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: mkdir <path>", 1
	}

	err := os.MkdirAll(args, 0755)
	if err != nil {
		return "", fmt.Sprintf("mkdir error: %v", err), 1
	}

	return fmt.Sprintf("created directory: %s", args), "", 0
}

// RmModule 删除文件或目录。
func RmModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: rm <path>", 1
	}
	clean := filepath.Clean(args)
	if strings.Contains(clean, "..") {
		return "", "rm: path traversal not allowed", 1
	}

	err := os.RemoveAll(clean)
	if err != nil {
		return "", fmt.Sprintf("rm error: %v", err), 1
	}

	return fmt.Sprintf("removed: %s", args), "", 0
}

// MvModule 移动/重命名文件或目录。
func MvModule(args string) (string, string, int) {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: mv <source> <destination>", 1
	}
	src, dst := filepath.Clean(parts[0]), filepath.Clean(parts[1])
	if strings.Contains(src, "..") || strings.Contains(dst, "..") {
		return "", "mv: path traversal not allowed", 1
	}
	if err := os.Rename(src, dst); err != nil {
		return "", fmt.Sprintf("mv error: %v", err), 1
	}
	return fmt.Sprintf("moved %s -> %s", src, dst), "", 0
}

// CpModule 复制文件。
func CpModule(args string) (string, string, int) {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: cp <source> <destination>", 1
	}
	src, dst := parts[0], parts[1]

	srcF, err := os.Open(src)
	if err != nil {
		return "", fmt.Sprintf("open source: %v", err), 1
	}
	defer srcF.Close()

	srcInfo, err := srcF.Stat()
	if err != nil {
		return "", fmt.Sprintf("stat source: %v", err), 1
	}

	dstF, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return "", fmt.Sprintf("create destination: %v", err), 1
	}

	n, err := io.Copy(dstF, srcF)
	dstF.Close()
	if err != nil {
		return "", fmt.Sprintf("copy error: %v", err), 1
	}
	return fmt.Sprintf("copied %d bytes %s -> %s", n, src, dst), "", 0
}

// ChtimesModule 修改文件时间戳。
// Usage: chtimes <path> [access_time] [modify_time]
// Times use RFC3339 format: "2006-01-02T15:04:05Z". If omitted, uses current time.
func ChtimesModule(args string) (string, string, int) {
	parts := strings.Fields(args)
	if len(parts) < 1 {
		return "", "usage: chtimes <path> [access_time] [modify_time]", 1
	}
	path := parts[0]

	now := time.Now()
	atime := now
	mtime := now

	if len(parts) >= 2 {
		t, err := time.Parse(timeRFC3339, parts[1])
		if err != nil {
			return "", fmt.Sprintf("invalid access time: %v", err), 1
		}
		atime = t
	}
	if len(parts) >= 3 {
		t, err := time.Parse(timeRFC3339, parts[2])
		if err != nil {
			return "", fmt.Sprintf("invalid modify time: %v", err), 1
		}
		mtime = t
	}

	if err := os.Chtimes(path, atime, mtime); err != nil {
		return "", fmt.Sprintf("chtimes error: %v", err), 1
	}
	return fmt.Sprintf("updated timestamps on %s", path), "", 0
}

// DownloadDirModule 下载目录（tar+gzip 压缩后返回 base64）。
// Usage: download_dir <directory_path>
func DownloadDirModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: download_dir <directory_path>", 1
	}

	info, err := os.Stat(args)
	if err != nil {
		return "", fmt.Sprintf("stat error: %v", err), 1
	}
	if !info.IsDir() {
		return "", fmt.Sprintf("%s is not a directory", args), 1
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	basePath := filepath.Clean(args)
	err = filepath.Walk(basePath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		relPath, relErr := filepath.Rel(filepath.Dir(basePath), path)
		if relErr != nil {
			relPath = path
		}

		hdr, hdrErr := tar.FileInfoHeader(fi, "")
		if hdrErr != nil {
			return hdrErr
		}
		hdr.Name = filepath.ToSlash(relPath)

		if hdrErr := tw.WriteHeader(hdr); hdrErr != nil {
			return hdrErr
		}

		if fi.IsDir() {
			return nil
		}

		f, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		_, copyErr := io.Copy(tw, f)
		f.Close()
		return copyErr
	})

	if err != nil {
		return "", fmt.Sprintf("tar error: %v", err), 1
	}

	if err := tw.Close(); err != nil {
		return "", fmt.Sprintf("tar close error: %v", err), 1
	}
	if err := gw.Close(); err != nil {
		return "", fmt.Sprintf("gzip close error: %v", err), 1
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), "", 0
}
