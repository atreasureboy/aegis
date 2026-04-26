// Package transfer 提供分块文件传输支持。
// 借鉴 Sliver 的文件上传/下载机制：大文件分块传输，通过 C2 通道转发。
package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// ChunkSize 是分块传输的大小（1MB）。
const ChunkSize = 1024 * 1024

// UploadTask 是文件上传任务的描述。
type UploadTask struct {
	FileID     string
	FilePath   string
	TotalSize  int64
	ChunkCount int
	Checksum   string
}

// DownloadTask 是文件下载任务的描述。
type DownloadTask struct {
	FileID     string
	FilePath   string
	TotalSize  int64
	ChunkCount int
}

// Chunk 是一个文件分块。
type Chunk struct {
	FileID    string
	Index     int
	Data      []byte
	IsLast    bool
}

// UploadFile 将文件分块上传（模拟实现）。
func UploadFile(path string) (*UploadTask, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	io.Copy(h, f)
	checksum := hex.EncodeToString(h.Sum(nil))

	totalSize := info.Size()
	chunkCount := int((totalSize + ChunkSize - 1) / ChunkSize)

	return &UploadTask{
		FilePath:   path,
		TotalSize:  totalSize,
		ChunkCount: chunkCount,
		Checksum:   checksum,
	}, nil
}

// ReadChunk 读取文件的指定分块。
func ReadChunk(path string, index int) (*Chunk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	offset := int64(index) * ChunkSize
	f.Seek(offset, io.SeekStart)

	buf := make([]byte, ChunkSize)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return &Chunk{
		Index:  index,
		Data:   buf[:n],
		IsLast: n < ChunkSize,
	}, nil
}
