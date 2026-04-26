// Package compress 提供 gzip 压缩/解压缩。
// 借鉴 Sliver implant/sliver/cryptography/crypto.go:291-307 的 gzipBuf/gunzipBuf + sync.Pool 模式。
package compress

import (
	"bytes"
	"compress/gzip"
	"io"
	"sync"
)

// gzipWriterPool 复用 gzip.Writer，减少内存分配。
// Sliver 使用相同的 sync.Pool 模式来优化高频压缩场景。
var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		return gzip.NewWriter(nil)
	},
}

// GzipCompress 使用 gzip 压缩数据。
// 使用 sync.Pool 复用 Writer，避免每次分配。
func GzipCompress(data []byte) ([]byte, error) {
	gz := gzipWriterPool.Get().(*gzip.Writer)
	defer gzipWriterPool.Put(gz)

	var buf bytes.Buffer
	gz.Reset(&buf)

	_, err := gz.Write(data)
	if err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// GzipDecompress 解压缩 gzip 数据。
func GzipDecompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// Limit decompressed size to 64MB to prevent zip bomb attacks
	return io.ReadAll(io.LimitReader(r, 64*1024*1024))
}
