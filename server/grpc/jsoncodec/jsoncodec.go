// Package jsoncodec 注册 JSON codec 到 gRPC，替代 protobuf 序列化。
// 允许手写 Go 结构体直接用于 gRPC 传输，无需 protoc 生成。
package jsoncodec

import (
	"encoding/json"

	"google.golang.org/grpc/encoding"
)

const name = "json"

// codec 实现 gRPC encoding.Codec 接口。
type codec struct{}

func (codec) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (codec) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func (codec) Name() string {
	return name
}

func init() {
	encoding.RegisterCodec(codec{})
}
