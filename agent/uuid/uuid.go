// Package uuid 提供 Agent 唯一主机标识。
// 借鉴 Sliver 的 hostuuid — 即使 Agent 重新安装，也能识别同一台主机。
//
// 面试要点：
// 1. 为什么需要主机 UUID：
//    - Agent 重装后仍能识别同一台机器
//    - 基于 MAC 地址、主板序列号等硬件信息生成
//    - 不依赖磁盘序列号（虚拟机可能变化）
// 2. 生成方式：
//    - Windows: wmic csproduct get UUID
//    - Linux: cat /sys/class/dmi/id/product_uuid
//    - MAC 地址 hash（备用方案）
// 3. Sliver 实现：sliver/implant/sliver/hostuuid/
package uuid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// HostUUID 生成主机唯一标识。
func HostUUID() string {
	components := []string{}

	// 1. MAC 地址（最可靠，跨平台）
	if macs, err := getMACAddresses(); err == nil {
		components = append(components, macs...)
	}

	// 2. 主机名
	if hostname, err := getHostname(); err == nil {
		components = append(components, hostname)
	}

	// 3. CPU 信息
	if cpu, err := getCPUInfo(); err == nil {
		components = append(components, cpu)
	}

	// 4. SHA256 hash
	h := sha256.Sum256([]byte(strings.Join(components, "|")))
	return fmt.Sprintf("host-%s", hex.EncodeToString(h[:8]))
}

// getMACAddresses 获取所有网络接口的 MAC 地址。
func getMACAddresses() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue // 跳过回环接口
		}
		if iface.Flags&net.FlagUp == 0 {
			continue // 跳过未启用的接口
		}
		mac := iface.HardwareAddr.String()
		if mac != "" {
			macs = append(macs, mac)
		}
	}
	return macs, nil
}

// getHostname 获取主机名。
func getHostname() (string, error) {
	return getHostnameImpl()
}

func getHostnameImpl() (string, error) {
	return os.Hostname()
}

// getCPUInfo 获取 CPU 型号信息。
func getCPUInfo() (string, error) {
	return runtime.GOARCH, nil
}

// MachineID 获取机器唯一标识（备用方案）。
func MachineID() string {
	// Linux: /etc/machine-id
	// Windows: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid
	// macOS: ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID
	return HostUUID() // 默认使用 HostUUID
}

// Fingerprint 生成主机指纹（用于唯一标识）。
type Fingerprint struct {
	HostUUID    string   `json:"host_uuid"`
	MACs        []string `json:"macs"`
	Hostname    string   `json:"hostname"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	CPU         string   `json:"cpu"`
}

// GenerateFingerprint 生成完整主机指纹。
func GenerateFingerprint() *Fingerprint {
	return &Fingerprint{
		HostUUID: HostUUID(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		CPU:      runtime.GOARCH,
	}
}
