// Package registry 提供 Windows 注册表操作。
// 借鉴 Sliver 的 registry (sliver/implant/sliver/registry/) — 原生 Go 注册表读写。
//
// 面试要点：
// 1. 注册表操作在渗透中的作用：
//    - 持久化：Run/RunOnce 键添加启动项
//    - UAC 绕过：修改注册表触发自动提升
//    - 信息收集：SAM 数据库、网络密码等
//    - 后门：注册表路径劫持
// 2. Windows 注册表 Go API：
//    - golang.org/x/sys/windows/registry 包
//    - registry.OpenKey → registry.QueryValue
//    - registry.CreateKey → registry.SetStringValue
// 3. 常用注册表路径：
//    - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (启动项)
//    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run (用户启动项)
//    - HKLM\SYSTEM\CurrentControlSet\Services (服务配置)
package registry

import (
	"encoding/hex"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Hive 是注册表根键。
type Hive string

const (
	ClassesRoot     Hive = "HKCR"
	CurrentUser     Hive = "HKCU"
	LocalMachine    Hive = "HKLM"
	Users           Hive = "HKUS"
	CurrentConfig   Hive = "HKCC"
)

// ValueType 是注册表值类型。
type ValueType int

const (
	String   ValueType = 1 // REG_SZ
	ExpandString ValueType = 2 // REG_EXPAND_SZ
	Binary   ValueType = 3 // REG_BINARY
	DWord    ValueType = 4 // REG_DWORD
	QWord    ValueType = 11 // REG_QWORD
	MultiString ValueType = 7 // REG_MULTI_SZ
)

// Read 读取注册表值，支持所有类型（SZ/DWORD/QWORD/BINARY/MULTISZ）。
func Read(hive Hive, path, name string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("registry operations only available on Windows")
	}

	key, err := openKey(hive, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()

	// 先探测类型
	buf := make([]byte, 1024)
	_, valType, err := key.GetValue(name, buf)
	if err != nil {
		// 缓冲区可能不够，用更大的
		buf = make([]byte, 65536)
		_, valType, err = key.GetValue(name, buf)
		if err != nil {
			return "", err
		}
	}

	switch valType {
	case registry.SZ:
		s, _, err := key.GetStringValue(name)
		return s, err
	case registry.EXPAND_SZ:
		s, _, err := key.GetStringValue(name)
		return s, err
	case registry.DWORD:
		v, _, err := key.GetIntegerValue(name)
		return fmt.Sprintf("%d", v), err
	case registry.QWORD:
		v, _, err := key.GetIntegerValue(name)
		return fmt.Sprintf("%d", v), err
	case registry.BINARY:
		v, _, err := key.GetBinaryValue(name)
		return hex.EncodeToString(v), err
	case registry.MULTI_SZ:
		v, _, err := key.GetStringsValue(name)
		return strings.Join(v, "|"), err
	default:
		s, _, err := key.GetStringValue(name)
		return s, err
	}
}

// Write 写入注册表值。
func Write(hive Hive, path, name string, value string, valueType ValueType) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry operations only available on Windows")
	}

	key, _, err := registry.CreateKey(openHive(hive), path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	switch valueType {
	case String:
		return key.SetStringValue(name, value)
	case ExpandString:
		return key.SetExpandStringValue(name, value)
	case DWord:
		v, _ := strconv.ParseUint(value, 10, 32)
		return key.SetDWordValue(name, uint32(v))
	case QWord:
		v, _ := strconv.ParseUint(value, 10, 64)
		return key.SetQWordValue(name, v)
	case Binary:
		data, err := hex.DecodeString(value)
		if err != nil {
			data = []byte(value)
		}
		return key.SetBinaryValue(name, data)
	case MultiString:
		return key.SetStringsValue(name, []string{value})
	default:
		return key.SetStringValue(name, value)
	}
}

// Delete 删除注册表值。
func Delete(hive Hive, path, name string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry operations only available on Windows")
	}

	key, err := openKey(hive, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	return key.DeleteValue(name)
}

// ListKeys 列出子键。
func ListKeys(hive Hive, path string) ([]string, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("registry operations only available on Windows")
	}

	key, err := openKey(hive, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	return key.ReadSubKeyNames(0)
}

// ListValues 列出值（返回类型+值）。
func ListValues(hive Hive, path string) ([]map[string]string, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("registry operations only available on Windows")
	}

	key, err := openKey(hive, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	names, err := key.ReadValueNames(0)
	if err != nil {
		return nil, err
	}

	result := make([]map[string]string, 0, len(names))
	for _, name := range names {
		entry := map[string]string{"name": name}

		buf := make([]byte, 4096)
		_, valType, err := key.GetValue(name, buf)
		if err != nil {
			entry["error"] = err.Error()
			result = append(result, entry)
			continue
		}

		typeNames := map[uint32]string{
			registry.SZ:       "SZ",
			registry.EXPAND_SZ: "EXPAND_SZ",
			registry.DWORD:    "DWORD",
			registry.QWORD:    "QWORD",
			registry.BINARY:   "BINARY",
			registry.MULTI_SZ: "MULTI_SZ",
		}
		if tn, ok := typeNames[valType]; ok {
			entry["type"] = tn
		} else {
			entry["type"] = fmt.Sprintf("0x%X", valType)
		}

		switch valType {
		case registry.SZ, registry.EXPAND_SZ:
			s, _, _ := key.GetStringValue(name)
			entry["value"] = s
		case registry.DWORD, registry.QWORD:
			v, _, _ := key.GetIntegerValue(name)
			entry["value"] = fmt.Sprintf("%d", v)
		case registry.BINARY:
			v, _, _ := key.GetBinaryValue(name)
			entry["value"] = hex.EncodeToString(v)
		case registry.MULTI_SZ:
			v, _, _ := key.GetStringsValue(name)
			entry["value"] = strings.Join(v, "|")
		default:
			s, _, _ := key.GetStringValue(name)
			entry["value"] = s
		}

		result = append(result, entry)
	}
	return result, nil
}

// CreateKey 创建注册表项（整个 key，非单个值）。
func CreateKey(hive Hive, path string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry operations only available on Windows")
	}
	key, _, err := registry.CreateKey(openHive(hive), path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	return key.Close()
}

// DeleteKey 删除注册表项及其所有子项/值（递归）。
func DeleteKey(hive Hive, path string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("registry operations only available on Windows")
	}
	return registry.DeleteKey(openHive(hive), path)
}

// Persist 添加持久化启动项。
func Persist(name, cmdPath string, currentUser bool) error {
	var path string
	var hive Hive
	if currentUser {
		path = `Software\Microsoft\Windows\CurrentVersion\Run`
		hive = CurrentUser
	} else {
		path = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
		hive = LocalMachine
	}

	return Write(hive, path, name, cmdPath, String)
}

// RemovePersist 移除持久化启动项。
func RemovePersist(name string, currentUser bool) error {
	var path string
	var hive Hive
	if currentUser {
		path = `Software\Microsoft\Windows\CurrentVersion\Run`
		hive = CurrentUser
	} else {
		path = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
		hive = LocalMachine
	}

	return Delete(hive, path, name)
}

// KnownPersistencePaths 是常见的持久化注册表路径。
var KnownPersistencePaths = map[string]string{
	"Run":                  `Software\Microsoft\Windows\CurrentVersion\Run`,
	"RunOnce":              `Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	"Run (HKLM)":           `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	"Services":             `SYSTEM\CurrentControlSet\Services`,
	"Winlogon":             `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	"BootExecute":          `SYSTEM\CurrentControlSet\Control\Session Manager`,
	"ImageFileExecution":   `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
}

// ParsePath 解析完整注册表路径。
func ParsePath(fullPath string) (Hive, string) {
	parts := strings.SplitN(fullPath, `\`, 2)
	if len(parts) < 2 {
		return LocalMachine, fullPath
	}

	var hive Hive
	switch strings.ToUpper(parts[0]) {
	case "HKCR", "HKEY_CLASSES_ROOT":
		hive = ClassesRoot
	case "HKCU", "HKEY_CURRENT_USER":
		hive = CurrentUser
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hive = LocalMachine
	case "HKUS", "HKEY_USERS":
		hive = Users
	default:
		hive = LocalMachine
	}

	return hive, parts[1]
}

// openHive 返回 registry.Key 根键。
func openHive(h Hive) registry.Key {
	switch h {
	case ClassesRoot:
		return registry.CLASSES_ROOT
	case CurrentUser:
		return registry.CURRENT_USER
	case LocalMachine:
		return registry.LOCAL_MACHINE
	case Users:
		return registry.USERS
	case CurrentConfig:
		return registry.CURRENT_CONFIG
	default:
		return registry.LOCAL_MACHINE
	}
}

// openKey 打开指定路径的注册表键。
func openKey(hive Hive, path string, access uint32) (registry.Key, error) {
	return registry.OpenKey(openHive(hive), path, access)
}
