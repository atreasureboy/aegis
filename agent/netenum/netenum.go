// Package netenum 提供原生 Windows 网络/AD 枚举。
// 参考 Havoc 的 CommandNet（net domain/logons/sessions/computers/share/localgroup/group/user/DC）。
// 使用 NetAPI32.dll 而非调用外部 net.exe 命令。
package netenum

// NetShareInfo 是共享文件夹信息。
type NetShareInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Remark  string `json:"remark"`
	Type    uint32 `json:"type"`
}

// NetUserInfo 是用户信息。
type NetUserInfo struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Comment  string `json:"comment"`
	Flags    uint32 `json:"flags"`
}

// NetGroupInfo 是组信息。
type NetGroupInfo struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
}

// NetSessionInfo 是会话信息。
type NetSessionInfo struct {
	Client  string `json:"client"`
	User    string `json:"user"`
	Time    uint32 `json:"time"`
	Idle    uint32 `json:"idle"`
}

// NetLoggedOnInfo 是登录用户信息。
type NetLoggedOnInfo struct {
	Domain   string `json:"domain"`
	UserName string `json:"username"`
	LogonSrv string `json:"logon_server"`
}

// NetComputerInfo 是计算机信息。
type NetComputerInfo struct {
	Name    string `json:"name"`
	OS      string `json:"os"`
	Domain  string `json:"domain"`
}

// NetConfig 是网络枚举配置。
type NetConfig struct {
	Target string // 目标主机/域 ("" = 本地)
}
