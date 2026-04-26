//go:build windows && amd64

package netenum

import (
	"fmt"
	"syscall"
	"unsafe"
)

// NetAPI32.dll procs
var (
	netapi32 = syscall.NewLazyDLL("netapi32.dll")

	procNetShareEnum     = netapi32.NewProc("NetShareEnum")
	procNetShareGetInfo  = netapi32.NewProc("NetShareGetInfo")
	procNetUserEnum      = netapi32.NewProc("NetUserEnum")
	procNetGroupEnum     = netapi32.NewProc("NetGroupEnum")
	procNetGroupGetUsers = netapi32.NewProc("NetGroupGetUsers")
	procNetWkstaUserEnum = netapi32.NewProc("NetWkstaUserEnum")
	procNetSessionEnum   = netapi32.NewProc("NetSessionEnum")
	procNetServerEnum    = netapi32.NewProc("NetServerEnum")
	procNetApiBufferFree = netapi32.NewProc("NetApiBufferFree")

	// DsGetDcNameW for domain controller lookup
	procDsGetDcName = netapi32.NewProc("DsGetDcNameW")
)

const (
	MAX_PREFERRED_LENGTH = 0xFFFFFFFF
	NERR_Success         = 0
)

// utf16PtrToString converts a UTF-16 pointer to a Go string.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	// Walk the string to find length
	var n int
	for pp := p; *pp != 0; pp = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(pp)) + 2)) {
		n++
	}
	if n == 0 {
		return ""
	}
	return syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(p))[:n:n])
}

// freeNetAPIBuffer releases memory allocated by NetAPI functions.
func freeNetAPIBuffer(ptr uintptr) error {
	ret, _, _ := procNetApiBufferFree.Call(ptr)
	if ret != 0 {
		return fmt.Errorf("NetApiBufferFree: %d", ret)
	}
	return nil
}

// EnumShares enumerates SMB shares on the target host.
func EnumShares(server string) ([]NetShareInfo, error) {
	var bufPtr uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	serverPtr, _ := syscall.UTF16PtrFromString(server)

	ret, _, _ := procNetShareEnum.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		2,
		uintptr(unsafe.Pointer(&bufPtr)),
		MAX_PREFERRED_LENGTH,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != NERR_Success && ret != 259 {
		return nil, fmt.Errorf("NetShareEnum: %d", ret)
	}
	defer freeNetAPIBuffer(bufPtr)

	type shareInfo2 struct {
		Netname *uint16
		Type    uint32
		Remark  *uint16
	}

	shares := make([]NetShareInfo, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		si := (*shareInfo2)(unsafe.Pointer(bufPtr + uintptr(i)*unsafe.Sizeof(shareInfo2{})))
		shares = append(shares, NetShareInfo{
			Name:   utf16PtrToString(si.Netname),
			Type:   si.Type,
			Remark: utf16PtrToString(si.Remark),
		})
	}
	return shares, nil
}

// EnumUsers enumerates local or remote users.
func EnumUsers(server string) ([]NetUserInfo, error) {
	var bufPtr uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	serverPtr, _ := syscall.UTF16PtrFromString(server)

	ret, _, _ := procNetUserEnum.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		1,
		0,
		uintptr(unsafe.Pointer(&bufPtr)),
		MAX_PREFERRED_LENGTH,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != NERR_Success && ret != 259 {
		return nil, fmt.Errorf("NetUserEnum: %d", ret)
	}
	defer freeNetAPIBuffer(bufPtr)

	type userInfo1 struct {
		Name     *uint16
		Comment  *uint16
		Flags    uint32
		FullName *uint16
	}

	users := make([]NetUserInfo, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		ui := (*userInfo1)(unsafe.Pointer(bufPtr + uintptr(i)*unsafe.Sizeof(userInfo1{})))
		users = append(users, NetUserInfo{
			Name:     utf16PtrToString(ui.Name),
			Comment:  utf16PtrToString(ui.Comment),
			Flags:    ui.Flags,
			FullName: utf16PtrToString(ui.FullName),
		})
	}
	return users, nil
}

// EnumGroups enumerates local groups.
func EnumGroups(server string) ([]NetGroupInfo, error) {
	var bufPtr uintptr
	var entriesRead, totalEntries uint32

	serverPtr, _ := syscall.UTF16PtrFromString(server)

	ret, _, _ := procNetGroupEnum.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		1,
		uintptr(unsafe.Pointer(&bufPtr)),
		MAX_PREFERRED_LENGTH,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0,
	)
	if ret != NERR_Success && ret != 259 {
		return nil, fmt.Errorf("NetGroupEnum: %d", ret)
	}
	defer freeNetAPIBuffer(bufPtr)

	type groupInfo1 struct {
		Name    *uint16
		Comment *uint16
	}

	groups := make([]NetGroupInfo, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		gi := (*groupInfo1)(unsafe.Pointer(bufPtr + uintptr(i)*unsafe.Sizeof(groupInfo1{})))
		groups = append(groups, NetGroupInfo{
			Name:    utf16PtrToString(gi.Name),
			Comment: utf16PtrToString(gi.Comment),
		})
	}
	return groups, nil
}

// EnumGroupMembers enumerates members of a specific group.
func EnumGroupMembers(server, group string) ([]string, error) {
	var bufPtr uintptr
	var entriesRead, totalEntries uint32

	serverPtr, _ := syscall.UTF16PtrFromString(server)
	groupPtr, _ := syscall.UTF16PtrFromString(group)

	ret, _, _ := procNetGroupGetUsers.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		uintptr(unsafe.Pointer(groupPtr)),
		0,
		uintptr(unsafe.Pointer(&bufPtr)),
		MAX_PREFERRED_LENGTH,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
	)
	if ret != NERR_Success && ret != 259 {
		return nil, fmt.Errorf("NetGroupGetUsers(%s): %d", group, ret)
	}
	defer freeNetAPIBuffer(bufPtr)

	type groupUsersInfo0 struct {
		Name *uint16
	}

	members := make([]string, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		gui := (*groupUsersInfo0)(unsafe.Pointer(bufPtr + uintptr(i)*unsafe.Sizeof(groupUsersInfo0{})))
		members = append(members, utf16PtrToString(gui.Name))
	}
	return members, nil
}

// EnumSessions enumerates active sessions on the target.
func EnumSessions(server string) ([]NetSessionInfo, error) {
	var bufPtr uintptr
	var entriesRead, totalEntries uint32

	serverPtr, _ := syscall.UTF16PtrFromString(server)

	ret, _, _ := procNetSessionEnum.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		0, 0, 0,
		10,
		uintptr(unsafe.Pointer(&bufPtr)),
		MAX_PREFERRED_LENGTH,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
	)
	if ret != NERR_Success && ret != 259 {
		return nil, fmt.Errorf("NetSessionEnum: %d", ret)
	}
	defer freeNetAPIBuffer(bufPtr)

	type sessionInfo10 struct {
		Client   *uint16
		UserName *uint16
		Time     uint32
		Idle     uint32
	}

	sessions := make([]NetSessionInfo, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		si := (*sessionInfo10)(unsafe.Pointer(bufPtr + uintptr(i)*unsafe.Sizeof(sessionInfo10{})))
		sessions = append(sessions, NetSessionInfo{
			Client: utf16PtrToString(si.Client),
			User:   utf16PtrToString(si.UserName),
			Time:   si.Time,
			Idle:   si.Idle,
		})
	}
	return sessions, nil
}

// EnumLoggedOn enumerates locally logged-on users.
func EnumLoggedOn(server string) ([]NetLoggedOnInfo, error) {
	var bufPtr uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	serverPtr, _ := syscall.UTF16PtrFromString(server)

	ret, _, _ := procNetWkstaUserEnum.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		1,
		uintptr(unsafe.Pointer(&bufPtr)),
		MAX_PREFERRED_LENGTH,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != NERR_Success && ret != 259 {
		return nil, fmt.Errorf("NetWkstaUserEnum: %d", ret)
	}
	defer freeNetAPIBuffer(bufPtr)

	type wkstaUserInfo1 struct {
		UserName    *uint16
		LogonDomain *uint16
		Other       *uint16
		LogonSrv    *uint16
	}

	users := make([]NetLoggedOnInfo, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		ui := (*wkstaUserInfo1)(unsafe.Pointer(bufPtr + uintptr(i)*unsafe.Sizeof(wkstaUserInfo1{})))
		users = append(users, NetLoggedOnInfo{
			UserName: utf16PtrToString(ui.UserName),
			Domain:   utf16PtrToString(ui.LogonDomain),
			LogonSrv: utf16PtrToString(ui.LogonSrv),
		})
	}
	return users, nil
}

// EnumComputers enumerates computers in the domain.
func EnumComputers(domain string) ([]NetComputerInfo, error) {
	var bufPtr uintptr
	var entriesRead, totalEntries uint32

	ret, _, _ := procNetServerEnum.Call(
		0,
		101,
		uintptr(unsafe.Pointer(&bufPtr)),
		MAX_PREFERRED_LENGTH,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0,
		0,
		0,
	)
	if ret != NERR_Success && ret != 259 {
		return nil, fmt.Errorf("NetServerEnum: %d", ret)
	}
	defer freeNetAPIBuffer(bufPtr)

	type serverInfo101 struct {
		PlatformID   uint32
		Name         *uint16
		VersionMajor uint32
		VersionMinor uint32
		Type         uint32
		Comment      *uint16
	}

	computers := make([]NetComputerInfo, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		si := (*serverInfo101)(unsafe.Pointer(bufPtr + uintptr(i)*unsafe.Sizeof(serverInfo101{})))
		name := utf16PtrToString(si.Name)
		if len(name) > 2 && name[:2] == "\\\\" {
			name = name[2:]
		}
		computers = append(computers, NetComputerInfo{
			Name:   name,
			Domain: domain,
		})
	}
	return computers, nil
}

// FindDomainController finds the domain controller for the current domain.
func FindDomainController() (string, error) {
	var dcInfo uintptr
	domainPtr, _ := syscall.UTF16PtrFromString("")

	ret, _, _ := procDsGetDcName.Call(
		0,
		uintptr(unsafe.Pointer(domainPtr)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&dcInfo)),
	)
	if ret != 0 {
		return "", fmt.Errorf("DsGetDcName: %d", ret)
	}
	defer freeNetAPIBuffer(dcInfo)

	type domainControllerInfo struct {
		DomainControllerName *uint16
	}

	dci := (*domainControllerInfo)(unsafe.Pointer(dcInfo))
	name := utf16PtrToString(dci.DomainControllerName)
	if len(name) > 2 && name[:2] == "\\\\" {
		name = name[2:]
	}
	return name, nil
}
