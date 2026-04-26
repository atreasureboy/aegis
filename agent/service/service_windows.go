//go:build windows

package service

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// ServiceInfo represents a Windows service with its configuration and status.
type ServiceInfo struct {
	Name        string
	DisplayName string
	Description string
	State       svc.State
	StartType   uint32
	BinaryPath  string
	PID         uint32
}

// EnumServices enumerates all Windows services using native API.
// Follows Sliver's pattern: EnumServicesStatusExW + per-service open with read-only perms.
func EnumServices() ([]ServiceInfo, error) {
	hSCM, err := connectToServiceManager()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SCM: %w", err)
	}
	defer windows.CloseServiceHandle(hSCM)

	return enumServicesFromHandle(hSCM)
}

// connectToServiceManager opens a connection to the SCM with minimal permissions.
func connectToServiceManager() (windows.Handle, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE|windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	return h, nil
}

// enumServicesFromHandle iterates services via EnumServicesStatusExW.
func enumServicesFromHandle(hSCM windows.Handle) ([]ServiceInfo, error) {
	var bytesNeeded, servicesReturned uint32
	var resumeHandle uint32
	bufSize := uint32(64 * 1024) // 64KB initial buffer

	for {
		buf := make([]byte, bufSize)
		err := enumServicesStatusEx(
			hSCM,
			windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32,
			windows.SERVICE_STATE_ALL,
			&buf[0],
			bufSize,
			&bytesNeeded,
			&servicesReturned,
			&resumeHandle,
			nil,
		)
		if err == nil {
			return parseEnumServices(buf, servicesReturned)
		}

		if err == windows.ERROR_MORE_DATA {
			bufSize = bytesNeeded
			continue
		}

		return nil, fmt.Errorf("EnumServicesStatusEx: %w", err)
	}
}

// enumServicesStatusEx wraps EnumServicesStatusExW syscall.
func enumServicesStatusEx(
	hSCManager windows.Handle,
	infoLevel uint32,
	serviceType uint32,
	serviceState uint32,
	lpServices *byte,
	cbBufSize uint32,
	pcbBytesNeeded *uint32,
	lpServicesReturned *uint32,
	lpResumeHandle *uint32,
	pszGroupName *uint16,
) error {
	r1, _, lastErr := syscall.Syscall12(
		procEnumServicesStatusExW.Addr(),
		10,
		uintptr(hSCManager),
		uintptr(infoLevel),
		uintptr(serviceType),
		uintptr(serviceState),
		uintptr(unsafe.Pointer(lpServices)),
		uintptr(cbBufSize),
		uintptr(unsafe.Pointer(pcbBytesNeeded)),
		uintptr(unsafe.Pointer(lpServicesReturned)),
		uintptr(unsafe.Pointer(lpResumeHandle)),
		uintptr(unsafe.Pointer(pszGroupName)),
		0,
		0,
	)
	if r1 == 0 {
		return lastErr
	}
	return nil
}

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procEnumServicesStatusExW = advapi32.NewProc("EnumServicesStatusExW")
)

// parseEnumServices parses the ENUM_SERVICE_STATUS_PROCESS array from the buffer.
func parseEnumServices(buf []byte, count uint32) ([]ServiceInfo, error) {
	var services []ServiceInfo

	entrySize := int(unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{}))
	for i := uint32(0); i < count; i++ {
		offset := int(i) * entrySize
		if offset+entrySize > len(buf) {
			break
		}
		entry := (*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[offset]))

		si := ServiceInfo{
			Name:        windows.UTF16PtrToString(entry.ServiceName),
			DisplayName: windows.UTF16PtrToString(entry.DisplayName),
			State:       svc.State(entry.ServiceStatusProcess.CurrentState),
			PID:         entry.ServiceStatusProcess.ProcessId,
		}

		// Open service to get config details (binary path, start type)
		si.fillConfig(entry.ServiceName)

		services = append(services, si)
	}

	return services, nil
}

// fillConfig opens a service handle to retrieve binary path and start type.
func (si *ServiceInfo) fillConfig(serviceName *uint16) {
	hSCM, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE|windows.SC_MANAGER_CONNECT)
	if err != nil {
		return
	}
	defer windows.CloseServiceHandle(hSCM)

	hSvc, err := windows.OpenService(hSCM, serviceName, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return
	}
	defer windows.CloseServiceHandle(hSvc)

	config, err := queryServiceConfig(hSvc)
	if err != nil {
		return
	}

	si.BinaryPath = windows.UTF16PtrToString(config.BinaryPathName)
	si.StartType = config.StartType

	if desc := queryServiceDescription(hSvc); desc != "" {
		si.Description = desc
	}
}

// queryServiceConfig retrieves the service configuration.
func queryServiceConfig(hSvc windows.Handle) (*windows.QUERY_SERVICE_CONFIG, error) {
	var bytesNeeded uint32

	// First call to determine buffer size
	windows.QueryServiceConfig(hSvc, nil, 0, &bytesNeeded)

	buf := make([]byte, bytesNeeded)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	err := windows.QueryServiceConfig(hSvc, config, uint32(len(buf)), &bytesNeeded)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// queryServiceDescription retrieves the service description.
func queryServiceDescription(hSvc windows.Handle) string {
	var bytesNeeded uint32

	windows.QueryServiceConfig2(hSvc, windows.SERVICE_CONFIG_DESCRIPTION, nil, 0, &bytesNeeded)

	buf := make([]byte, bytesNeeded)
	err := windows.QueryServiceConfig2(hSvc, windows.SERVICE_CONFIG_DESCRIPTION, &buf[0], uint32(len(buf)), &bytesNeeded)
	if err != nil {
		return ""
	}

	desc := (*windows.SERVICE_DESCRIPTION)(unsafe.Pointer(&buf[0]))
	return windows.UTF16PtrToString(desc.Description)
}

// FormatServices formats service list for display.
func FormatServices(services []ServiceInfo) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-40s %-50s %-12s %-12s %s\n", "NAME", "DISPLAY NAME", "STATE", "START TYPE", "BINARY PATH"))
	sb.WriteString(strings.Repeat("-", 160) + "\n")
	for _, s := range services {
		sb.WriteString(fmt.Sprintf("%-40s %-50s %-12s %-12s %s\n",
			s.Name, s.DisplayName, stateStr(s.State), startTypeStr(s.StartType), s.BinaryPath))
	}
	return sb.String()
}

func stateStr(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start pending"
	case svc.StopPending:
		return "stop pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue pending"
	case svc.PausePending:
		return "pause pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

func startTypeStr(t uint32) string {
	switch t {
	case windows.SERVICE_AUTO_START:
		return "auto"
	case windows.SERVICE_DEMAND_START:
		return "manual"
	case windows.SERVICE_DISABLED:
		return "disabled"
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
