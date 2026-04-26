//go:build windows

package modules

// Native NetstatModule - Windows implementation using iphlpapi.dll.

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NetstatModule lists network connections natively on Windows.
func NetstatModule(args string) (string, string, int) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-6s %-25s %-25s %-15s %s\n",
		"Proto", "Local Address", "Foreign Address", "State", "PID"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	// TCP connections
	tcpEntries, err := getExtendedTcpTable()
	if err != nil {
		sb.WriteString(fmt.Sprintf("TCP error: %v\n", err))
	} else {
		for _, e := range tcpEntries {
			localAddr := fmt.Sprintf("%s:%d", net.IPv4(
				byte(e.dwLocalAddr), byte(e.dwLocalAddr>>8),
				byte(e.dwLocalAddr>>16), byte(e.dwLocalAddr>>24)), e.dwLocalPort)
			foreignAddr := fmt.Sprintf("%s:%d", net.IPv4(
				byte(e.dwRemoteAddr), byte(e.dwRemoteAddr>>8),
				byte(e.dwRemoteAddr>>16), byte(e.dwRemoteAddr>>24)), e.dwRemotePort)
			state := tcpStateName(e.dwState)
			sb.WriteString(fmt.Sprintf("%-6s %-25s %-25s %-15s %d\n",
				"TCP", localAddr, foreignAddr, state, e.dwOwningPid))
		}
	}

	// UDP endpoints
	udpEntries, err := getUdpTable()
	if err != nil {
		sb.WriteString(fmt.Sprintf("UDP error: %v\n", err))
	} else {
		for _, e := range udpEntries {
			localAddr := fmt.Sprintf("%s:%d", net.IPv4(
				byte(e.dwLocalAddr), byte(e.dwLocalAddr>>8),
				byte(e.dwLocalAddr>>16), byte(e.dwLocalAddr>>24)), e.dwLocalPort)
			sb.WriteString(fmt.Sprintf("%-6s %-25s %-25s %-15s %d\n",
				"UDP", localAddr, "*:*", "UNCONN", e.dwOwningPid))
		}
	}

	return sb.String(), "", 0
}

// MIB_TCPROW_OWNER_PID structure.
type mibTCPRowOwnerPid struct {
	dwState      uint32
	dwLocalAddr  uint32
	dwLocalPort  uint32
	dwRemoteAddr uint32
	dwRemotePort uint32
	dwOwningPid  uint32
}

// MIB_UDPROW_OWNER_PID structure.
type mibUDPRowOwnerPid struct {
	dwLocalAddr uint32
	dwLocalPort uint32
	dwOwningPid uint32
}

// TCP state constants.
func tcpStateName(state uint32) string {
	states := map[uint32]string{
		1:  "CLOSED",
		2:  "LISTEN",
		3:  "SYN_SENT",
		4:  "SYN_RCVD",
		5:  "ESTABLISHED",
		6:  "FIN_WAIT1",
		7:  "FIN_WAIT2",
		8:  "CLOSE_WAIT",
		9:  "CLOSING",
		10: "LAST_ACK",
		11: "TIME_WAIT",
		12: "DELETE_TCB",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return fmt.Sprintf("STATE_%d", state)
}

// getExtendedTcpTable calls GetExtendedTcpTable from iphlpapi.dll.
func getExtendedTcpTable() ([]mibTCPRowOwnerPid, error) {
	mod, err := syscall.LoadDLL("iphlpapi.dll")
	if err != nil {
		return nil, err
	}
	proc, err := mod.FindProc("GetExtendedTcpTable")
	if err != nil {
		return nil, err
	}

	// First call to get buffer size
	var size uint32
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, uintptr(2), 0) // AF_INET = 2, TCP_TABLE_OWNER_PID_CONNECTIONS = 2
	if size == 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable: zero size")
	}

	buf := make([]byte, size)
	ret, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,    // sort
		2,    // af: AF_INET
		2,    // class: TCP_TABLE_OWNER_PID_CONNECTIONS
		0,    // reserved
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	// First 4 bytes = number of entries
	numEntries := binary.LittleEndian.Uint32(buf[:4])
	entries := make([]mibTCPRowOwnerPid, numEntries)

	offset := 4
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPid{})
	for i := uint32(0); i < numEntries; i++ {
		entry := (*mibTCPRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		entries[i] = *entry
		// Convert port from network byte order (stored as uint32 but only 2 bytes meaningful)
		portHi := uint32(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&entries[i].dwLocalPort))[:]))
		entries[i].dwLocalPort = portHi
		portHi2 := uint32(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&entries[i].dwRemotePort))[:]))
		entries[i].dwRemotePort = portHi2
		offset += int(rowSize)
	}

	return entries, nil
}

// getUdpTable calls GetExtendedUdpTable from iphlpapi.dll (with PID).
func getUdpTable() ([]mibUDPRowOwnerPid, error) {
	mod, err := syscall.LoadDLL("iphlpapi.dll")
	if err != nil {
		return nil, err
	}
	proc, err := mod.FindProc("GetExtendedUdpTable")
	if err != nil {
		return nil, err
	}

	// First call to get buffer size
	var size uint32
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 1, 0) // AF_INET=2, UDP_TABLE_OWNER_PID=1
	if size == 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable: zero size")
	}

	buf := make([]byte, size)
	ret, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,    // sort
		2,    // af: AF_INET
		1,    // class: UDP_TABLE_OWNER_PID
		0,    // reserved
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	entries := make([]mibUDPRowOwnerPid, numEntries)

	offset := 4
	rowSize := unsafe.Sizeof(mibUDPRowOwnerPid{})
	for i := uint32(0); i < numEntries; i++ {
		entry := (*mibUDPRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		entries[i] = *entry
		entries[i].dwLocalPort = uint32(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&entries[i].dwLocalPort))[:]))
		offset += int(rowSize)
	}

	return entries, nil
}

// Suppress unused import warning.
var _ = windows.ERROR_SUCCESS
