//go:build !windows

package modules

// Native NetstatModule - Linux implementation parsing /proc/net/*.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// tcpState maps numeric TCP states to human-readable names.
var tcpState = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// NetstatModule lists network connections natively.
func NetstatModule(args string) (string, string, int) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-6s %-25s %-25s %-15s %s\n",
		"Proto", "Local Address", "Foreign Address", "State", "PID/Name"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	// Parse TCP
	parseNetFile("/proc/net/tcp", "tcp", &sb)
	parseNetFile("/proc/net/tcp6", "tcp6", &sb)
	// Parse UDP
	parseUDPFile("/proc/net/udp", "udp", &sb)
	parseUDPFile("/proc/net/udp6", "udp6", &sb)

	return sb.String(), "", 0
}

func parseNetFile(path, proto string, sb *strings.Builder) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // file may not exist (e.g., no IPv6)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddr := decodeAddr(fields[1], false)
		foreignAddr := decodeAddr(fields[2], false)
		state := tcpState[fields[3]]
		if state == "" {
			state = fields[3]
		}

		inode := fields[9]
		pid := findPIDByInode(inode)

		sb.WriteString(fmt.Sprintf("%-6s %-25s %-25s %-15s %s\n",
			proto, localAddr, foreignAddr, state, pid))
	}
}

func parseUDPFile(path, proto string, sb *strings.Builder) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddr := decodeAddr(fields[1], false)
		inode := fields[9]
		pid := findPIDByInode(inode)

		sb.WriteString(fmt.Sprintf("%-6s %-25s %-25s %-15s %s\n",
			proto, localAddr, "*:*", "UNCONN", pid))
	}
}

// decodeAddr converts "0100000A:0050" to "10.0.0.1:80".
func decodeAddr(s string, ipv6 bool) string {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s
	}

	if ipv6 {
		// IPv6: 24 bytes hex -> decode to 16 bytes
		raw, err := hex.DecodeString(parts[0])
		if err != nil || len(raw) != 16 {
			return s
		}
		// /proc/net/tcp6 stores addresses in little-endian word groups
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			copy(ip[i*4:(i+1)*4], raw[i*4:(i+1)*4])
		}
		port, _ := strconv.ParseUint(parts[1], 16, 16)
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	}

	// IPv4: 4 bytes hex, little-endian
	raw, err := hex.DecodeString(parts[0])
	if err != nil || len(raw) != 4 {
		return s
	}
	ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
	port, _ := strconv.ParseUint(parts[1], 16, 16)
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

// findPIDByInode scans /proc/[pid]/fd to find the PID owning the inode.
func findPIDByInode(inode string) string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "?"
	}

	targetInode := inode
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := parsePID(e.Name())
		if pid == 0 {
			continue
		}

		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if err != nil {
				continue
			}
			// symlink looks like "socket:[12345]"
			if strings.Contains(link, "socket:["+targetInode+"]") {
				name := getProcName(pid)
				return fmt.Sprintf("%d/%s", pid, name)
			}
		}
	}
	return "?"
}

// getProcName reads /proc/[pid]/comm.
func getProcName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		// Fallback to /proc/[pid]/stat
		data, err = os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return "?"
		}
		return parseStatName(string(data))
	}
	return strings.TrimSpace(string(data))
}

// Unused but needed for compilation on non-Linux unix.
var _ = binary.LittleEndian
