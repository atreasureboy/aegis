package modules

// Native IfconfigModule - cross-platform network interface listing using net.Interfaces().

import (
	"fmt"
	"net"
	"strings"
)

// IfconfigModule returns network interface information.
func IfconfigModule(args string) (string, string, int) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Sprintf("net.Interfaces: %v", err), 1
	}

	var sb strings.Builder
	for _, iface := range interfaces {
		sb.WriteString(fmt.Sprintf("%s:\n", iface.Name))
		sb.WriteString(fmt.Sprintf("  flags:    %s\n", formatFlags(iface.Flags)))
		sb.WriteString(fmt.Sprintf("  mtu:      %d\n", iface.MTU))
		sb.WriteString(fmt.Sprintf("  mac:      %s\n", iface.HardwareAddr))

		addrs, err := iface.Addrs()
		if err != nil {
			sb.WriteString("  addrs:    (error reading addresses)\n")
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() != nil {
				sb.WriteString(fmt.Sprintf("  ipv4:     %s/%s\n", ipNet.IP, formatMask(ipNet.Mask)))
			} else if ipNet.IP.To16() != nil {
				sb.WriteString(fmt.Sprintf("  ipv6:     %s/%s\n", ipNet.IP, formatMask(ipNet.Mask)))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String(), "", 0
}

func formatFlags(flags net.Flags) string {
	var parts []string
	if flags&net.FlagUp != 0 {
		parts = append(parts, "UP")
	} else {
		parts = append(parts, "DOWN")
	}
	if flags&net.FlagBroadcast != 0 {
		parts = append(parts, "BROADCAST")
	}
	if flags&net.FlagLoopback != 0 {
		parts = append(parts, "LOOPBACK")
	}
	if flags&net.FlagPointToPoint != 0 {
		parts = append(parts, "POINTOPOINT")
	}
	if flags&net.FlagMulticast != 0 {
		parts = append(parts, "MULTICAST")
	}
	return strings.Join(parts, ",")
}

func formatMask(mask net.IPMask) string {
	if len(mask) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	// IPv6 prefix length
	ones, _ := mask.Size()
	return fmt.Sprintf("/%d", ones)
}
