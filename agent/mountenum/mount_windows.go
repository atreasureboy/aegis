//go:build windows

package mountenum

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MountInfo represents a mounted volume.
type MountInfo struct {
	DriveLetter   string
	VolumeName    string
	FileSystem    string
	SerialNumber  uint32
	TotalBytes    uint64
	FreeBytes     uint64
	DriveType     uint32
}

// EnumMounts enumerates all mounted drives using native Windows API.
func EnumMounts() ([]MountInfo, error) {
	drives, err := getLogicalDrives()
	if err != nil {
		return nil, fmt.Errorf("GetLogicalDrives: %w", err)
	}

	var mounts []MountInfo
	for _, drive := range drives {
		info := MountInfo{DriveLetter: drive}

		// Get volume information
		name, fsName, serial, err := getVolumeInfo(drive)
		if err == nil {
			info.VolumeName = name
			info.FileSystem = fsName
			info.SerialNumber = serial
		}

		// Get disk space
		total, free, err := getDiskFreeSpace(drive)
		if err == nil {
			info.TotalBytes = total
			info.FreeBytes = free
		}

		// Get drive type
		info.DriveType = getDriveType(drive)

		mounts = append(mounts, info)
	}

	return mounts, nil
}

func getLogicalDrives() ([]string, error) {
	bitmask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}

	var drives []string
	for i := 0; i < 26; i++ {
		if bitmask&(1<<uint32(i)) != 0 {
			drives = append(drives, fmt.Sprintf("%c:\\", 'A'+i))
		}
	}
	return drives, nil
}

func getVolumeInfo(drive string) (string, string, uint32, error) {
	volName := make([]uint16, windows.MAX_PATH+1)
	fsName := make([]uint16, windows.MAX_PATH+1)
	var serial, maxCompLen, fsFlags uint32

	driveRoot := drive + `\`
	rootPtr, err := syscall.UTF16PtrFromString(driveRoot)
	if err != nil {
		return "", "", 0, err
	}

	err = windows.GetVolumeInformation(
		rootPtr,
		&volName[0],
		uint32(len(volName)),
		&serial,
		&maxCompLen,
		&fsFlags,
		&fsName[0],
		uint32(len(fsName)),
	)
	if err != nil {
		return "", "", 0, err
	}

	return windows.UTF16ToString(volName), windows.UTF16ToString(fsName), serial, nil
}

func getDiskFreeSpace(drive string) (uint64, uint64, error) {
	rootPtr, err := syscall.UTF16PtrFromString(drive + `\`)
	if err != nil {
		return 0, 0, err
	}

	var freeBytes, totalBytes, totalFree uint64
	err = windows.GetDiskFreeSpaceEx(
		rootPtr,
		&freeBytes,
		&totalBytes,
		&totalFree,
	)
	if err != nil {
		return 0, 0, err
	}

	return totalBytes, freeBytes, nil
}

func getDriveType(drive string) uint32 {
	rootPtr, _ := syscall.UTF16PtrFromString(drive + `\`)
	if rootPtr == nil {
		return 0
	}
	return getDriveTypeW(rootPtr)
}

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procGetDriveTypeW = kernel32.NewProc("GetDriveTypeW")
)

func getDriveTypeW(path *uint16) uint32 {
	ret, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(path)))
	return uint32(ret)
}

// FormatMounts formats mount info for display.
func FormatMounts(mounts []MountInfo) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-8s %-20s %-10s %-15s %-20s %-20s %s\n",
		"DRIVE", "VOLUME NAME", "TYPE", "FILE SYSTEM", "TOTAL SIZE", "FREE SPACE", "SERIAL"))
	sb.WriteString(strings.Repeat("-", 120) + "\n")
	for _, m := range mounts {
		sb.WriteString(fmt.Sprintf("%-8s %-20s %-10s %-15s %-20s %-20s 0x%08X\n",
			m.DriveLetter,
			truncate(m.VolumeName, 20),
			driveTypeStr(m.DriveType),
			m.FileSystem,
			humanSize(m.TotalBytes),
			humanSize(m.FreeBytes),
			m.SerialNumber,
		))
	}
	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-1] + "…"
	}
	return s
}

func humanSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func driveTypeStr(t uint32) string {
	switch t {
	case 0:
		return "unknown"
	case 1:
		return "no root"
	case 2:
		return "removable"
	case 3:
		return "fixed"
	case 4:
		return "remote"
	case 5:
		return "cdrom"
	case 6:
		return "ramdisk"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
