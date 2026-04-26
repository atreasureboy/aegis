//go:build !windows

package mountenum

import "fmt"

// MountInfo represents a mounted volume (stub for non-Windows).
type MountInfo struct {
	DriveLetter   string
	VolumeName    string
	FileSystem    string
	SerialNumber  uint32
	TotalBytes    uint64
	FreeBytes     uint64
	DriveType     uint32
}

// EnumMounts is not available on non-Windows platforms.
func EnumMounts() ([]MountInfo, error) {
	return nil, fmt.Errorf("mount enumeration not supported on this platform")
}

// FormatMounts formats mount info for display.
func FormatMounts(mounts []MountInfo) string {
	return "mount enumeration is only available on Windows\n"
}
