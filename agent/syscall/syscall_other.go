//go:build !windows || !amd64

package syscall

// ResolveNtdll 在非 Windows 平台上为 no-op。
func (t *SyscallTable) ResolveNtdll() error {
	return nil
}
