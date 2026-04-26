//go:build !windows

package netenum

import "fmt"

func EnumShares(server string) ([]NetShareInfo, error) {
	return nil, fmt.Errorf("net share only available on Windows")
}

func EnumUsers(server string) ([]NetUserInfo, error) {
	return nil, fmt.Errorf("net user only available on Windows")
}

func EnumGroups(server string) ([]NetGroupInfo, error) {
	return nil, fmt.Errorf("net group only available on Windows")
}

func EnumGroupMembers(server, group string) ([]string, error) {
	return nil, fmt.Errorf("net group members only available on Windows")
}

func EnumSessions(server string) ([]NetSessionInfo, error) {
	return nil, fmt.Errorf("net sessions only available on Windows")
}

func EnumLoggedOn(server string) ([]NetLoggedOnInfo, error) {
	return nil, fmt.Errorf("net logons only available on Windows")
}

func EnumComputers(domain string) ([]NetComputerInfo, error) {
	return nil, fmt.Errorf("net computers only available on Windows")
}

func FindDomainController() (string, error) {
	return "", fmt.Errorf("domain controller lookup only available on Windows")
}
