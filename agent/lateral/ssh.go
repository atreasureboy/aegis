// Package lateral provides SSH remote command execution.
// Reference: Sliver's shell/ssh/ssh.go — supports password, private key, and SSH agent auth.
package lateral

import (
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHExec runs a command on a remote host via SSH.
// Supports password auth (if password != ""), private key auth (if keyPath != ""),
// and falls back to SSH agent.
func SSHExec(host, port, username, password, keyPath, command string) (stdout, stderr string, exitCode int, err error) {
	if port == "" {
		port = "22"
	}

	var auths []ssh.AuthMethod

	// Password auth
	if password != "" {
		auths = append(auths, ssh.Password(password))
	}

	// Private key auth
	if keyPath != "" {
		signer, err := loadPrivateKey(keyPath)
		if err != nil {
			return "", "", 1, fmt.Errorf("load SSH key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}

	// Fallback to SSH agent
	if len(auths) == 0 {
		if am := sshAgentAuth(); am != nil {
			auths = append(auths, am)
		}
	}

	if len(auths) == 0 {
		return "", "", 1, fmt.Errorf("no SSH auth method (provide password, key path, or set SSH_AUTH_SOCK)")
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := host + ":" + port
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return "", "", 1, fmt.Errorf("SSH connect %s: %w", addr, err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return "", "", 1, fmt.Errorf("SSH new session: %w", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf strings.Builder
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	err = session.Run(command)
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			return stdoutBuf.String(), stderrBuf.String(), exitErr.ExitStatus(), nil
		}
		return stdoutBuf.String(), stderrBuf.String(), 1, fmt.Errorf("SSH command: %w", err)
	}

	return stdoutBuf.String(), stderrBuf.String(), 0, nil
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	// Try PEM format (RSA, ECDSA, ED25519)
	signer, err := ssh.ParsePrivateKey(keyData)
	if err == nil {
		return signer, nil
	}
	return nil, fmt.Errorf("parse key: %w", err)
}

func sshAgentAuth() ssh.AuthMethod {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers)
}
