package main

import (
	"fmt"
	"os"

	"github.com/aegis-c2/aegis/server/pki"
)

func main() {
	pkiMgr, err := pki.New("pki/ca.crt", "pki/ca.key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load PKI: %v\n", err)
		os.Exit(1)
	}

	certPEM, keyPEM, err := pkiMgr.GenerateOperatorCert("admin", "admin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate cert: %v\n", err)
		os.Exit(1)
	}

	os.WriteFile("client.crt", certPEM, 0600)
	os.WriteFile("client.key", keyPEM, 0600)
	os.WriteFile("client_ca.crt", pkiMgr.CACertPEM(), 0600)

	fmt.Println("Generated client credentials:")
	fmt.Println("  client.crt, client.key, client_ca.crt")
	fmt.Println("Use: aegis-client --cert client.crt --key client.key --ca client_ca.crt --server 127.0.0.1:8444")
}
