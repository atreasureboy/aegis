// Quick AES-GCM encryptor for stage2 payload.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: encrypt <input> <aes_key_hex>")
		os.Exit(1)
	}
	inputPath := os.Args[1]
	keyHex := os.Args[2]

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad key: %v\n", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipher: %v\n", err)
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gcm: %v\n", err)
		os.Exit(1)
	}

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	encrypted := gcm.Seal(nonce, nonce, data, nil)

	outPath := inputPath + ".enc"
	err = os.WriteFile(outPath, encrypted, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Encrypted: %d bytes -> %s\n", len(encrypted), outPath)
}
