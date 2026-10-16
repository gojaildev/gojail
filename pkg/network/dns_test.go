package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDNSList_Custom(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "valid and invalid mixed IPs",
			input:    []string{"9.9.9.9", "1.1.1.1", "invalid-ip", "   "},
			expected: []string{"9.9.9.9", "1.1.1.1"},
		},
		{
			name:     "whitespace padded IPs",
			input:    []string{"  8.8.8.8  ", "1.0.0.1"},
			expected: []string{"8.8.8.8", "1.0.0.1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := ResolveDNSList(tc.input)
			if len(res) != len(tc.expected) {
				t.Fatalf("expected %d IPs, got %d: %v", len(tc.expected), len(res), res)
			}
			for i, exp := range tc.expected {
				if res[i] != exp {
					t.Errorf("at index %d: expected %s, got %s", i, exp, res[i])
				}
			}
		})
	}
}

func TestResolveDNSList_FallbackToHostOrDefault(t *testing.T) {
	// Empty or invalid custom list triggers host resolution or fallback
	res := ResolveDNSList([]string{"not-an-ip", " "})
	if len(res) == 0 {
		t.Fatal("expected fallback DNS servers, got empty slice")
	}
}

func TestParseHostResolvConf_EdgeCases(t *testing.T) {
	testCases := []struct {
		name            string
		content         string
		expectedServers []string
	}{
		{
			name: "filters loopback and comments with hash and semicolon",
			content: `
# Hash comment
nameserver 127.0.0.53
; Semicolon comment
search lan local
nameserver 192.168.1.1
options edns0
nameserver 8.8.4.4
`,
			expectedServers: []string{"192.168.1.1", "8.8.4.4"},
		},
		{
			name: "ignores missing fields or invalid ips",
			content: `
nameserver
nameserver not-an-ip
nameserver 999.999.999.999
nameserver 10.0.0.1
`,
			expectedServers: []string{"10.0.0.1"},
		},
		{
			name: "all loopback addresses filtered",
			content: `
nameserver 127.0.0.1
nameserver 127.0.0.53
`,
			expectedServers: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			confPath := filepath.Join(tmpDir, "resolv.conf")
			if err := os.WriteFile(confPath, []byte(tc.content), 0644); err != nil {
				t.Fatalf("failed to write dummy resolv.conf: %v", err)
			}

			servers := parseHostResolvConf(confPath)
			if len(servers) != len(tc.expectedServers) {
				t.Fatalf("expected %d servers, got %d: %v", len(tc.expectedServers), len(servers), servers)
			}
			for i, exp := range tc.expectedServers {
				if servers[i] != exp {
					t.Errorf("at index %d: expected %s, got %s", i, exp, servers[i])
				}
			}
		})
	}
}

func TestParseHostResolvConf_NonExistentFile(t *testing.T) {
	servers := parseHostResolvConf("/path/does/not/exist/resolv.conf")
	if servers != nil {
		t.Errorf("expected nil for nonexistent file, got %v", servers)
	}
}

func TestInjectResolvConf(t *testing.T) {
	tmpRoot := t.TempDir()
	dns := []string{"1.0.0.1", "8.8.8.8"}

	if err := InjectResolvConf(tmpRoot, dns); err != nil {
		t.Fatalf("InjectResolvConf failed: %v", err)
	}

	resolvPath := filepath.Join(tmpRoot, "etc", "resolv.conf")
	data, err := os.ReadFile(resolvPath)
	if err != nil {
		t.Fatalf("failed to read injected resolv.conf: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "nameserver 1.0.0.1") || !strings.Contains(content, "nameserver 8.8.8.8") {
		t.Errorf("expected resolv.conf to contain both nameservers, got:\n%s", content)
	}

	// Overwrite existing file test
	dnsUpdated := []string{"9.9.9.9"}
	if err := InjectResolvConf(tmpRoot, dnsUpdated); err != nil {
		t.Fatalf("InjectResolvConf overwrite failed: %v", err)
	}

	dataUpdated, err := os.ReadFile(resolvPath)
	if err != nil {
		t.Fatalf("failed to read updated resolv.conf: %v", err)
	}

	contentUpdated := string(dataUpdated)
	if !strings.Contains(contentUpdated, "nameserver 9.9.9.9") || strings.Contains(contentUpdated, "1.0.0.1") {
		t.Errorf("expected updated content with only 9.9.9.9, got:\n%s", contentUpdated)
	}
}
