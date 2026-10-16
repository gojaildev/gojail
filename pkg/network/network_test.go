package network

import (
	"path/filepath"
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("expected non-nil Manager")
	}
	if m.bridgeName != DefaultBridgeName {
		t.Errorf("expected bridgeName %s, got %s", DefaultBridgeName, m.bridgeName)
	}
	if m.IPAM() == nil {
		t.Fatal("expected initialized IPAM in Manager")
	}
}

func TestEnsureBridge(t *testing.T) {
	m := NewManager()
	_, err := m.EnsureBridge()
	if err != nil {
		t.Skipf("skipping bridge test; requires root permissions: %v", err)
	}
}

func TestManager_ApplyPortForwarding_InvalidProtocol(t *testing.T) {
	tmpDir := t.TempDir()
	ipam, err := NewIPAMWithPaths("10.200.0.0/24", filepath.Join(tmpDir, "ipam.json"), filepath.Join(tmpDir, "ipam.lock"))
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	m := &Manager{
		bridgeName: DefaultBridgeName,
		bridgeCIDR: DefaultBridgeCIDR,
		ipam:       ipam,
	}

	testCases := []struct {
		name     string
		protocol string
	}{
		{
			name:     "unsupported sctp protocol",
			protocol: "sctp",
		},
		{
			name:     "unsupported icmp protocol",
			protocol: "icmp",
		},
		{
			name:     "arbitrary invalid protocol string",
			protocol: "raw_ip",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mappings := []PortMapping{
				{
					HostPort:      8080,
					ContainerPort: 80,
					Protocol:      tc.protocol,
				},
			}

			err := m.applyPortForwarding("10.200.0.2", mappings)
			if err == nil {
				t.Fatalf("expected error for protocol %q, got nil", tc.protocol)
			}
		})
	}
}

func TestManager_Cleanup_SafeExecution(t *testing.T) {
	tmpDir := t.TempDir()
	ipam, err := NewIPAMWithPaths("10.200.0.0/24", filepath.Join(tmpDir, "ipam.json"), filepath.Join(tmpDir, "ipam.lock"))
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	m := &Manager{
		bridgeName: DefaultBridgeName,
		bridgeCIDR: DefaultBridgeCIDR,
		ipam:       ipam,
	}

	// 1. Cleanup on a container ID with no prior IP lease or interface should not panic or fail
	m.Cleanup("nonexistent-container-id", nil)

	// 2. Cleanup on a container ID with an active lease should release the lease
	cID := "active-test-container"
	ip, err := ipam.AllocateIP(cID)
	if err != nil {
		t.Fatalf("failed to allocate IP: %v", err)
	}

	// Verify lease exists before cleanup
	if _, ok := ipam.GetIP(cID); !ok {
		t.Fatalf("expected container IP to be present")
	}

	// Trigger cleanup (with nil port mappings so no iptables exec is triggered)
	m.Cleanup(cID, nil)

	// Verify lease has been released
	if _, ok := ipam.GetIP(cID); ok {
		t.Errorf("expected IP %s to be released after cleanup", ip)
	}
}
