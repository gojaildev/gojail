package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestIPAM_AllocationAndRelease(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "ipam.json")
	lockFile := filepath.Join(tmpDir, "ipam.lock")

	ipam, err := NewIPAMWithPaths("10.200.0.0/24", stateFile, lockFile)
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	ip1, err := ipam.AllocateIP("container-1")
	if err != nil {
		t.Fatalf("failed to allocate IP: %v", err)
	}

	if ip1.String() != "10.200.0.2" {
		t.Errorf("expected 10.200.0.2, got %s", ip1.String())
	}

	// Idempotency check: same container should receive same IP
	ip1Again, err := ipam.AllocateIP("container-1")
	if err != nil {
		t.Fatalf("idempotent allocation failed: %v", err)
	}
	if !ip1.Equal(ip1Again) {
		t.Errorf("expected same IP for same container, got %s vs %s", ip1, ip1Again)
	}

	// Next container gets next sequential address
	ip2, err := ipam.AllocateIP("container-2")
	if err != nil {
		t.Fatalf("failed to allocate IP 2: %v", err)
	}
	if ip2.String() != "10.200.0.3" {
		t.Errorf("expected 10.200.0.3, got %s", ip2.String())
	}

	// Release container 1
	if err := ipam.ReleaseIP("container-1"); err != nil {
		t.Fatalf("failed to release IP: %v", err)
	}

	// Releasing non-existent container should be a safe no-op
	if err := ipam.ReleaseIP("container-unknown"); err != nil {
		t.Fatalf("releasing unknown container returned unexpected error: %v", err)
	}

	// Container 3 should reuse the released 10.200.0.2 address
	ip3, err := ipam.AllocateIP("container-3")
	if err != nil {
		t.Fatalf("failed to allocate IP 3: %v", err)
	}
	if ip3.String() != "10.200.0.2" {
		t.Errorf("expected recycled IP 10.200.0.2, got %s", ip3.String())
	}
}

func TestIPAM_AccessorsAndGetIP(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "ipam.json")
	lockFile := filepath.Join(tmpDir, "ipam.lock")

	ipam, err := NewIPAMWithPaths("192.168.100.0/24", stateFile, lockFile)
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	// Verify Gateway and Subnet accessors
	if ipam.Gateway().String() != "192.168.100.1" {
		t.Errorf("expected gateway 192.168.100.1, got %s", ipam.Gateway())
	}
	if ipam.Subnet().String() != "192.168.100.0/24" {
		t.Errorf("expected subnet 192.168.100.0/24, got %s", ipam.Subnet())
	}

	// GetIP on unallocated container
	if gotIP, ok := ipam.GetIP("nonexistent"); ok || gotIP != nil {
		t.Errorf("expected nil, false for nonexistent container, got %v, %v", gotIP, ok)
	}

	// Allocate container and query via GetIP
	allocatedIP, err := ipam.AllocateIP("c-test-getip")
	if err != nil {
		t.Fatalf("failed to allocate IP: %v", err)
	}

	gotIP, ok := ipam.GetIP("c-test-getip")
	if !ok {
		t.Fatalf("expected GetIP to return true for existing container")
	}
	if !gotIP.Equal(allocatedIP) {
		t.Errorf("expected %s, got %s", allocatedIP, gotIP)
	}
}

func TestIPAM_InitializationErrors(t *testing.T) {
	testCases := []struct {
		name string
		cidr string
	}{
		{
			name: "invalid CIDR format",
			cidr: "not-a-cidr",
		},
		{
			name: "missing subnet mask",
			cidr: "10.0.0.1",
		},
		{
			name: "out of range IP",
			cidr: "999.999.999.999/24",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewIPAM(tc.cidr)
			if err == nil {
				t.Fatalf("expected error initializing IPAM with %q, got nil", tc.cidr)
			}

			tmpDir := t.TempDir()
			_, errPaths := NewIPAMWithPaths(tc.cidr, filepath.Join(tmpDir, "state"), filepath.Join(tmpDir, "lock"))
			if errPaths == nil {
				t.Fatalf("expected error initializing IPAMWithPaths with %q, got nil", tc.cidr)
			}
		})
	}
}

func TestIPAM_SubnetExhaustion(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "ipam.json")
	lockFile := filepath.Join(tmpDir, "ipam.lock")

	// Pre-populate all available host IPs (.2 to .254) in the state file
	allocations := make(map[string]string)
	for i := 2; i < 255; i++ {
		allocations[fmt.Sprintf("container-%d", i)] = fmt.Sprintf("10.0.0.%d", i)
	}
	initialState := struct {
		Subnet      string            `json:"subnet"`
		Allocations map[string]string `json:"allocations"`
	}{
		Subnet:      "10.0.0.0/24",
		Allocations: allocations,
	}

	stateData, err := json.Marshal(initialState)
	if err != nil {
		t.Fatalf("failed to marshal initial state: %v", err)
	}
	if err := os.WriteFile(stateFile, stateData, 0644); err != nil {
		t.Fatalf("failed to write full state file: %v", err)
	}

	ipam, err := NewIPAMWithPaths("10.0.0.0/24", stateFile, lockFile)
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	// Allocation must fail due to address exhaustion
	_, err = ipam.AllocateIP("container-overflow")
	if err == nil {
		t.Fatalf("expected error due to subnet exhaustion, got nil")
	}
}

func TestIPAM_CorruptedStateRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "ipam.json")
	lockFile := filepath.Join(tmpDir, "ipam.lock")

	if err := os.WriteFile(stateFile, []byte("{corrupted-json"), 0644); err != nil {
		t.Fatalf("failed to create corrupted state file: %v", err)
	}

	ipam, err := NewIPAMWithPaths("10.10.0.0/24", stateFile, lockFile)
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	_, err = ipam.AllocateIP("c-should-fail")
	if err == nil {
		t.Fatalf("expected error allocating from corrupted state file, got nil")
	}
}

func TestIPAM_ConcurrentAllocations(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "ipam.json")
	lockFile := filepath.Join(tmpDir, "ipam.lock")

	ipam, err := NewIPAMWithPaths("10.200.0.0/24", stateFile, lockFile)
	if err != nil {
		t.Fatalf("failed to init IPAM: %v", err)
	}

	const workerCount = 20
	var wg sync.WaitGroup
	allocated := sync.Map{}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cID := fmt.Sprintf("jail-concurrent-%d", id)
			ip, aErr := ipam.AllocateIP(cID)
			if aErr != nil {
				t.Errorf("failed allocating for %s: %v", cID, aErr)
				return
			}
			if _, loaded := allocated.LoadOrStore(ip.String(), cID); loaded {
				t.Errorf("duplicate IP collision detected: %s", ip.String())
			}
		}(i)
	}

	wg.Wait()
}
