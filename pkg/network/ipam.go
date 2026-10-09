package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const (
	DefaultStateDir  = "/var/run/gojail"
	DefaultStateFile = "/var/run/gojail/ipam.json"
	DefaultLockFile  = "/var/run/gojail/ipam.lock"
)

// IPAMState represents the persistent snapshot of active IP allocations.
type IPAMState struct {
	Subnet      string            `json:"subnet"`
	Allocations map[string]string `json:"allocations"` // containerID -> IP
}

// IPAM manages IP address allocation and persistent leases for container networks.
type IPAM struct {
	mu        sync.Mutex
	stateFile string
	lockFile  string
	subnet    *net.IPNet
	gateway   net.IP
}

// NewIPAM creates a new IPAM manager for the given CIDR (default: 10.200.0.0/24).
func NewIPAM(cidr string) (*IPAM, error) {
	if cidr == "" {
		cidr = "10.200.0.0/24"
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 subnets are currently supported: %s", cidr)
	}

	// Gateway defaults to the first usable host IP (e.g. 10.200.0.1) as a 4-byte IPv4 address
	gw := make(net.IP, 4)
	copy(gw, ip4.Mask(ipNet.Mask))
	gw[3] = 1

	return &IPAM{
		stateFile: DefaultStateFile,
		lockFile:  DefaultLockFile,
		subnet:    ipNet,
		gateway:   gw,
	}, nil
}

// NewIPAMWithPaths creates an IPAM manager with custom state and lock file paths (useful for tests).
func NewIPAMWithPaths(cidr, stateFile, lockFile string) (*IPAM, error) {
	ipam, err := NewIPAM(cidr)
	if err != nil {
		return nil, err
	}
	ipam.stateFile = stateFile
	ipam.lockFile = lockFile
	return ipam, nil
}

// Gateway returns the bridge gateway IP address.
func (ipam *IPAM) Gateway() net.IP {
	return ipam.gateway
}

// Subnet returns the configured IP subnet.
func (ipam *IPAM) Subnet() *net.IPNet {
	return ipam.subnet
}

// withLock acquires a file-based lock and in-memory lock to synchronize access across processes.
func (ipam *IPAM) withLock(fn func() error) error {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(ipam.lockFile), 0755); err != nil {
		return fmt.Errorf("failed to create lock directory: %w", err)
	}

	f, err := os.OpenFile(ipam.lockFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file %s: %w", ipam.lockFile, err)
	}
	defer func() {
		_ = f.Close()
	}()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire IPAM lock: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}()

	return fn()
}

// loadState reads the persistent allocation table from disk.
func (ipam *IPAM) loadState() (*IPAMState, error) {
	state := &IPAMState{
		Subnet:      ipam.subnet.String(),
		Allocations: make(map[string]string),
	}

	data, err := os.ReadFile(ipam.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, fmt.Errorf("failed to read IPAM state: %w", err)
	}

	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("corrupted IPAM state file: %w", err)
	}

	if state.Allocations == nil {
		state.Allocations = make(map[string]string)
	}

	return state, nil
}

// saveState persists the allocation table to disk atomically.
func (ipam *IPAM) saveState(state *IPAMState) error {
	if err := os.MkdirAll(filepath.Dir(ipam.stateFile), 0755); err != nil {
		return fmt.Errorf("failed to create state dir: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal IPAM state: %w", err)
	}

	tmpFile := ipam.stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary state file: %w", err)
	}

	if err := os.Rename(tmpFile, ipam.stateFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit IPAM state: %w", err)
	}

	return nil
}

// AllocateIP grants an available IP in the subnet to the specified container ID.
func (ipam *IPAM) AllocateIP(containerID string) (net.IP, error) {
	var allocatedIP net.IP

	err := ipam.withLock(func() error {
		state, err := ipam.loadState()
		if err != nil {
			return err
		}

		// Idempotency: if already allocated, return existing lease
		if existing, ok := state.Allocations[containerID]; ok {
			allocatedIP = net.ParseIP(existing).To4()
			if allocatedIP != nil {
				return nil
			}
		}

		// Track used IPs
		used := make(map[string]bool)
		for _, ipStr := range state.Allocations {
			used[ipStr] = true
		}

		baseIP := ipam.subnet.IP.To4()
		if baseIP == nil {
			return errors.New("subnet IP is not a valid IPv4 address")
		}

		// Iterate through usable host IPs in the /24 subnet (from .2 to .254)
		for i := 2; i < 255; i++ {
			candidate := net.IPv4(baseIP[0], baseIP[1], baseIP[2], byte(i)).To4()
			candStr := candidate.String()

			if !used[candStr] && !candidate.Equal(ipam.gateway) {
				state.Allocations[containerID] = candStr
				if err := ipam.saveState(state); err != nil {
					return err
				}
				allocatedIP = candidate
				return nil
			}
		}

		return errors.New("IPAM subnet address space exhausted (no free IPs)")
	})

	if err != nil {
		return nil, err
	}
	return allocatedIP, nil
}

// ReleaseIP frees the IP leased by the given container ID.
func (ipam *IPAM) ReleaseIP(containerID string) error {
	return ipam.withLock(func() error {
		state, err := ipam.loadState()
		if err != nil {
			return err
		}

		if _, ok := state.Allocations[containerID]; ok {
			delete(state.Allocations, containerID)
			return ipam.saveState(state)
		}
		return nil
	})
}

// GetIP returns the leased IP address for a container if allocated.
func (ipam *IPAM) GetIP(containerID string) (net.IP, bool) {
	var found net.IP
	var exists bool

	_ = ipam.withLock(func() error {
		state, err := ipam.loadState()
		if err != nil {
			return err
		}
		if ipStr, ok := state.Allocations[containerID]; ok {
			parsed := net.ParseIP(ipStr)
			if parsed != nil {
				found = parsed.To4()
				exists = true
			}
		}
		return nil
	})

	return found, exists
}
