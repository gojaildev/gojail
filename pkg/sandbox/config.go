package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/arkrix/gojail/pkg/network"
)

// ResourceMetrics contains accounting information collected from Cgroups v2.
type ResourceMetrics struct {
	PeakMemoryBytes int64 `json:"peak_memory_bytes"`
	UserCPUTimeUS   int64 `json:"user_cpu_time_us"`
	SystemCPUTimeUS int64 `json:"system_cpu_time_us"`
}

// MountSpec defines a host-to-container filesystem bind mount.
type MountSpec struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	ReadOnly      bool   `json:"read_only"`
}

// ParseMountSpec parses a string in the format "host_path:container_path[:ro|rw]".
func ParseMountSpec(spec string) (*MountSpec, error) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("invalid volume format %q, expected 'host:container[:ro|rw]'", spec)
	}

	hostPath := strings.TrimSpace(parts[0])
	containerPath := strings.TrimSpace(parts[1])

	if hostPath == "" || containerPath == "" {
		return nil, fmt.Errorf("empty host or container path in volume specification: %q", spec)
	}

	absHost, err := filepath.Abs(hostPath)
	if err != nil {
		return nil, fmt.Errorf("invalid host path %s: %w", hostPath, err)
	}

	realHost, err := filepath.EvalSymlinks(absHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host path symlinks %s: %w", absHost, err)
	}

	readOnly := false
	if len(parts) == 3 {
		mode := strings.ToLower(strings.TrimSpace(parts[2]))
		switch mode {
		case "ro":
			readOnly = true
		case "rw":
			readOnly = false
		default:
			return nil, fmt.Errorf("invalid mount option %q, expected 'ro' or 'rw'", mode)
		}
	}

	if !filepath.IsAbs(containerPath) {
		containerPath = "/" + containerPath
	}
	containerPath = filepath.Clean(containerPath)

	return &MountSpec{
		HostPath:      realHost,
		ContainerPath: containerPath,
		ReadOnly:      readOnly,
	}, nil
}

// PortMapping is an alias to network.PortMapping to avoid import cycles.
type PortMapping = network.PortMapping

// Config defines the constraints and execution parameters for a sandbox run.
type Config struct {
	ID               string                `json:"id"`
	MemoryLimitBytes int64                 `json:"memory_limit_bytes"`
	MaxProcesses     int64                 `json:"max_processes"`
	StorageLimitMB   int64                 `json:"storage_limit_mb"`
	Timeout          time.Duration         `json:"timeout"`
	Command          string                `json:"command"`
	Args             []string              `json:"args"`
	Env              []string              `json:"env"`
	Image            string                `json:"image,omitempty"`
	RootPath         string                `json:"root_path,omitempty"`
	Rootfs           string                `json:"rootfs,omitempty"`
	Mounts           []MountSpec           `json:"mounts,omitempty"`
	TTY              bool                  `json:"tty,omitempty"`
	SeccompProfile   string                `json:"seccomp_profile,omitempty"`
	NetworkMode      string                `json:"network_mode,omitempty"` // "none" (air-gapped) or "bridge" (veth + outbound NAT)
	PortMappings     []network.PortMapping `json:"port_mappings,omitempty"`
	DNSServers       []string              `json:"dns_servers,omitempty"`
}

// Result holds standard output, errors, execution timings, and resource telemetry.
type Result struct {
	ExitCode int             `json:"exit_code"`
	Stdout   string          `json:"stdout"`
	Stderr   string          `json:"stderr"`
	Duration time.Duration   `json:"duration"`
	TimedOut bool            `json:"timed_out"`
	Metrics  ResourceMetrics `json:"metrics"`
}
