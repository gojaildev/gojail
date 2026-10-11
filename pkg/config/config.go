package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DaemonConfig encapsulates all configurable parameters for gojaild.
type DaemonConfig struct {
	Server   ServerConfig   `yaml:"server"`
	Pool     PoolConfig     `yaml:"pool"`
	Defaults DefaultsConfig `yaml:"defaults"`
	Storage  StorageConfig  `yaml:"storage"`
}

// ServerConfig configures the Unix socket listener.
type ServerConfig struct {
	SocketPath string `yaml:"socket_path"`
	SocketMode uint32 `yaml:"socket_mode"`
}

// PoolConfig controls pre-forked worker concurrency.
type PoolConfig struct {
	WarmWorkers int `yaml:"warm_workers"`
}

// DefaultsConfig specifies fallback execution limits.
type DefaultsConfig struct {
	MemoryLimitMB  int64 `yaml:"memory_limit_mb"`
	MaxProcesses   int64 `yaml:"max_processes"`
	TimeoutSec     int   `yaml:"timeout_sec"`
	StorageLimitMB int64 `yaml:"storage_limit_mb"`
}

// StorageConfig sets filesystem locations for sandbox operations.
type StorageConfig struct {
	CgroupRoot string `yaml:"cgroup_root"`
	LayersDir  string `yaml:"layers_dir"`
	LogsDir    string `yaml:"logs_dir"`
}

// DefaultConfig returns sane production defaults.
func DefaultConfig() *DaemonConfig {
	return &DaemonConfig{
		Server: ServerConfig{
			SocketPath: "/var/run/gojail.sock",
			SocketMode: 0666,
		},
		Pool: PoolConfig{
			WarmWorkers: 2,
		},
		Defaults: DefaultsConfig{
			MemoryLimitMB:  128,
			MaxProcesses:   64,
			TimeoutSec:     10,
			StorageLimitMB: 64,
		},
		Storage: StorageConfig{
			CgroupRoot: "/sys/fs/cgroup/gojail",
			LayersDir:  "/run/gojail/layers",
			LogsDir:    "/run/gojail/logs",
		},
	}
}

// LoadConfig attempts to load configuration from an explicit path,
// standard /etc/gojail/config.yaml, or falls back to defaults.
func LoadConfig(path string) (*DaemonConfig, error) {
	cfg := DefaultConfig()

	targetPath := path
	if targetPath == "" {
		candidates := []string{
			"/etc/gojail/config.yaml",
			"config.yaml",
		}
		for _, cand := range candidates {
			if _, err := os.Stat(cand); err == nil {
				targetPath = cand
				break
			}
		}
	}

	if targetPath == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) && path == "" {
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", targetPath, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config at %s: %w", targetPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Server.SocketPath), 0755); err != nil {
		if os.Geteuid() == 0 {
			return nil, fmt.Errorf("failed to ensure socket directory: %w", err)
		}
	}

	if err := os.MkdirAll(cfg.Storage.LayersDir, 0755); err != nil {
		if os.Geteuid() == 0 {
			return nil, fmt.Errorf("failed to ensure layers directory: %w", err)
		}
	}

	if err := os.MkdirAll(cfg.Storage.LogsDir, 0755); err != nil {
		if os.Geteuid() == 0 {
			return nil, fmt.Errorf("failed to ensure logs directory: %w", err)
		}
	}

	return cfg, nil
}
