package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfig_DefaultValues(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.SocketPath != "/var/run/gojail.sock" {
		t.Errorf("unexpected default socket path: %s", cfg.Server.SocketPath)
	}
	if cfg.Pool.WarmWorkers != 2 {
		t.Errorf("unexpected default worker count: %d", cfg.Pool.WarmWorkers)
	}
	if cfg.Defaults.MemoryLimitMB != 128 {
		t.Errorf("unexpected default memory limit: %d", cfg.Defaults.MemoryLimitMB)
	}
	if cfg.Defaults.MaxProcesses != 64 {
		t.Errorf("unexpected default max processes: %d", cfg.Defaults.MaxProcesses)
	}
	if cfg.Defaults.TimeoutSec != 10 {
		t.Errorf("unexpected default timeout: %d", cfg.Defaults.TimeoutSec)
	}
	if cfg.Defaults.StorageLimitMB != 64 {
		t.Errorf("unexpected default storage limit: %d", cfg.Defaults.StorageLimitMB)
	}
	if cfg.Storage.CgroupRoot != "/sys/fs/cgroup/gojail" {
		t.Errorf("unexpected default cgroup root: %s", cfg.Storage.CgroupRoot)
	}
	if cfg.Storage.LayersDir != "/run/gojail/layers" {
		t.Errorf("unexpected default layers dir: %s", cfg.Storage.LayersDir)
	}
	if cfg.Storage.LogsDir != "/run/gojail/logs" {
		t.Errorf("unexpected default logs dir: %s", cfg.Storage.LogsDir)
	}
}

func TestConfig_LoadCustomYAML(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "test-config.yaml")

	yamlContent := `
server:
  socket_path: "/tmp/custom-gojail.sock"
  socket_mode: 0660
pool:
  warm_workers: 5
defaults:
  memory_limit_mb: 256
  max_processes: 128
  timeout_sec: 15
  storage_limit_mb: 128
storage:
  cgroup_root: "/tmp/cgroup"
  layers_dir: "/tmp/layers"
  logs_dir: "/tmp/logs"
`
	if err := os.WriteFile(confPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(confPath)
	if err != nil {
		t.Fatalf("failed to load custom config: %v", err)
	}

	if cfg.Server.SocketPath != "/tmp/custom-gojail.sock" {
		t.Errorf("expected custom socket path, got: %s", cfg.Server.SocketPath)
	}
	if cfg.Pool.WarmWorkers != 5 {
		t.Errorf("expected 5 warm workers, got: %d", cfg.Pool.WarmWorkers)
	}
	if cfg.Defaults.MemoryLimitMB != 256 {
		t.Errorf("expected 256MB memory limit, got: %d", cfg.Defaults.MemoryLimitMB)
	}
	if cfg.Defaults.StorageLimitMB != 128 {
		t.Errorf("expected 128MB storage limit, got: %d", cfg.Defaults.StorageLimitMB)
	}
	if cfg.Storage.LayersDir != "/tmp/layers" {
		t.Errorf("expected custom layers dir, got: %s", cfg.Storage.LayersDir)
	}
	if cfg.Storage.LogsDir != "/tmp/logs" {
		t.Errorf("expected custom logs dir, got: %s", cfg.Storage.LogsDir)
	}
}

func TestConfig_LoadConfig_EmptyPathFallback(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("expected fallback to default config with empty path, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config on fallback")
	}
	if cfg.Server.SocketPath != "/var/run/gojail.sock" {
		t.Errorf("expected default socket path on empty fallback, got: %s", cfg.Server.SocketPath)
	}
}

func TestConfig_LoadConfig_Errors(t *testing.T) {
	tmpDir := t.TempDir()

	malformedPath := filepath.Join(tmpDir, "malformed.yaml")
	if err := os.WriteFile(malformedPath, []byte("server:\n  socket_path: [invalid-yaml"), 0644); err != nil {
		t.Fatalf("failed to write malformed config: %v", err)
	}

	nonExistentPath := filepath.Join(tmpDir, "does-not-exist.yaml")

	testCases := []struct {
		name          string
		path          string
		expectedError string
	}{
		{
			name:          "nonexistent explicit file returns read error",
			path:          nonExistentPath,
			expectedError: "failed to read config file",
		},
		{
			name:          "malformed yaml content returns parse error",
			path:          malformedPath,
			expectedError: "failed to parse yaml config",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(tc.path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil cfg: %+v", tc.expectedError, cfg)
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("expected error containing %q, got: %v", tc.expectedError, err)
			}
		})
	}
}
