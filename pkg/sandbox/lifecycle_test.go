package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIntegration_DeterministicLifecycleCleanup(t *testing.T) {
	requireRoot(t)

	testCases := []struct {
		name        string
		command     string
		args        []string
		timeout     time.Duration
		expectError bool
	}{
		{
			name:        "normal_exit_cleans_resources",
			command:     "/bin/echo",
			args:        []string{"lifecycle-ok"},
			timeout:     5 * time.Second,
			expectError: false,
		},
		{
			name:        "timeout_termination_reaps_and_cleans",
			command:     "/bin/sleep",
			args:        []string{"30"},
			timeout:     300 * time.Millisecond,
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			containerID := fmt.Sprintf("test-lifecycle-%d", time.Now().UnixNano())
			cgroupPath := filepath.Join(defaultCgroupRoot, containerID)
			layerBase := filepath.Join("/run/gojail/layers", containerID)

			runner := NewRunner(Config{
				ID:               containerID,
				Command:          tc.command,
				Args:             tc.args,
				Timeout:          tc.timeout,
				MemoryLimitBytes: 64 * 1024 * 1024,
				MaxProcesses:     32,
				StorageLimitMB:   32,
			})

			res, err := runner.Run()
			if tc.expectError && err == nil {
				t.Fatalf("expected error, got nil result: %+v", res)
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected runner error: %v", err)
			}

			// Verify cgroup slice directory is completely removed
			if _, statErr := os.Stat(cgroupPath); !os.IsNotExist(statErr) {
				t.Errorf("cgroup directory was not cleaned up: %s still exists", cgroupPath)
			}

			// Verify overlay layer directory is completely unmounted and removed
			if _, statErr := os.Stat(layerBase); !os.IsNotExist(statErr) {
				t.Errorf("overlay base directory was not cleaned up: %s still exists", layerBase)
			}
		})
	}
}

func TestIntegration_CgroupCleanupRetryLoop(t *testing.T) {
	requireRoot(t)

	cgID := fmt.Sprintf("test-cg-retry-%d", time.Now().UnixNano())
	cg, err := NewCgroupController(cgID)
	if err != nil {
		t.Fatalf("failed creating cgroup controller: %v", err)
	}

	cgPath := filepath.Join(defaultCgroupRoot, cgID)

	// Verify directory exists
	if _, statErr := os.Stat(cgPath); os.IsNotExist(statErr) {
		t.Fatalf("expected cgroup dir %s to exist", cgPath)
	}

	// Explicit cleanup should remove the directory
	if err := cg.Cleanup(); err != nil {
		t.Fatalf("cg.Cleanup returned error: %v", err)
	}

	// Verify directory is gone
	if _, statErr := os.Stat(cgPath); !os.IsNotExist(statErr) {
		t.Errorf("cgroup dir %s still exists after Cleanup()", cgPath)
	}
}
