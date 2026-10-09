package sandbox

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain intercepts the re-exec hook when running under 'go test'
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == "__tcp_echo_server__" {
		port := "8080"
		if len(os.Args) >= 3 {
			port = os.Args[2]
		}
		l, err := net.Listen("tcp", "0.0.0.0:"+port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			_ = l.Close()
		}()

		fmt.Println("READY")

		conn, err := l.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			os.Exit(1)
		}
		_, _ = conn.Write([]byte("jail-ack\n"))
		_ = conn.Close()
		os.Exit(0)
	}

	if len(os.Args) >= 3 && os.Args[1] == "__init_child__" {
		if err := InitChild(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error in test child init: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	os.Exit(m.Run())
}

func requireRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping integration test: requires root privileges for namespaces/cgroups")
	}
}

func TestIntegration_BasicExecution(t *testing.T) {
	requireRoot(t)

	cfg := Config{
		ID:               "test-basic-exec",
		Command:          "/bin/sh",
		Args:             []string{"-c", "echo hello_sandbox"},
		Timeout:          5 * time.Second,
		MemoryLimitBytes: 64 * 1024 * 1024,
		MaxProcesses:     16,
		Env:              []string{"PATH=/bin:/usr/bin"},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run() failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d. stderr: %s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "hello_sandbox") {
		t.Errorf("expected output to contain 'hello_sandbox', got: %q", res.Stdout)
	}
}

func TestIntegration_TimeoutEnforcement(t *testing.T) {
	requireRoot(t)

	cfg := Config{
		ID:               "test-timeout-exec",
		Command:          "/bin/sh",
		Args:             []string{"-c", "sleep 3"},
		Timeout:          500 * time.Millisecond,
		MemoryLimitBytes: 64 * 1024 * 1024,
		MaxProcesses:     16,
		Env:              []string{"PATH=/bin:/usr/bin"},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run() unexpected error: %v", err)
	}

	if !res.TimedOut {
		t.Errorf("expected timed_out to be true, got false")
	}
	if res.Duration < 450*time.Millisecond || res.Duration > 2*time.Second {
		t.Errorf("duration out of expected bounds: %v", res.Duration)
	}
}

func TestIntegration_NetworkIsolation(t *testing.T) {
	requireRoot(t)

	cfg := Config{
		ID:               "test-net-isolation",
		Command:          "/bin/sh",
		Args:             []string{"-c", "ping -c 1 -W 1 1.1.1.1 || exit 42"},
		Timeout:          5 * time.Second,
		MemoryLimitBytes: 64 * 1024 * 1024,
		MaxProcesses:     16,
		Env:              []string{"PATH=/bin:/usr/bin:/sbin:/usr/sbin"},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run() error: %v", err)
	}

	if res.ExitCode != 42 {
		t.Errorf("expected exit code 42 due to network failure, got %d. stderr: %s", res.ExitCode, res.Stderr)
	}
}

func TestIntegration_SeccompBlockSyscall(t *testing.T) {
	requireRoot(t)

	cfg := Config{
		ID:               "test-seccomp-block",
		Command:          "/bin/sh",
		Args:             []string{"-c", "mount -t tmpfs none /tmp 2>&1"},
		Timeout:          5 * time.Second,
		MemoryLimitBytes: 64 * 1024 * 1024,
		MaxProcesses:     16,
		Env:              []string{"PATH=/bin:/usr/bin:/sbin:/usr/sbin"},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("runner.Run() error: %v", err)
	}

	if res.ExitCode == 0 {
		t.Errorf("expected mount to be blocked by seccomp, but succeeded with exit code 0")
	}

	output := strings.ToLower(res.Stdout + res.Stderr)
	if !strings.Contains(output, "operation not permitted") && !strings.Contains(output, "permission denied") {
		t.Logf("output received: %s (exit code %d)", output, res.ExitCode)
	}
}

func TestIntegration_CgroupFreezeThaw(t *testing.T) {
	requireRoot(t)

	testID := fmt.Sprintf("test-freeze-%d", time.Now().UnixNano())
	cg, err := NewCgroupController(testID)
	if err != nil {
		t.Fatalf("failed to create cgroup controller: %v", err)
	}
	defer func() {
		_ = cg.Cleanup()
	}()

	if err := cg.Freeze(); err != nil {
		t.Fatalf("Freeze() failed: %v", err)
	}

	if err := cg.Thaw(); err != nil {
		t.Fatalf("Thaw() failed: %v", err)
	}
}
