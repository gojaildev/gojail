package sandbox

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arkrix/gojail/pkg/network"
)

func TestIntegration_NetworkModeNone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping network isolation test; root privileges required")
	}

	cfg := Config{
		ID:               fmt.Sprintf("test-net-none-%d", time.Now().UnixNano()),
		MemoryLimitBytes: 128 * 1024 * 1024,
		MaxProcesses:     32,
		StorageLimitMB:   64,
		Timeout:          5 * time.Second,
		NetworkMode:      "none",
		Command:          "/bin/sh",
		Args: []string{
			"-c",
			"ip -o link show | wc -l",
		},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("failed to run container: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", res.ExitCode, res.Stderr)
	}

	output := strings.TrimSpace(res.Stdout)
	if output != "1" {
		t.Errorf("expected exactly 1 interface (lo) in 'none' mode, got %s", output)
	}
}

func TestIntegration_NetworkModeBridge_Egress(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping bridge egress test; root privileges required")
	}

	netMgr := network.NewManager()
	if _, err := netMgr.EnsureBridge(); err != nil {
		t.Fatalf("failed to ensure bridge: %v", err)
	}

	hostListener, err := net.Listen("tcp", "10.200.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on bridge gateway: %v", err)
	}
	defer func() {
		_ = hostListener.Close()
	}()

	gatewayPort := hostListener.Addr().(*net.TCPAddr).Port

	acceptedCh := make(chan bool, 1)
	go func() {
		conn, err := hostListener.Accept()
		if err == nil {
			_ = conn.Close()
			acceptedCh <- true
		} else {
			acceptedCh <- false
		}
	}()

	cfg := Config{
		ID:               fmt.Sprintf("test-net-bridge-%d", time.Now().UnixNano()),
		MemoryLimitBytes: 128 * 1024 * 1024,
		MaxProcesses:     32,
		StorageLimitMB:   64,
		Timeout:          5 * time.Second,
		NetworkMode:      "bridge",
		Command:          "/bin/sh",
		Args: []string{
			"-c",
			fmt.Sprintf("nc -z -w 2 10.200.0.1 %d || echo 'FALLBACK' | nc -w 2 10.200.0.1 %d", gatewayPort, gatewayPort),
		},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("failed to run bridge container: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("failed to reach bridge gateway (exit %d): %s (stdout: %s)", res.ExitCode, res.Stderr, res.Stdout)
	}

	select {
	case ok := <-acceptedCh:
		if !ok {
			t.Fatal("failed to accept egress connection from container")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for egress connection from container")
	}
}

func TestIntegration_NetworkModeBridge_PortForwarding(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping port forwarding test; root privileges required")
	}

	hostPort := 18080
	containerPort := 8080

	selfBin, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get test executable: %v", err)
	}

	cfg := Config{
		ID:               fmt.Sprintf("test-net-dnat-%d", time.Now().UnixNano()),
		MemoryLimitBytes: 128 * 1024 * 1024,
		MaxProcesses:     32,
		StorageLimitMB:   64,
		Timeout:          15 * time.Second,
		NetworkMode:      "bridge",
		PortMappings: []network.PortMapping{
			{
				HostPort:      hostPort,
				ContainerPort: containerPort,
				Protocol:      "tcp",
			},
		},
		Mounts: []MountSpec{
			{
				HostPath:      selfBin,
				ContainerPath: "/bin/echo_server",
				ReadOnly:      true,
			},
		},
		Command: "/bin/echo_server",
		Args: []string{
			"__tcp_echo_server__",
			fmt.Sprintf("%d", containerPort),
		},
	}

	runner := NewRunner(cfg)

	errCh := make(chan error, 1)
	go func() {
		res, err := runner.Run()
		if err != nil {
			errCh <- err
			return
		}
		if res.ExitCode != 0 {
			errCh <- fmt.Errorf("container exited with code %d: stderr=%q stdout=%q", res.ExitCode, res.Stderr, res.Stdout)
			return
		}
		errCh <- nil
	}()

	var conn net.Conn
	var dialErr error

	endpoints := []string{
		fmt.Sprintf("10.200.0.1:%d", hostPort),
		fmt.Sprintf("127.0.0.1:%d", hostPort),
	}

	for i := 0; i < 50; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("container failed before connection: %v", err)
			}
		default:
		}

		time.Sleep(100 * time.Millisecond)
		for _, ep := range endpoints {
			conn, dialErr = net.DialTimeout("tcp", ep, 150*time.Millisecond)
			if dialErr == nil {
				break
			}
		}
		if dialErr == nil {
			break
		}
	}

	if dialErr != nil {
		t.Fatalf("failed to connect to host port %d: %v", hostPort, dialErr)
	}
	defer func() {
		_ = conn.Close()
	}()

	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("failed reading through forwarded port: %v", err)
	}

	received := strings.TrimSpace(string(buf[:n]))
	if received != "jail-ack" {
		t.Errorf("expected 'jail-ack', got %q", received)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("container error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for container exit")
	}
}

func TestIntegration_NetworkModeBridge_CustomDNS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping custom DNS test; root privileges required")
	}

	cfg := Config{
		ID:               fmt.Sprintf("test-net-dns-%d", time.Now().UnixNano()),
		MemoryLimitBytes: 128 * 1024 * 1024,
		MaxProcesses:     32,
		StorageLimitMB:   64,
		Timeout:          5 * time.Second,
		NetworkMode:      "bridge",
		DNSServers:       []string{"9.9.9.9", "1.1.1.1"},
		Command:          "/bin/sh",
		Args: []string{
			"-c",
			"cat /etc/resolv.conf",
		},
	}

	runner := NewRunner(cfg)
	res, err := runner.Run()
	if err != nil {
		t.Fatalf("failed to run bridge container with custom DNS: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	if !strings.Contains(res.Stdout, "nameserver 9.9.9.9") || !strings.Contains(res.Stdout, "nameserver 1.1.1.1") {
		t.Errorf("resolv.conf did not contain custom DNS servers, got:\n%s", res.Stdout)
	}
}
