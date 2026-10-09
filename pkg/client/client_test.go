package client

import (
	"bytes"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/arkrix/gojail/pkg/network"
	"github.com/arkrix/gojail/pkg/protocol"
)

func TestClient_Run(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	go func() {
		conn, aErr := l.Accept()
		if aErr != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		// Read the incoming client request first to prevent broken pipe (RST)
		var req protocol.Request
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}

		fw := protocol.NewFrameWriter(conn)
		_ = fw.WriteFrame(protocol.StreamStdout, []byte("hello from daemon"))
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 0,
			Duration: 10 * time.Millisecond,
		})
	}()

	c := NewClient(sockPath)
	resp, err := c.Run(ExecOptions{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if resp.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", resp.ExitCode)
	}
}

func TestClient_Run_WithNetworkOptions(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_net.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	var receivedReq protocol.Request
	go func() {
		conn, aErr := l.Accept()
		if aErr != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		if err := json.NewDecoder(conn).Decode(&receivedReq); err != nil {
			return
		}

		fw := protocol.NewFrameWriter(conn)
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 0,
		})
	}()

	c := NewClient(sockPath)
	_, err = c.Run(ExecOptions{
		Command:     "/bin/echo",
		NetworkMode: "bridge",
		PortMappings: []network.PortMapping{
			{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if receivedReq.NetworkMode != "bridge" {
		t.Errorf("expected NetworkMode 'bridge', got %q", receivedReq.NetworkMode)
	}
	if len(receivedReq.PortMappings) != 1 {
		t.Fatalf("expected 1 port mapping, got %d", len(receivedReq.PortMappings))
	}
	if receivedReq.PortMappings[0].HostPort != 8080 || receivedReq.PortMappings[0].ContainerPort != 80 {
		t.Errorf("port mapping corrupted in wire transit: %+v", receivedReq.PortMappings[0])
	}
}

func TestClient_ConnectionRefused(t *testing.T) {
	c := NewClient("/tmp/nonexistent_gojail_socket.sock")
	_, err := c.Run(ExecOptions{
		Command: "/bin/echo",
	})
	if err == nil {
		t.Errorf("expected error on missing socket, got nil")
	}
}

func TestClient_StreamStats(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_stats.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	go func() {
		conn, aErr := l.Accept()
		if aErr != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		var req protocol.Request
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}

		fw := protocol.NewFrameWriter(conn)
		_ = fw.WriteStatsFrame(protocol.StatsPayload{
			ContainerID:      "test-jail-1",
			Timestamp:        time.Now(),
			MemoryBytes:      32 * 1024 * 1024,
			MemoryLimitBytes: 128 * 1024 * 1024,
			PeakMemoryBytes:  40 * 1024 * 1024,
			CPUPercent:       15.5,
			PIDsCurrent:      3,
			PIDsLimit:        64,
		})
		_ = fw.WriteExitFrame(protocol.ExitPayload{ExitCode: 0})
	}()

	c := NewClient(sockPath)
	receivedSamples := 0

	err = c.StreamStats("test-jail-1", func(s protocol.StatsPayload) {
		receivedSamples++
		if s.ContainerID != "test-jail-1" {
			t.Errorf("expected container ID 'test-jail-1', got %s", s.ContainerID)
		}
		if s.CPUPercent != 15.5 {
			t.Errorf("expected CPU percent 15.5, got %.2f", s.CPUPercent)
		}
		if s.PIDsCurrent != 3 {
			t.Errorf("expected 3 current PIDs, got %d", s.PIDsCurrent)
		}
	})

	if err != nil {
		t.Fatalf("StreamStats failed: %v", err)
	}

	if receivedSamples != 1 {
		t.Fatalf("expected 1 sample, got %d", receivedSamples)
	}
}

func TestClient_PauseAndUnpause(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_pause.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	go func() {
		for {
			conn, aErr := l.Accept()
			if aErr != nil {
				return
			}

			var req protocol.Request
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = conn.Close()
				continue
			}

			var resp protocol.ControlResponse
			if req.TargetID == "test-jail-1" && (req.Action == "pause" || req.Action == "unpause") {
				resp.Success = true
			} else {
				resp.Success = false
				resp.Error = "invalid target or action"
			}

			_ = json.NewEncoder(conn).Encode(resp)
			_ = conn.Close()
		}
	}()

	c := NewClient(sockPath)

	if err := c.PauseJob("test-jail-1"); err != nil {
		t.Fatalf("PauseJob failed: %v", err)
	}

	if err := c.UnpauseJob("test-jail-1"); err != nil {
		t.Fatalf("UnpauseJob failed: %v", err)
	}

	if err := c.PauseJob("invalid-id"); err == nil {
		t.Errorf("expected error on invalid target, got nil")
	}
}

func TestClient_ListJobs(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_list.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	expectedJobs := []protocol.JobInfo{
		{
			ID:      "test-job-100",
			PID:     9999,
			Status:  "running",
			Command: "/bin/sh",
		},
	}

	go func() {
		conn, aErr := l.Accept()
		if aErr != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		var req protocol.Request
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}

		if req.Action == "list" {
			_ = json.NewEncoder(conn).Encode(protocol.ControlResponse{
				Success: true,
				Jobs:    expectedJobs,
			})
		}
	}()

	c := NewClient(sockPath)
	jobs, err := c.ListJobs()
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}

	if len(jobs) != 1 || jobs[0].ID != "test-job-100" {
		t.Errorf("unexpected jobs: %+v", jobs)
	}
}

func TestClient_StopJob(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_stop.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	go func() {
		for {
			conn, aErr := l.Accept()
			if aErr != nil {
				return
			}

			var req protocol.Request
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = conn.Close()
				continue
			}

			var resp protocol.ControlResponse
			if req.Action == "stop" && req.TargetID == "running-job" {
				resp.Success = true
			} else {
				resp.Success = false
				resp.Error = "not found"
			}

			_ = json.NewEncoder(conn).Encode(resp)
			_ = conn.Close()
		}
	}()

	c := NewClient(sockPath)
	if err := c.StopJob("running-job"); err != nil {
		t.Fatalf("StopJob failed: %v", err)
	}

	if err := c.StopJob("unknown-job"); err == nil {
		t.Error("expected error for unknown-job, got nil")
	}
}

func TestClient_Exec(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test_exec.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	go func() {
		conn, aErr := l.Accept()
		if aErr != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		var req protocol.Request
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}

		fw := protocol.NewFrameWriter(conn)
		_ = fw.WriteFrame(protocol.StreamStdout, []byte("exec stdout output\n"))
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 0,
		})
	}()

	c := NewClient(sockPath)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code, err := c.Exec(ContainerExecOptions{
		ContainerID: "running-jail",
		Command:     "ls",
		Args:        []string{"-la"},
		Stdout:      &stdout,
		Stderr:      &stderr,
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !bytes.Contains(stdout.Bytes(), []byte("exec stdout output")) {
		t.Errorf("expected stdout to contain test string, got: %s", stdout.String())
	}
}
