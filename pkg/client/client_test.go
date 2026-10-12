package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
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

func TestClient_StreamLogs(t *testing.T) {
	testCases := []struct {
		name          string
		containerID   string
		follow        bool
		tail          int
		serverFrames  [][]byte
		serverError   string
		expectError   bool
		expectedBytes []byte
	}{
		{
			name:        "Successful static log stream",
			containerID: "cont-123",
			follow:      false,
			tail:        50,
			serverFrames: [][]byte{
				[]byte("line 1\n"),
				[]byte("line 2\n"),
			},
			serverError:   "",
			expectError:   false,
			expectedBytes: []byte("line 1\nline 2\n"),
		},
		{
			name:          "Daemon returns container not found error",
			containerID:   "cont-missing",
			follow:        false,
			tail:          0,
			serverFrames:  nil,
			serverError:   "no logs found for container \"cont-missing\"",
			expectError:   true,
			expectedBytes: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sockPath := filepath.Join(tmpDir, "test_logs.sock")

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
				if dErr := json.NewDecoder(conn).Decode(&req); dErr != nil {
					return
				}

				if req.Action != "logs" || req.TargetID != tc.containerID || req.Follow != tc.follow || req.Tail != tc.tail {
					return
				}

				fw := protocol.NewFrameWriter(conn)
				for _, frame := range tc.serverFrames {
					_ = fw.WriteFrame(protocol.StreamStdout, frame)
				}

				exit := protocol.ExitPayload{ExitCode: 0}
				if tc.serverError != "" {
					exit.ExitCode = 1
					exit.Error = tc.serverError
				}
				_ = fw.WriteExitFrame(exit)
			}()

			c := NewClient(sockPath)
			var out bytes.Buffer

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			sErr := c.StreamLogs(ctx, tc.containerID, tc.follow, tc.tail, &out)
			if tc.expectError {
				if sErr == nil {
					t.Fatalf("expected error containing %q, got nil", tc.serverError)
				}
			} else {
				if sErr != nil {
					t.Fatalf("unexpected error: %v", sErr)
				}
				if !bytes.Equal(out.Bytes(), tc.expectedBytes) {
					t.Fatalf("expected output %q, got %q", string(tc.expectedBytes), out.String())
				}
			}
		})
	}
}

func TestClient_StopJobWithSignal_TableDriven(t *testing.T) {
	testCases := []struct {
		name            string
		targetID        string
		signal          string
		timeoutSec      int
		expectSuccess   bool
		expectedReqSig  string
		expectedReqTime int
	}{
		{
			name:            "Custom SIGTERM with timeout",
			targetID:        "target-job-1",
			signal:          "SIGTERM",
			timeoutSec:      5,
			expectSuccess:   true,
			expectedReqSig:  "SIGTERM",
			expectedReqTime: 5,
		},
		{
			name:            "Immediate SIGKILL",
			targetID:        "target-job-1",
			signal:          "SIGKILL",
			timeoutSec:      0,
			expectSuccess:   true,
			expectedReqSig:  "SIGKILL",
			expectedReqTime: 0,
		},
		{
			name:            "Unknown job returns error",
			targetID:        "nonexistent",
			signal:          "SIGINT",
			timeoutSec:      2,
			expectSuccess:   false,
			expectedReqSig:  "SIGINT",
			expectedReqTime: 2,
		},
	}

	sockPath := filepath.Join(t.TempDir(), "s.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	var mu sync.Mutex
	var lastReq protocol.Request
	reqReceived := make(chan struct{}, 1)

	go func() {
		for {
			conn, aErr := l.Accept()
			if aErr != nil {
				return
			}

			var req protocol.Request
			if dErr := json.NewDecoder(conn).Decode(&req); dErr != nil {
				_ = conn.Close()
				continue
			}

			mu.Lock()
			lastReq = req
			mu.Unlock()

			select {
			case reqReceived <- struct{}{}:
			default:
			}

			var resp protocol.ControlResponse
			if req.TargetID == "target-job-1" {
				resp.Success = true
			} else {
				resp.Success = false
				resp.Error = "container not found"
			}

			_ = json.NewEncoder(conn).Encode(resp)
			_ = conn.Close()
		}
	}()

	c := NewClient(sockPath)

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sErr := c.StopJobWithSignal(tc.targetID, tc.signal, tc.timeoutSec)
			if tc.expectSuccess && sErr != nil {
				t.Fatalf("expected success, got error: %v", sErr)
			}
			if !tc.expectSuccess && sErr == nil {
				t.Fatalf("expected error, got nil")
			}

			<-reqReceived

			mu.Lock()
			req := lastReq
			mu.Unlock()

			if req.Signal != tc.expectedReqSig {
				t.Errorf("expected request Signal=%q, got %q", tc.expectedReqSig, req.Signal)
			}
			if req.TimeoutSec != tc.expectedReqTime {
				t.Errorf("expected request TimeoutSec=%d, got %d", tc.expectedReqTime, req.TimeoutSec)
			}
		})
	}
}
