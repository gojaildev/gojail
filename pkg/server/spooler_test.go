package server

import (
	"bytes"
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkrix/gojail/pkg/protocol"
)

func TestLogSpooler_LifecycleAndTailing(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gojail-spooler-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	spooler := NewLogSpooler(tempDir)

	testCases := []struct {
		name          string
		containerID   string
		writes        []string
		tail          int
		follow        bool
		expectedLines int
	}{
		{
			name:          "Read full logs without tail limit",
			containerID:   "cont-full",
			writes:        []string{"line1\n", "line2\n", "line3\n"},
			tail:          0,
			follow:        false,
			expectedLines: 3,
		},
		{
			name:          "Tail last 2 lines",
			containerID:   "cont-tail",
			writes:        []string{"alpha\n", "beta\n", "gamma\n", "delta\n"},
			tail:          2,
			follow:        false,
			expectedLines: 2,
		},
		{
			name:          "Tail requested lines exceeding available count",
			containerID:   "cont-exceed",
			writes:        []string{"one\n", "two\n"},
			tail:          10,
			follow:        false,
			expectedLines: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, oErr := spooler.Open(tc.containerID)
			if oErr != nil {
				t.Fatalf("Open failed: %v", oErr)
			}

			for _, w := range tc.writes {
				if _, err := spooler.Write(tc.containerID, []byte(w)); err != nil {
					t.Fatalf("Write failed: %v", err)
				}
			}
			spooler.Close(tc.containerID)

			var outBuf bytes.Buffer
			fw := protocol.NewFrameWriter(&outBuf)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := spooler.StreamLogs(ctx, fw, tc.containerID, tc.tail, tc.follow, func() bool {
				return false
			})
			if err != nil {
				t.Fatalf("StreamLogs failed: %v", err)
			}

			fr := protocol.NewFrameReader(&outBuf)
			receivedLines := 0
			for {
				streamType, payload, rErr := fr.ReadFrame()
				if rErr != nil {
					break
				}
				if streamType == protocol.StreamStdout && len(payload) > 0 {
					lines := bytes.Split(bytes.TrimSuffix(payload, []byte("\n")), []byte("\n"))
					receivedLines += len(lines)
				}
			}

			if receivedLines != tc.expectedLines {
				t.Fatalf("expected %d lines, received %d", tc.expectedLines, receivedLines)
			}
		})
	}
}

func TestLogSpooler_MissingFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gojail-spooler-missing-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	spooler := NewLogSpooler(tempDir)
	var outBuf bytes.Buffer
	fw := protocol.NewFrameWriter(&outBuf)

	testCases := []struct {
		name        string
		containerID string
	}{
		{
			name:        "Nonexistent container returns error",
			containerID: "non-existent-id",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := spooler.StreamLogs(context.Background(), fw, tc.containerID, 0, false, func() bool { return false })
			if err == nil {
				t.Fatal("expected error for non-existent container log, got nil")
			}
		})
	}
}

func TestLogSpooler_FollowStreaming(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gojail-spooler-follow-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	spooler := NewLogSpooler(tempDir)
	containerID := "cont-follow-test"

	_, err = spooler.Open(containerID)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	_, _ = spooler.Write(containerID, []byte("initial\n"))

	var outBuf bytes.Buffer
	fw := protocol.NewFrameWriter(&outBuf)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var running atomic.Bool
	running.Store(true)

	doneCh := make(chan error, 1)

	go func() {
		doneCh <- spooler.StreamLogs(ctx, fw, containerID, 0, true, func() bool {
			return running.Load()
		})
	}()

	time.Sleep(150 * time.Millisecond)
	_, _ = spooler.Write(containerID, []byte("followed\n"))
	time.Sleep(150 * time.Millisecond)

	running.Store(false)
	spooler.Close(containerID)

	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("StreamLogs returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StreamLogs timed out waiting for follow to finish")
	}

	content := outBuf.String()
	if !bytes.Contains([]byte(content), []byte("initial")) || !bytes.Contains([]byte(content), []byte("followed")) {
		t.Fatalf("expected output to contain both initial and followed chunks, got: %q", content)
	}
}
