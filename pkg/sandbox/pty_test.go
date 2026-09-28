package sandbox

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIntegration_PTYInteractiveExecution(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping test; root privileges required for pty and namespaces")
	}

	pool, err := NewPoolWithStorage(1, 16)
	if err != nil {
		t.Fatalf("failed to initialize pool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Acquire custom interactive worker (non-networked)
	worker, err := pool.AcquireCustom(16, nil, true, []string{"/bin/sh"}, false, "")
	if err != nil {
		t.Fatalf("failed to acquire pty worker: %v", err)
	}

	var mu sync.Mutex
	var output strings.Builder

	handler := PTYIOHandler{
		OnOutput: func(b []byte) {
			mu.Lock()
			output.Write(b)
			mu.Unlock()
		},
	}

	done := make(chan error, 1)
	go func() {
		_, execErr := worker.ExecutePTY(ctx, handler)
		done <- execErr
	}()

	// Send an interactive command and exit
	time.Sleep(100 * time.Millisecond)
	if err := worker.WriteInput([]byte("echo 'pty_active'\nexit\n")); err != nil {
		t.Fatalf("failed to write to pty: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ExecutePTY returned unexpected error: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("interactive pty test timed out")
	}

	mu.Lock()
	captured := output.String()
	mu.Unlock()

	if !strings.Contains(captured, "pty_active") {
		t.Errorf("expected 'pty_active' in pty output, got: %s", captured)
	}
}
