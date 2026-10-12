package server

import (
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestJobRegistry_RegisterAndList(t *testing.T) {
	reg := NewJobRegistry()

	reg.Register("job-1", 1001, "/bin/sh", []string{"-c", "echo hello"}, func() {})
	reg.Register("job-2", 1002, "/bin/sleep", []string{"10"}, func() {})

	jobs := reg.List()
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(jobs))
	}

	foundMap := make(map[string]bool)
	for _, j := range jobs {
		foundMap[j.ID] = true
		if j.Status != "running" {
			t.Errorf("job %s expected running status, got %s", j.ID, j.Status)
		}
	}

	if !foundMap["job-1"] || !foundMap["job-2"] {
		t.Errorf("expected both jobs in list: %+v", foundMap)
	}
}

func TestJobRegistry_UpdateFinished(t *testing.T) {
	reg := NewJobRegistry()

	reg.Register("job-1", 1001, "/bin/true", nil, func() {})
	reg.UpdateFinished("job-1", 0, 1024*1024, false)

	jobs := reg.List()
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}

	if jobs[0].Status != "completed" {
		t.Errorf("expected status 'completed', got %s", jobs[0].Status)
	}
	if jobs[0].ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", jobs[0].ExitCode)
	}

	reg.Register("job-2", 1002, "/bin/false", nil, func() {})
	reg.UpdateFinished("job-2", 1, 2048*1024, false)

	for _, j := range reg.List() {
		if j.ID == "job-2" && j.Status != "failed" {
			t.Errorf("expected status 'failed', got %s", j.Status)
		}
	}
}

func TestJobRegistry_Stop(t *testing.T) {
	reg := NewJobRegistry()

	canceled := false
	cancel := func() {
		canceled = true
	}

	reg.Register("job-1", 1234, "/bin/sleep", []string{"100"}, cancel)

	if err := reg.Stop("job-1"); err != nil {
		t.Fatalf("expected stop to succeed, got %v", err)
	}

	if !canceled {
		t.Errorf("expected cancel func to be invoked on stop")
	}

	jobs := reg.List()
	if jobs[0].Status != "killed" {
		t.Errorf("expected status 'killed', got %s", jobs[0].Status)
	}

	if err := reg.Stop("job-1"); err == nil {
		t.Errorf("expected error when stopping non-running job, got nil")
	}
	if err := reg.Stop("nonexistent"); err == nil {
		t.Errorf("expected error when stopping nonexistent job, got nil")
	}
}

func TestJobRegistry_StopWithSignal_TableDriven(t *testing.T) {
	testCases := []struct {
		name           string
		signal         syscall.Signal
		grace          time.Duration
		finishEarly    bool
		expectedStatus string
		expectCancel   bool
	}{
		{
			name:           "Immediate SIGKILL",
			signal:         syscall.SIGKILL,
			grace:          5 * time.Second,
			finishEarly:    false,
			expectedStatus: "killed",
			expectCancel:   true,
		},
		{
			name:           "Graceful stop completes before timeout",
			signal:         syscall.SIGTERM,
			grace:          200 * time.Millisecond,
			finishEarly:    true,
			expectedStatus: "completed",
			expectCancel:   false,
		},
		{
			name:           "Grace period expires falls back to kill",
			signal:         syscall.SIGTERM,
			grace:          50 * time.Millisecond,
			finishEarly:    false,
			expectedStatus: "killed",
			expectCancel:   true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			reg := NewJobRegistry()
			var mu sync.Mutex
			canceled := false
			cancel := func() {
				mu.Lock()
				canceled = true
				mu.Unlock()
			}

			jobID := "test-" + tc.name
			reg.Register(jobID, 0, "/bin/sleep", []string{"10"}, cancel)

			if tc.finishEarly {
				go func() {
					time.Sleep(15 * time.Millisecond)
					reg.UpdateFinished(jobID, 0, 0, false)
				}()
			}

			err := reg.StopWithSignal(jobID, tc.signal, tc.grace)
			if err != nil {
				t.Fatalf("unexpected stop error: %v", err)
			}

			mu.Lock()
			wasCanceled := canceled
			mu.Unlock()

			if wasCanceled != tc.expectCancel {
				t.Errorf("expected cancel=%v, got %v", tc.expectCancel, wasCanceled)
			}

			info, _, _, _, exists := reg.GetJob(jobID)
			if !exists {
				t.Fatalf("job not found in registry")
			}
			if info.Status != tc.expectedStatus {
				t.Errorf("expected status %q, got %q", tc.expectedStatus, info.Status)
			}
		})
	}
}

func TestParseSignal(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectedSig syscall.Signal
		expectErr   bool
	}{
		{name: "empty defaults to SIGTERM", input: "", expectedSig: syscall.SIGTERM, expectErr: false},
		{name: "named SIGTERM", input: "SIGTERM", expectedSig: syscall.SIGTERM, expectErr: false},
		{name: "named TERM", input: "TERM", expectedSig: syscall.SIGTERM, expectErr: false},
		{name: "lowercase sigkill", input: "sigkill", expectedSig: syscall.SIGKILL, expectErr: false},
		{name: "named INT", input: "INT", expectedSig: syscall.SIGINT, expectErr: false},
		{name: "numeric 9", input: "9", expectedSig: syscall.Signal(9), expectErr: false},
		{name: "numeric 15", input: "15", expectedSig: syscall.Signal(15), expectErr: false},
		{name: "invalid signal", input: "NOT_A_SIGNAL", expectedSig: 0, expectErr: true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sig, err := ParseSignal(tc.input)
			if tc.expectErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.input)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
			}
			if !tc.expectErr && sig != tc.expectedSig {
				t.Errorf("expected signal %v, got %v", tc.expectedSig, sig)
			}
		})
	}
}

func TestJobRegistry_PauseAndUnpauseValidation(t *testing.T) {
	reg := NewJobRegistry()

	if err := reg.Pause("missing"); err == nil {
		t.Errorf("expected error pausing nonexistent job, got nil")
	}
	if err := reg.Unpause("missing"); err == nil {
		t.Errorf("expected error unpausing nonexistent job, got nil")
	}
}
