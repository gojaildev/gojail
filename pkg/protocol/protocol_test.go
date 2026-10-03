package protocol

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestFrameWriter_And_Reader(t *testing.T) {
	buf := new(bytes.Buffer)
	writer := NewFrameWriter(buf)
	reader := NewFrameReader(buf)

	testData := []struct {
		streamType StreamType
		payload    []byte
	}{
		{StreamStdout, []byte("hello world\n")},
		{StreamStderr, []byte("error: something failed\n")},
		{StreamStdin, []byte("input command\n")},
	}

	for _, tc := range testData {
		if err := writer.WriteFrame(tc.streamType, tc.payload); err != nil {
			t.Fatalf("WriteFrame failed for type %d: %v", tc.streamType, err)
		}

		st, payload, err := reader.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame failed for type %d: %v", tc.streamType, err)
		}

		if st != tc.streamType {
			t.Errorf("expected stream type %d, got %d", tc.streamType, st)
		}

		if !bytes.Equal(payload, tc.payload) {
			t.Errorf("expected payload %q, got %q", string(tc.payload), string(payload))
		}
	}
}

func TestWriteExitFrame_And_ParseExitPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	writer := NewFrameWriter(buf)
	reader := NewFrameReader(buf)

	original := ExitPayload{
		ExitCode: 42,
		Duration: 250 * time.Millisecond,
		TimedOut: false,
		Error:    "",
	}

	if err := writer.WriteExitFrame(original); err != nil {
		t.Fatalf("WriteExitFrame failed: %v", err)
	}

	st, raw, err := reader.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if st != StreamExit {
		t.Fatalf("expected stream type %d, got %d", StreamExit, st)
	}

	parsed, err := ParseExitPayload(raw)
	if err != nil {
		t.Fatalf("ParseExitPayload failed: %v", err)
	}

	if parsed.ExitCode != original.ExitCode {
		t.Errorf("expected exit code %d, got %d", original.ExitCode, parsed.ExitCode)
	}
	if parsed.Duration != original.Duration {
		t.Errorf("expected duration %v, got %v", original.Duration, parsed.Duration)
	}
	if parsed.TimedOut != original.TimedOut {
		t.Errorf("expected TimedOut %v, got %v", original.TimedOut, parsed.TimedOut)
	}
}

func TestWriteStatsFrame_And_ParseStatsPayload(t *testing.T) {
	buf := new(bytes.Buffer)
	writer := NewFrameWriter(buf)
	reader := NewFrameReader(buf)

	original := StatsPayload{
		ContainerID:      "test-container-42",
		Timestamp:        time.Now().Truncate(time.Second),
		MemoryBytes:      1024 * 1024 * 32,
		MemoryLimitBytes: 1024 * 1024 * 128,
		PeakMemoryBytes:  1024 * 1024 * 48,
		CPUUsageUS:       450000,
		CPUPercent:       12.5,
		PIDsCurrent:      4,
		PIDsLimit:        32,
	}

	if err := writer.WriteStatsFrame(original); err != nil {
		t.Fatalf("WriteStatsFrame failed: %v", err)
	}

	st, raw, err := reader.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if st != StreamStats {
		t.Fatalf("expected stream type %d, got %d", StreamStats, st)
	}

	parsed, err := ParseStatsPayload(raw)
	if err != nil {
		t.Fatalf("ParseStatsPayload failed: %v", err)
	}

	if parsed.ContainerID != original.ContainerID {
		t.Errorf("expected container ID %q, got %q", original.ContainerID, parsed.ContainerID)
	}
	if parsed.MemoryBytes != original.MemoryBytes {
		t.Errorf("expected memory %d, got %d", original.MemoryBytes, parsed.MemoryBytes)
	}
	if parsed.CPUPercent != original.CPUPercent {
		t.Errorf("expected CPU%% %f, got %f", original.CPUPercent, parsed.CPUPercent)
	}
}

func TestWindowSize_Encode_Decode(t *testing.T) {
	originalRows := uint16(45)
	originalCols := uint16(120)

	payload := EncodeWindowSize(originalRows, originalCols)
	ws, err := ParseWindowSize(payload)
	if err != nil {
		t.Fatalf("ParseWindowSize failed: %v", err)
	}

	if ws.Rows != originalRows {
		t.Errorf("expected rows %d, got %d", originalRows, ws.Rows)
	}
	if ws.Cols != originalCols {
		t.Errorf("expected cols %d, got %d", originalCols, ws.Cols)
	}

	if _, err := ParseWindowSize([]byte{1, 2}); err == nil {
		t.Error("expected error parsing truncated window size payload, got nil")
	}
}

func TestFrameReader_EOF(t *testing.T) {
	buf := new(bytes.Buffer)
	reader := NewFrameReader(buf)

	_, _, err := reader.ReadFrame()
	if err != io.EOF {
		t.Errorf("expected io.EOF on empty buffer, got %v", err)
	}
}
