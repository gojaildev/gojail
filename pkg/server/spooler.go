package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arkrix/gojail/pkg/protocol"
)

// LogSpooler manages per-container append-only log files and streaming subscribers.
type LogSpooler struct {
	logsDir string
	mu      sync.RWMutex
	files   map[string]*os.File
}

// NewLogSpooler initializes a spooler writing logs to logsDir.
func NewLogSpooler(logsDir string) *LogSpooler {
	return &LogSpooler{
		logsDir: logsDir,
		files:   make(map[string]*os.File),
	}
}

// LogFilePath returns the expected log file path for a container ID.
func (ls *LogSpooler) LogFilePath(containerID string) string {
	return filepath.Join(ls.logsDir, fmt.Sprintf("%s.log", containerID))
}

// Open creates or opens the container log file in append mode.
func (ls *LogSpooler) Open(containerID string) (*os.File, error) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if err := os.MkdirAll(ls.logsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %w", err)
	}

	p := ls.LogFilePath(containerID)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open container log file %s: %w", p, err)
	}

	ls.files[containerID] = f
	return f, nil
}

// Close closes the active log writer for a container.
func (ls *LogSpooler) Close(containerID string) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if f, exists := ls.files[containerID]; exists {
		_ = f.Sync()
		_ = f.Close()
		delete(ls.files, containerID)
	}
}

// Write writes bytes into the container log file.
func (ls *LogSpooler) Write(containerID string, chunk []byte) (int, error) {
	ls.mu.RLock()
	f, exists := ls.files[containerID]
	ls.mu.RUnlock()

	if !exists || f == nil {
		return 0, nil
	}
	return f.Write(chunk)
}

// StreamLogs reads log history for containerID, applies tail filtering, and optionally follows new writes.
func (ls *LogSpooler) StreamLogs(ctx context.Context, fw *protocol.FrameWriter, containerID string, tail int, follow bool, isRunning func() bool) error {
	logPath := ls.LogFilePath(containerID)

	file, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no logs found for container %q", containerID)
		}
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	if tail > 0 {
		lines, rErr := tailLines(file, tail)
		if rErr != nil {
			return fmt.Errorf("failed to tail logs: %w", rErr)
		}
		for _, line := range lines {
			if err := fw.WriteFrame(protocol.StreamStdout, []byte(line+"\n")); err != nil {
				return err
			}
		}
	} else {
		buf := make([]byte, 32*1024)
		for {
			n, rErr := file.Read(buf)
			if n > 0 {
				if err := fw.WriteFrame(protocol.StreamStdout, buf[:n]); err != nil {
					return err
				}
			}
			if rErr != nil {
				break
			}
		}
	}

	if !follow {
		return nil
	}

	reader := bufio.NewReader(file)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for {
				line, rErr := reader.ReadBytes('\n')
				if len(line) > 0 {
					if err := fw.WriteFrame(protocol.StreamStdout, line); err != nil {
						return err
					}
				}
				if rErr != nil {
					break
				}
			}

			if !isRunning() {
				// Flush any remaining bytes before exiting follow loop
				for {
					line, rErr := reader.ReadBytes('\n')
					if len(line) > 0 {
						_ = fw.WriteFrame(protocol.StreamStdout, line)
					}
					if rErr != nil {
						break
					}
				}
				return nil
			}
		}
	}
}

// tailLines reads the last n lines from a file using an offset scan.
func tailLines(f *os.File, n int) ([]string, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	if size == 0 {
		return nil, nil
	}

	var lines []string
	var cursor int64
	buf := make([]byte, 1)

	currentLine := make([]byte, 0)
	for cursor = size - 1; cursor >= 0; cursor-- {
		if _, err := f.Seek(cursor, io.SeekStart); err != nil {
			return nil, err
		}
		if _, err := f.Read(buf); err != nil {
			return nil, err
		}

		if buf[0] == '\n' && len(currentLine) > 0 {
			lines = append([]string{string(reverseBytes(currentLine))}, lines...)
			currentLine = currentLine[:0]
			if len(lines) == n {
				break
			}
		} else if buf[0] != '\n' {
			currentLine = append(currentLine, buf[0])
		}
	}

	if len(currentLine) > 0 && len(lines) < n {
		lines = append([]string{string(reverseBytes(currentLine))}, lines...)
	}

	return lines, nil
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
