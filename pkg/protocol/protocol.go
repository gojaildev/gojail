package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/arkrix/gojail/pkg/network"
	"github.com/arkrix/gojail/pkg/sandbox"
)

type StreamType uint8

const (
	StreamStdout StreamType = 1
	StreamStderr StreamType = 2
	StreamExit   StreamType = 3
	StreamStdin  StreamType = 4
	StreamResize StreamType = 5
	StreamStats  StreamType = 6
)

// Request defines the unified initial JSON payload sent from client to daemon.
type Request struct {
	Action           string                `json:"action,omitempty"` // "run", "list", "stop", "stats"
	TargetID         string                `json:"target_id,omitempty"`
	Command          string                `json:"command,omitempty"`
	Args             []string              `json:"args,omitempty"`
	Env              []string              `json:"env,omitempty"`
	Image            string                `json:"image,omitempty"`
	Timeout          time.Duration         `json:"timeout,omitempty"`
	MemoryLimitBytes int64                 `json:"memory_limit_bytes,omitempty"`
	MaxProcesses     int64                 `json:"max_processes,omitempty"`
	StorageLimitMB   int64                 `json:"storage_limit_mb,omitempty"`
	Mounts           []sandbox.MountSpec   `json:"mounts,omitempty"`
	TTY              bool                  `json:"tty,omitempty"`
	SeccompProfile   string                `json:"seccomp_profile,omitempty"`
	NetworkMode      string                `json:"network_mode,omitempty"`
	PortMappings     []network.PortMapping `json:"port_mappings,omitempty"`
	DNSServers       []string              `json:"dns_servers,omitempty"`
}

// StatsPayload represents a point-in-time metrics sample streamed from daemon to client.
type StatsPayload struct {
	ContainerID      string    `json:"container_id"`
	Timestamp        time.Time `json:"timestamp"`
	MemoryBytes      int64     `json:"memory_bytes"`
	MemoryLimitBytes int64     `json:"memory_limit_bytes"`
	PeakMemoryBytes  int64     `json:"peak_memory_bytes"`
	CPUUsageUS       int64     `json:"cpu_usage_us"`
	CPUPercent       float64   `json:"cpu_percent"`
	PIDsCurrent      int64     `json:"pids_current"`
	PIDsLimit        int64     `json:"pids_limit"`
}

// JobInfo encapsulates runtime metadata about an instance tracked by the daemon.
type JobInfo struct {
	ID              string        `json:"id"`
	PID             int           `json:"pid"`
	Command         string        `json:"command"`
	Args            []string      `json:"args"`
	Status          string        `json:"status"` // "running", "completed", "failed", "killed", "timed_out"
	StartTime       time.Time     `json:"start_time"`
	Duration        time.Duration `json:"duration"`
	PeakMemoryBytes int64         `json:"peak_memory_bytes"`
	ExitCode        int           `json:"exit_code"`
}

// ControlResponse is returned for non-streaming control actions ("list", "stop").
type ControlResponse struct {
	Success bool      `json:"success"`
	Error   string    `json:"error,omitempty"`
	Jobs    []JobInfo `json:"jobs,omitempty"`
}

type WindowSize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

type ExitPayload struct {
	ExitCode int                     `json:"exit_code"`
	Duration time.Duration           `json:"duration"`
	TimedOut bool                    `json:"timed_out"`
	Metrics  sandbox.ResourceMetrics `json:"metrics"`
	Error    string                  `json:"error,omitempty"`
}

type FrameWriter struct {
	w io.Writer
}

func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

func (fw *FrameWriter) WriteFrame(streamType StreamType, payload []byte) error {
	header := make([]byte, 5)
	header[0] = byte(streamType)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))

	if _, err := fw.w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := fw.w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (fw *FrameWriter) WriteExitFrame(payload ExitPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal exit payload: %w", err)
	}
	return fw.WriteFrame(StreamExit, data)
}

func (fw *FrameWriter) WriteStatsFrame(payload StatsPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal stats payload: %w", err)
	}
	return fw.WriteFrame(StreamStats, data)
}

type FrameReader struct {
	r io.Reader
}

func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

func (fr *FrameReader) ReadFrame() (StreamType, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(fr.r, header); err != nil {
		return 0, nil, err
	}

	streamType := StreamType(header[0])
	length := binary.BigEndian.Uint32(header[1:])

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return 0, nil, err
		}
	}

	return streamType, payload, nil
}

func ParseExitPayload(payload []byte) (*ExitPayload, error) {
	var exitPayload ExitPayload
	if err := json.Unmarshal(payload, &exitPayload); err != nil {
		return nil, err
	}
	return &exitPayload, nil
}

func ParseStatsPayload(payload []byte) (*StatsPayload, error) {
	var stats StatsPayload
	if err := json.Unmarshal(payload, &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

func ParseWindowSize(payload []byte) (*WindowSize, error) {
	if len(payload) < 4 {
		return nil, errors.New("invalid resize payload length")
	}
	return &WindowSize{
		Rows: binary.BigEndian.Uint16(payload[0:2]),
		Cols: binary.BigEndian.Uint16(payload[2:4]),
	}, nil
}

func EncodeWindowSize(rows, cols uint16) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], rows)
	binary.BigEndian.PutUint16(buf[2:4], cols)
	return buf
}
