package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
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
	Action           string                `json:"action,omitempty"` // "run", "list", "stop", "stats", "exec", "logs"
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
	Follow           bool                  `json:"follow,omitempty"`
	Tail             int                   `json:"tail,omitempty"`
	Signal           string                `json:"signal,omitempty"`
	TimeoutSec       int                   `json:"timeout_sec"`
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
	Status          string        `json:"status"` // "running", "completed", "failed", "killed", "timed_out", "stopped"
	ExitCode        int           `json:"exit_code"`
	PeakMemoryBytes int64         `json:"peak_memory_bytes"`
	Duration        time.Duration `json:"duration"`
	StartTime       time.Time     `json:"start_time"`
}

// ControlResponse is returned for synchronous RPC actions (list, stop, pause, unpause).
type ControlResponse struct {
	Success bool      `json:"success"`
	Error   string    `json:"error,omitempty"`
	Jobs    []JobInfo `json:"jobs,omitempty"`
}

// ExitPayload is packed into a StreamExit frame upon completion of an execution.
type ExitPayload struct {
	ExitCode int                     `json:"exit_code"`
	Duration time.Duration           `json:"duration"`
	TimedOut bool                    `json:"timed_out"`
	Metrics  sandbox.ResourceMetrics `json:"metrics"`
	Error    string                  `json:"error,omitempty"`
}

// WindowSize holds terminal row and column dimensions for PTY operations.
type WindowSize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// FrameWriter encapsulates the low-level multiplexing protocol over a raw stream.
type FrameWriter struct {
	w io.Writer
}

// NewFrameWriter wraps an io.Writer with framing support.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteFrame transmits an individual protocol frame.
func (fw *FrameWriter) WriteFrame(streamType StreamType, payload []byte) error {
	header := make([]byte, 5)
	header[0] = byte(streamType)
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))

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

// WriteExitFrame encodes and emits a StreamExit frame.
func (fw *FrameWriter) WriteExitFrame(exit ExitPayload) error {
	data, err := json.Marshal(exit)
	if err != nil {
		return err
	}
	return fw.WriteFrame(StreamExit, data)
}

// WriteStatsFrame serializes and transmits a single telemetry metric snapshot frame.
func (fw *FrameWriter) WriteStatsFrame(stats StatsPayload) error {
	data, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	return fw.WriteFrame(StreamStats, data)
}

// FrameReader decodes binary-framed streams.
type FrameReader struct {
	r io.Reader
}

// NewFrameReader wraps an io.Reader to parse incoming frames.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// ReadFrame parses the next frame from the input stream.
func (fr *FrameReader) ReadFrame() (StreamType, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(fr.r, header); err != nil {
		return 0, nil, err
	}

	streamType := StreamType(header[0])
	length := binary.BigEndian.Uint32(header[1:5])

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return 0, nil, err
		}
	}

	return streamType, payload, nil
}

// ParseExitPayload decodes a raw StreamExit frame body.
func ParseExitPayload(payload []byte) (*ExitPayload, error) {
	var exit ExitPayload
	if err := json.Unmarshal(payload, &exit); err != nil {
		return nil, err
	}
	return &exit, nil
}

// ParseStatsPayload decodes a raw StreamStats frame body.
func ParseStatsPayload(payload []byte) (*StatsPayload, error) {
	var stats StatsPayload
	if err := json.Unmarshal(payload, &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

// EncodeWindowSize packs terminal row and column values into binary format.
func EncodeWindowSize(rows, cols uint16) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], rows)
	binary.BigEndian.PutUint16(buf[2:4], cols)
	return buf
}

// ParseWindowSize unpacks binary-encoded row and column metrics.
func ParseWindowSize(data []byte) (*WindowSize, error) {
	if len(data) < 4 {
		return nil, errors.New("invalid window size payload: too short")
	}
	return &WindowSize{
		Rows: binary.BigEndian.Uint16(data[0:2]),
		Cols: binary.BigEndian.Uint16(data[2:4]),
	}, nil
}
