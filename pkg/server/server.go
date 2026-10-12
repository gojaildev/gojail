package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/arkrix/gojail/pkg/config"
	"github.com/arkrix/gojail/pkg/network"
	"github.com/arkrix/gojail/pkg/protocol"
	"github.com/arkrix/gojail/pkg/sandbox"
	"github.com/creack/pty"
)

// Request defines the wire format sent by clients over the Unix socket.
type Request = protocol.Request

// Daemon represents the long-running gojaild server instance.
type Daemon struct {
	cfg      *config.DaemonConfig
	listener net.Listener
	shutdown chan struct{}
	wg       sync.WaitGroup
	pool     *sandbox.Pool
	registry *JobRegistry
	spooler  *LogSpooler
	lockFile *os.File
}

// NewDaemon initializes a new Unix socket daemon driven by DaemonConfig.
func NewDaemon(cfg *config.DaemonConfig) *Daemon {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Daemon{
		cfg:      cfg,
		registry: NewJobRegistry(),
		spooler:  NewLogSpooler(cfg.Storage.LogsDir),
		shutdown: make(chan struct{}),
	}
}

// Start acquires the daemon lock, executes crash recovery, warms sandboxes, and starts accepting requests.
func (d *Daemon) Start() error {
	lockFile, err := AcquireDaemonLock("/var/run/gojaild.pid")
	if err != nil {
		return fmt.Errorf("daemon start aborted: %w", err)
	}
	d.lockFile = lockFile

	if unmounted, err := SweepStaleMounts(defaultLayersDir); err != nil {
		fmt.Fprintf(os.Stderr, "[recovery] Error sweeping mounts: %v\n", err)
	} else if unmounted > 0 {
		fmt.Printf("[recovery] Cleaned %d orphaned mount points from previous runs\n", unmounted)
	}

	if err := ResetLayersTree(defaultLayersDir); err != nil {
		fmt.Fprintf(os.Stderr, "[recovery] Error resetting layers: %v\n", err)
	}

	if err := SweepStaleCgroups(); err != nil {
		fmt.Fprintf(os.Stderr, "[recovery] Error sweeping cgroups: %v\n", err)
	}

	poolSize := d.cfg.Pool.WarmWorkers
	if poolSize <= 0 {
		poolSize = 2
	}

	storageLimit := d.cfg.Defaults.StorageLimitMB
	if storageLimit <= 0 {
		storageLimit = 64
	}

	pool, err := sandbox.NewPoolWithStorage(poolSize, storageLimit)
	if err != nil {
		return fmt.Errorf("failed to initialize warm pool: %w", err)
	}
	d.pool = pool

	_ = os.Remove(d.cfg.Server.SocketPath)

	l, err := net.Listen("unix", d.cfg.Server.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket %s: %w", d.cfg.Server.SocketPath, err)
	}
	d.listener = l

	if err := os.Chmod(d.cfg.Server.SocketPath, os.FileMode(d.cfg.Server.SocketMode)); err != nil {
		return fmt.Errorf("failed to chmod socket %s: %w", d.cfg.Server.SocketPath, err)
	}

	d.wg.Add(1)
	go d.acceptLoop()

	return nil
}

func (d *Daemon) acceptLoop() {
	defer d.wg.Done()

	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-d.shutdown:
				return
			default:
				fmt.Fprintf(os.Stderr, "[gojaild] Accept error: %v\n", err)
				continue
			}
		}

		d.wg.Add(1)
		go func(c net.Conn) {
			defer d.wg.Done()
			d.handleConnection(c)
		}(conn)
	}
}

func (d *Daemon) handleConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	frameWriter := protocol.NewFrameWriter(conn)
	frameReader := protocol.NewFrameReader(conn)

	var req protocol.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
				ExitCode: 1,
				Error:    fmt.Sprintf("invalid request payload: %v", err),
			})
		}
		return
	}

	switch req.Action {
	case "list":
		jobs := d.registry.List()
		_ = json.NewEncoder(conn).Encode(protocol.ControlResponse{
			Success: true,
			Jobs:    jobs,
		})
		return

	case "stop":
		sig, parseErr := ParseSignal(req.Signal)
		if parseErr != nil {
			resp := protocol.ControlResponse{
				Success: false,
				Error:   parseErr.Error(),
			}
			_ = json.NewEncoder(conn).Encode(resp)
			return
		}

		grace := 10 * time.Second
		if req.TimeoutSec > 0 {
			grace = time.Duration(req.TimeoutSec) * time.Second
		} else if req.TimeoutSec < 0 {
			grace = 0
		}

		err := d.registry.StopWithSignal(req.TargetID, sig, grace)
		resp := protocol.ControlResponse{Success: err == nil}
		if err != nil {
			resp.Error = err.Error()
		}
		_ = json.NewEncoder(conn).Encode(resp)
		return

	case "pause":
		err := d.registry.Pause(req.TargetID)
		resp := protocol.ControlResponse{Success: err == nil}
		if err != nil {
			resp.Error = err.Error()
		}
		_ = json.NewEncoder(conn).Encode(resp)
		return

	case "unpause":
		err := d.registry.Unpause(req.TargetID)
		resp := protocol.ControlResponse{Success: err == nil}
		if err != nil {
			resp.Error = err.Error()
		}
		_ = json.NewEncoder(conn).Encode(resp)
		return

	case "stats":
		d.handleStatsStream(conn, frameWriter, req.TargetID)
		return

	case "exec":
		d.handleExec(conn, frameWriter, frameReader, req)
		return

	case "logs":
		d.handleLogsStream(conn, frameWriter, req)
		return
	}

	if req.Timeout == 0 {
		req.Timeout = time.Duration(d.cfg.Defaults.TimeoutSec) * time.Second
	}
	if req.MemoryLimitBytes == 0 {
		req.MemoryLimitBytes = d.cfg.Defaults.MemoryLimitMB * 1024 * 1024
	}
	if req.MaxProcesses == 0 {
		req.MaxProcesses = d.cfg.Defaults.MaxProcesses
	}
	if req.StorageLimitMB == 0 {
		req.StorageLimitMB = d.cfg.Defaults.StorageLimitMB
	}

	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()

	initialCmd := []string{req.Command}
	if len(req.Args) > 0 {
		initialCmd = append(initialCmd, req.Args...)
	}

	requiresNetwork := req.NetworkMode == "bridge" || len(req.PortMappings) > 0 || len(req.DNSServers) > 0
	worker, err := d.pool.AcquireCustom(req.StorageLimitMB, req.Mounts, req.TTY, initialCmd, requiresNetwork, req.Image)
	if err != nil {
		_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    fmt.Sprintf("worker acquire failed: %v", err),
		})
		return
	}

	// Setup bridge network & port forwarding if requested
	if requiresNetwork {
		netMgr := network.NewManager()
		if err := netMgr.SetupContainerNetwork(worker.ID, worker.PID(), worker.RootPath(), req.PortMappings, req.DNSServers); err != nil {
			worker.Destroy()
			d.registry.UpdateFinished(worker.ID, 1, 0, false)
			_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
				ExitCode: 1,
				Error:    fmt.Sprintf("failed to setup worker network: %v", err),
			})
			return
		}
		defer netMgr.Cleanup(worker.ID, req.PortMappings)
	}

	d.registry.Register(worker.ID, worker.PID(), req.Command, req.Args, cancel)
	d.registry.AttachCgroup(worker.ID, worker.Cgroup(), req.MemoryLimitBytes, req.MaxProcesses)

	if d.spooler != nil {
		_, _ = d.spooler.Open(worker.ID)
		defer d.spooler.Close(worker.ID)
	}

	var writeMu sync.Mutex

	if req.TTY {
		go func() {
			for {
				streamType, payload, rErr := frameReader.ReadFrame()
				if rErr != nil {
					break
				}
				switch streamType {
				case protocol.StreamStdin:
					_ = worker.WriteInput(payload)
				case protocol.StreamResize:
					ws, pErr := protocol.ParseWindowSize(payload)
					if pErr == nil {
						_ = worker.Resize(ws.Rows, ws.Cols)
					}
				}
			}
		}()

		ptyHandler := sandbox.PTYIOHandler{
			OnOutput: func(chunk []byte) {
				writeMu.Lock()
				_ = frameWriter.WriteFrame(protocol.StreamStdout, chunk)
				if d.spooler != nil {
					_, _ = d.spooler.Write(worker.ID, chunk)
				}
				writeMu.Unlock()
			},
		}

		res, ptyErr := worker.ExecutePTY(ctx, ptyHandler)
		if ptyErr != nil {
			d.registry.UpdateFinished(worker.ID, 1, 0, false)
			_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
				ExitCode: 1,
				Error:    ptyErr.Error(),
			})
			return
		}

		d.registry.UpdateFinished(worker.ID, res.ExitCode, res.Metrics.PeakMemoryBytes, res.TimedOut)

		_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
			ExitCode: res.ExitCode,
			Duration: res.Duration,
			TimedOut: res.TimedOut,
			Metrics:  res.Metrics,
		})
		return
	}

	script := strings.Join(req.Args, " ")
	if len(req.Args) >= 2 && req.Args[0] == "-c" {
		script = req.Args[1]
	}

	handler := sandbox.StreamHandler{
		OnStdout: func(chunk []byte) {
			writeMu.Lock()
			_ = frameWriter.WriteFrame(protocol.StreamStdout, chunk)
			if d.spooler != nil {
				_, _ = d.spooler.Write(worker.ID, chunk)
			}
			writeMu.Unlock()
		},
		OnStderr: func(chunk []byte) {
			writeMu.Lock()
			_ = frameWriter.WriteFrame(protocol.StreamStderr, chunk)
			if d.spooler != nil {
				_, _ = d.spooler.Write(worker.ID, chunk)
			}
			writeMu.Unlock()
		},
	}

	res, err := worker.ExecuteStream(ctx, script, handler)
	if err != nil {
		d.registry.UpdateFinished(worker.ID, 1, 0, false)
		_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    err.Error(),
		})
		return
	}

	d.registry.UpdateFinished(worker.ID, res.ExitCode, res.Metrics.PeakMemoryBytes, res.TimedOut)

	_ = frameWriter.WriteExitFrame(protocol.ExitPayload{
		ExitCode: res.ExitCode,
		Duration: res.Duration,
		TimedOut: res.TimedOut,
		Metrics:  res.Metrics,
	})
}

func (d *Daemon) handleExec(conn net.Conn, fw *protocol.FrameWriter, fr *protocol.FrameReader, req protocol.Request) {
	jobInfo, cg, _, _, exists := d.registry.GetJob(req.TargetID)
	if !exists {
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    fmt.Sprintf("container %q not found", req.TargetID),
		})
		return
	}

	if jobInfo.Status != "running" {
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    fmt.Sprintf("container %q is not running (status: %s)", req.TargetID, jobInfo.Status),
		})
		return
	}

	selfBin, err := os.Executable()
	if err != nil {
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    fmt.Sprintf("failed to resolve binary path: %v", err),
		})
		return
	}

	execPayload := struct {
		TargetPID int      `json:"target_pid"`
		Command   string   `json:"command"`
		Args      []string `json:"args"`
		Env       []string `json:"env"`
	}{
		TargetPID: jobInfo.PID,
		Command:   req.Command,
		Args:      req.Args,
		Env:       req.Env,
	}

	data, err := json.Marshal(execPayload)
	if err != nil {
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    fmt.Sprintf("failed to serialize exec payload: %v", err),
		})
		return
	}

	cmd := exec.Command(selfBin, "__init_exec__", string(data))

	var writeMu sync.Mutex

	if req.TTY {
		ptmx, err := pty.Start(cmd)
		if err != nil {
			_ = fw.WriteExitFrame(protocol.ExitPayload{
				ExitCode: 1,
				Error:    fmt.Sprintf("failed to allocate pty for exec: %v", err),
			})
			return
		}
		defer func() { _ = ptmx.Close() }()

		if cg != nil {
			_ = cg.AttachPID(cmd.Process.Pid)
		}

		go func() {
			for {
				streamType, payload, rErr := fr.ReadFrame()
				if rErr != nil {
					break
				}
				switch streamType {
				case protocol.StreamStdin:
					_, _ = ptmx.Write(payload)
				case protocol.StreamResize:
					ws, pErr := protocol.ParseWindowSize(payload)
					if pErr == nil {
						_ = pty.Setsize(ptmx, &pty.Winsize{Rows: ws.Rows, Cols: ws.Cols})
					}
				}
			}
		}()

		buf := make([]byte, 4096)
		for {
			n, rErr := ptmx.Read(buf)
			if n > 0 {
				writeMu.Lock()
				_ = fw.WriteFrame(protocol.StreamStdout, buf[:n])
				if d.spooler != nil {
					_, _ = d.spooler.Write(req.TargetID, buf[:n])
				}
				writeMu.Unlock()
			}
			if rErr != nil {
				break
			}
		}

		_ = cmd.Wait()
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}

		_ = fw.WriteExitFrame(protocol.ExitPayload{ExitCode: exitCode})
		return
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = fw.WriteExitFrame(protocol.ExitPayload{ExitCode: 1, Error: err.Error()})
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = fw.WriteExitFrame(protocol.ExitPayload{ExitCode: 1, Error: err.Error()})
		return
	}

	if err := cmd.Start(); err != nil {
		_ = fw.WriteExitFrame(protocol.ExitPayload{ExitCode: 1, Error: err.Error()})
		return
	}

	if cg != nil {
		_ = cg.AttachPID(cmd.Process.Pid)
	}

	var pipeWg sync.WaitGroup
	pipeWg.Add(2)

	go func() {
		defer pipeWg.Done()
		b := make([]byte, 4096)
		for {
			n, rErr := stdoutPipe.Read(b)
			if n > 0 {
				writeMu.Lock()
				_ = fw.WriteFrame(protocol.StreamStdout, b[:n])
				if d.spooler != nil {
					_, _ = d.spooler.Write(req.TargetID, b[:n])
				}
				writeMu.Unlock()
			}
			if rErr != nil {
				break
			}
		}
	}()

	go func() {
		defer pipeWg.Done()
		b := make([]byte, 4096)
		for {
			n, rErr := stderrPipe.Read(b)
			if n > 0 {
				writeMu.Lock()
				_ = fw.WriteFrame(protocol.StreamStderr, b[:n])
				if d.spooler != nil {
					_, _ = d.spooler.Write(req.TargetID, b[:n])
				}
				writeMu.Unlock()
			}
			if rErr != nil {
				break
			}
		}
	}()

	pipeWg.Wait()
	_ = cmd.Wait()

	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	_ = fw.WriteExitFrame(protocol.ExitPayload{ExitCode: exitCode})
}

func (d *Daemon) handleStatsStream(conn net.Conn, fw *protocol.FrameWriter, targetID string) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.shutdown:
			return
		case <-ticker.C:
			jobInfo, currentCG, curMemLim, curProcLim, exists := d.registry.GetJob(targetID)
			if !exists {
				_ = fw.WriteExitFrame(protocol.ExitPayload{
					ExitCode: 1,
					Error:    fmt.Sprintf("container %q not found", targetID),
				})
				return
			}

			if jobInfo.Status != "running" && jobInfo.Status != "paused" {
				_ = fw.WriteExitFrame(protocol.ExitPayload{
					ExitCode: jobInfo.ExitCode,
					Duration: jobInfo.Duration,
					Error:    fmt.Sprintf("container %q stopped (status: %s)", targetID, jobInfo.Status),
				})
				return
			}

			if currentCG == nil {
				_ = fw.WriteExitFrame(protocol.ExitPayload{
					ExitCode: 1,
					Error:    fmt.Sprintf("cgroup not found for container %q", targetID),
				})
				return
			}

			live, cpuPercent, err := currentCG.SampleStats()
			if err != nil {
				_ = fw.WriteExitFrame(protocol.ExitPayload{
					ExitCode: 1,
					Error:    fmt.Sprintf("failed to read cgroup telemetry: %v", err),
				})
				return
			}

			payload := protocol.StatsPayload{
				ContainerID:      targetID,
				Timestamp:        time.Now(),
				MemoryBytes:      live.MemoryCurrentBytes,
				MemoryLimitBytes: curMemLim,
				PeakMemoryBytes:  live.MemoryPeakBytes,
				CPUUsageUS:       live.CPUUsageUS,
				CPUPercent:       cpuPercent,
				PIDsCurrent:      live.PIDsCurrent,
				PIDsLimit:        curProcLim,
			}

			if err := fw.WriteStatsFrame(payload); err != nil {
				return
			}
		}
	}
}

func (d *Daemon) handleLogsStream(conn net.Conn, fw *protocol.FrameWriter, req protocol.Request) {
	if d.spooler == nil {
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    "log spooling is not enabled on this daemon",
		})
		return
	}

	isRunning := func() bool {
		job, _, _, _, exists := d.registry.GetJob(req.TargetID)
		if !exists {
			return false
		}
		return job.Status == "running" || job.Status == "paused"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := conn.Read(buf); err != nil {
				cancel()
				return
			}
		}
	}()

	err := d.spooler.StreamLogs(ctx, fw, req.TargetID, req.Tail, req.Follow, isRunning)
	if err != nil && !errors.Is(err, context.Canceled) {
		_ = fw.WriteExitFrame(protocol.ExitPayload{
			ExitCode: 1,
			Error:    err.Error(),
		})
		return
	}

	_ = fw.WriteExitFrame(protocol.ExitPayload{ExitCode: 0})
}

// Stop gracefully terminates the listener, stops all active container jobs,
// shuts down workers, and releases the PID lock.
func (d *Daemon) Stop() {
	close(d.shutdown)

	if d.listener != nil {
		_ = d.listener.Close()
	}

	// Cancel/terminate all active jobs so worker goroutines can unblock
	if d.registry != nil {
		for _, job := range d.registry.List() {
			if job.Status == "running" {
				_ = d.registry.Stop(job.ID)
			}
		}
	}

	if d.pool != nil {
		d.pool.Close()
	}

	// Wait with a 3-second grace period for connections to drain cleanly
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		fmt.Fprintln(os.Stderr, "[gojaild] Shutdown wait timed out, proceeding with exit")
	}

	_ = os.Remove(d.cfg.Server.SocketPath)

	if d.lockFile != nil {
		_ = syscall.Flock(int(d.lockFile.Fd()), syscall.LOCK_UN)
		_ = d.lockFile.Close()
		_ = os.Remove("/var/run/gojaild.pid")
	}
}
