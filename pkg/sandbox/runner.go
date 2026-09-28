package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/arkrix/gojail/pkg/image"
	"github.com/arkrix/gojail/pkg/network"
	"golang.org/x/sys/unix"
)

// Runner orchestrates execution, enforcement, and I/O capturing.
type Runner struct {
	cfg Config
}

// NewRunner initializes a sandbox runner with a given configuration.
func NewRunner(cfg Config) *Runner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxProcesses == 0 {
		cfg.MaxProcesses = 64
	}
	if cfg.MemoryLimitBytes == 0 {
		cfg.MemoryLimitBytes = 128 * 1024 * 1024
	}
	if cfg.StorageLimitMB == 0 {
		cfg.StorageLimitMB = 64
	}
	if cfg.NetworkMode == "" {
		cfg.NetworkMode = "none"
	}

	return &Runner{cfg: cfg}
}

// Run spawns a contained child process inside namespaces and cgroups.
func (r *Runner) Run() (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()

	// 1. Determine lower directory: custom rootfs, image rootfs, or host root "/"
	lowerDir := "/"
	if r.cfg.Rootfs != "" {
		lowerDir = r.cfg.Rootfs
	} else if r.cfg.Image != "" {
		imgStore, err := image.NewStore("")
		if err != nil {
			return nil, fmt.Errorf("failed to open image store: %w", err)
		}
		imgRootfs, err := imgStore.GetRootfs(r.cfg.Image)
		if err != nil {
			return nil, fmt.Errorf("failed resolving image rootfs: %w", err)
		}
		lowerDir = imgRootfs
	}

	// 2. Prepare overlay filesystem in parent host namespace
	overlay, err := NewOverlayManagerWithLower(r.cfg.ID, r.cfg.StorageLimitMB, lowerDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize overlay manager: %w", err)
	}
	defer func() {
		_ = overlay.Cleanup()
	}()

	targetRoot, err := overlay.Mount()
	if err != nil {
		return nil, fmt.Errorf("failed to mount overlay: %w", err)
	}

	r.cfg.RootPath = targetRoot

	// 3. Setup cgroup limits
	cg, err := NewCgroupController(r.cfg.ID)
	if err != nil {
		return nil, fmt.Errorf("cgroup init error: %w", err)
	}
	defer func() {
		_ = cg.Cleanup()
	}()

	if err := cg.ApplyLimits(r.cfg.MemoryLimitBytes, r.cfg.MaxProcesses); err != nil {
		return nil, fmt.Errorf("failed to apply cgroup limits: %w", err)
	}

	cfgBytes, err := json.Marshal(r.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}

	selfBin, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	syncR, syncW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create sync pipe: %w", err)
	}
	defer syncW.Close()

	cmd := exec.CommandContext(ctx, selfBin, "__init_child__", string(cfgBytes))
	cmd.ExtraFiles = []*os.File{syncR}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNET,
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()

	if err := cmd.Start(); err != nil {
		_ = syncR.Close()
		return nil, fmt.Errorf("failed to start containerized child: %w", err)
	}

	_ = syncR.Close()

	childPid := cmd.Process.Pid

	if err := cg.AttachPID(childPid); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("failed to bind process to cgroup: %w", err)
	}

	// 4. Provision veth pair, bridge routing, DNS, and port forwarding if requested
	if r.cfg.NetworkMode == "bridge" {
		netMgr := network.NewManager()
		if err := netMgr.SetupContainerNetwork(r.cfg.ID, childPid, r.cfg.RootPath, r.cfg.PortMappings, r.cfg.DNSServers); err != nil {
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("failed to setup container networking: %w", err)
		}
		defer netMgr.Cleanup(r.cfg.ID, r.cfg.PortMappings)
	}

	// Unblock child
	_ = syncW.Close()

	waitErr := cmd.Wait()
	duration := time.Since(start)

	metrics := cg.ReadMetrics()
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	exitCode := 0

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if timedOut {
			exitCode = 124
		} else {
			return nil, fmt.Errorf("execution error: %w", waitErr)
		}
	}

	if timedOut && exitCode == 0 {
		exitCode = 124
	}

	return &Result{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		Duration: duration,
		TimedOut: timedOut,
		Metrics:  metrics,
	}, nil
}

// configureLoopback activates 'lo' interface inside the new network namespace.
func configureLoopback() error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("failed to find lo interface: %w", err)
	}

	if err := unix.IoctlSetInt(0, unix.SIOCSIFFLAGS, lo.Index); err != nil {
		_ = err
	}
	return nil
}

// mountDevNodes provisions essential device nodes and mounts devpts inside targetRoot.
func mountDevNodes(targetRoot string) error {
	devPath := filepath.Join(targetRoot, "dev")
	if err := os.MkdirAll(devPath, 0755); err != nil {
		return fmt.Errorf("failed to mkdir /dev: %w", err)
	}

	devFiles := []string{"null", "zero", "urandom", "random", "tty"}
	for _, f := range devFiles {
		src := filepath.Join("/dev", f)
		dst := filepath.Join(devPath, f)

		if _, err := os.Stat(src); err != nil {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		touchFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			if f == "tty" {
				continue
			}
			return fmt.Errorf("failed to touch %s: %w", dst, err)
		}
		_ = touchFile.Close()

		if err := syscall.Mount(src, dst, "", syscall.MS_BIND, ""); err != nil {
			if f == "tty" {
				continue
			}
			return fmt.Errorf("failed to bind mount %s: %w", dst, err)
		}
	}

	ptsPath := filepath.Join(devPath, "pts")
	if err := os.MkdirAll(ptsPath, 0755); err != nil {
		return fmt.Errorf("failed to mkdir /dev/pts: %w", err)
	}
	ptsOpts := "newinstance,ptmxmode=0666,mode=0620"
	if err := syscall.Mount("devpts", ptsPath, "devpts", 0, ptsOpts); err != nil {
		_ = syscall.Mount("/dev/pts", ptsPath, "", syscall.MS_BIND, "")
	}

	ptmxTarget := filepath.Join(devPath, "ptmx")
	if _, err := os.Lstat(ptmxTarget); os.IsNotExist(err) {
		_ = os.Symlink("pts/ptmx", ptmxTarget)
	}

	return nil
}

// applyCustomMounts bind-mounts requested host volumes into the container root.
func applyCustomMounts(targetRoot string, mounts []MountSpec) error {
	for _, m := range mounts {
		cleanDst := strings.TrimPrefix(m.ContainerPath, "/")
		fullDst := filepath.Join(targetRoot, cleanDst)

		hostFi, err := os.Stat(m.HostPath)
		if err != nil {
			return fmt.Errorf("failed to inspect mount source %s: %w", m.HostPath, err)
		}

		if hostFi.IsDir() {
			if err := os.MkdirAll(fullDst, 0777); err != nil {
				return fmt.Errorf("failed to create directory mount point %s: %w", fullDst, err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(fullDst), 0755); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %w", fullDst, err)
			}
			f, err := os.OpenFile(fullDst, os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				return fmt.Errorf("failed to touch file mount point %s: %w", fullDst, err)
			}
			_ = f.Close()
		}

		if err := syscall.Mount(m.HostPath, fullDst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			return fmt.Errorf("failed to bind mount %s to %s: %w", m.HostPath, fullDst, err)
		}

		if m.ReadOnly {
			flags := syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_REC
			if err := syscall.Mount("", fullDst, "", uintptr(flags), ""); err != nil {
				return fmt.Errorf("failed to remount %s read-only: %w", fullDst, err)
			}
		}
	}
	return nil
}

// pivotRoot executes pivot_root to replace the root filesystem and unmount old root.
func pivotRoot(newRoot string) error {
	if err := syscall.Mount(newRoot, newRoot, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to bind-mount new root %s onto itself: %w", newRoot, err)
	}

	oldRoot := filepath.Join(newRoot, ".oldroot")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return fmt.Errorf("failed to create oldroot dir %s: %w", oldRoot, err)
	}

	if err := unix.PivotRoot(newRoot, oldRoot); err != nil {
		return fmt.Errorf("unix pivot_root failed: %w", err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir / after pivot_root failed: %w", err)
	}

	oldRootPath := "/.oldroot"
	if err := syscall.Unmount(oldRootPath, syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("failed to unmount old root %s: %w", oldRootPath, err)
	}

	_ = os.Remove(oldRootPath)
	return nil
}

// dropPrivileges removes root capabilities and applies seccomp filters.
func dropPrivileges(seccompProfile string) error {
	const unprivilegedUID = 65534
	const unprivilegedGID = 65534

	if err := DropCapabilities(); err != nil {
		return fmt.Errorf("capability drop failed: %w", err)
	}
	if err := ApplySeccompFilter(seccompProfile); err != nil {
		return fmt.Errorf("seccomp filter failed: %w", err)
	}
	if err := syscall.Setgroups([]int{unprivilegedGID}); err != nil {
		return fmt.Errorf("setgroups failed: %w", err)
	}
	if err := syscall.Setgid(unprivilegedGID); err != nil {
		return fmt.Errorf("setgid failed: %w", err)
	}
	if err := syscall.Setuid(unprivilegedUID); err != nil {
		return fmt.Errorf("setuid failed: %w", err)
	}
	return nil
}

// InitChild executes inside the new namespace before the target workload runs.
func InitChild(cfgJSON string) error {
	var cfg Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return fmt.Errorf("child: failed to parse config: %w", err)
	}

	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("child: failed to make root private: %w", err)
	}

	targetRoot := cfg.RootPath
	if targetRoot == "" {
		return errors.New("child: missing root path for container")
	}

	if err := mountDevNodes(targetRoot); err != nil {
		return fmt.Errorf("child: failed to mount dev nodes: %w", err)
	}

	if err := applyCustomMounts(targetRoot, cfg.Mounts); err != nil {
		return fmt.Errorf("child: failed to apply volume mounts: %w", err)
	}

	if err := pivotRoot(targetRoot); err != nil {
		return fmt.Errorf("child: pivot_root failed: %w", err)
	}

	_ = configureLoopback()

	// Wait for parent host to finish network plumbing (extra file descriptor 3)
	syncPipe := os.NewFile(uintptr(3), "syncPipe")
	if syncPipe != nil {
		buf := make([]byte, 1)
		_, _ = syncPipe.Read(buf)
		_ = syncPipe.Close()
	}

	if err := dropPrivileges(cfg.SeccompProfile); err != nil {
		return fmt.Errorf("child: privilege drop failed: %w", err)
	}

	binaryPath, err := exec.LookPath(cfg.Command)
	if err != nil {
		return fmt.Errorf("child: command not found: %w", err)
	}

	execArgs := append([]string{cfg.Command}, cfg.Args...)
	if err := syscall.Exec(binaryPath, execArgs, cfg.Env); err != nil {
		return fmt.Errorf("child: exec failed: %w", err)
	}

	return nil
}
