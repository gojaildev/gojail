package server

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	defaultPIDFile   = "/var/run/gojaild.pid"
	defaultLayersDir = "/run/gojail/layers"
	cgroupRoot       = "/sys/fs/cgroup/gojail"
)

// AcquireDaemonLock ensures only one gojaild instance runs concurrently using flock.
func AcquireDaemonLock(pidPath string) (*os.File, error) {
	if pidPath == "" {
		pidPath = defaultPIDFile
	}

	if err := os.MkdirAll(filepath.Dir(pidPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create pidfile directory: %w", err)
	}

	file, err := os.OpenFile(pidPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open pidfile %s: %w", pidPath, err)
	}

	// Non-blocking exclusive lock
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another gojaild daemon instance is already active (lock held on %s)", pidPath)
	}

	// Write daemon PID
	if err := file.Truncate(0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to truncate pidfile: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to seek pidfile: %w", err)
	}
	if _, err := file.WriteString(strconv.Itoa(os.Getpid()) + "\n"); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to write pid to %s: %w", pidPath, err)
	}

	return file, nil
}

// SweepStaleMounts parses /proc/mounts and detaches any dangling gojail layers mounts.
func SweepStaleMounts(layersPrefix string) (int, error) {
	if layersPrefix == "" {
		layersPrefix = defaultLayersDir
	}

	mountsFile, err := os.Open("/proc/mounts")
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read /proc/mounts: %w", err)
	}
	defer func() {
		_ = mountsFile.Close()
	}()

	var matchedMounts []string
	scanner := bufio.NewScanner(mountsFile)
	cleanPrefix := filepath.Clean(layersPrefix)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		target := filepath.Clean(fields[1])

		// Match mount points located inside or equal to the layers directory
		if target == cleanPrefix || strings.HasPrefix(target, cleanPrefix+"/") {
			matchedMounts = append(matchedMounts, target)
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("error parsing /proc/mounts: %w", err)
	}

	// Sort mount targets in descending order by length so nested mounts unmount before parents
	sort.Slice(matchedMounts, func(i, j int) bool {
		return len(matchedMounts[i]) > len(matchedMounts[j])
	})

	unmountedCount := 0
	for _, target := range matchedMounts {
		if err := unix.Unmount(target, unix.MNT_DETACH); err != nil && !os.IsNotExist(err) {
			// Log error but continue sweeping remaining targets
			fmt.Fprintf(os.Stderr, "[recovery] Warning: failed to unmount %s: %v\n", target, err)
		} else {
			unmountedCount++
		}
	}

	return unmountedCount, nil
}

// SweepStaleCgroups traverses the cgroup hierarchy and cleans up dead workers.
func SweepStaleCgroups() error {
	entries, err := os.ReadDir(cgroupRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to inspect %s: %w", cgroupRoot, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "warm-") || strings.HasPrefix(name, "jail-") {
			cgPath := filepath.Join(cgroupRoot, name)

			// If cgroup.kill exists (cgroups v2), send kill to terminate any lingering processes
			killFile := filepath.Join(cgPath, "cgroup.kill")
			if _, err := os.Stat(killFile); err == nil {
				_ = os.WriteFile(killFile, []byte("1\n"), 0644)
			}

			// Remove dead cgroup node
			_ = os.Remove(cgPath)
		}
	}
	return nil
}

// ResetLayersTree safely detaches mounts and cleans the layers scratch directory.
func ResetLayersTree(layersDir string) error {
	if layersDir == "" {
		layersDir = defaultLayersDir
	}

	// Detach all mounts first
	if _, err := SweepStaleMounts(layersDir); err != nil {
		return fmt.Errorf("failed to sweep stale mounts: %w", err)
	}

	// Remove all orphaned layer files/directories
	if err := os.RemoveAll(layersDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clean layers directory %s: %w", layersDir, err)
	}

	// Recreate fresh scratch tree
	if err := os.MkdirAll(layersDir, 0755); err != nil {
		return fmt.Errorf("failed to recreate layers directory %s: %w", layersDir, err)
	}

	return nil
}
