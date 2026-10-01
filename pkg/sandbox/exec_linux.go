package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// JoinNamespaces locks the OS thread, unshares filesystem attributes,
// and attaches the thread to targetPid's IPC, UTS, Network, PID, and Mount namespaces.
func JoinNamespaces(targetPid int) error {
	if targetPid <= 0 {
		return errors.New("invalid target PID for namespace join")
	}

	// 1. Lock the current Go routine strictly to its underlying OS thread.
	// Linux namespace mutations are thread-scoped until forking.
	runtime.LockOSThread()

	// 2. Unshare CLONE_FS so this thread doesn't share filesystem struct with other Go runtime threads.
	// Failing to unshare CLONE_FS causes setns(..., CLONE_NEWNS) to return EINVAL in multi-threaded processes.
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("unshare(CLONE_FS) failed: %w", err)
	}

	nsTypes := []struct {
		name  string
		clone int
	}{
		{"ipc", unix.CLONE_NEWIPC},
		{"uts", unix.CLONE_NEWUTS},
		{"net", unix.CLONE_NEWNET},
		{"pid", unix.CLONE_NEWPID},
		{"mnt", unix.CLONE_NEWNS},
	}

	for _, ns := range nsTypes {
		nsPath := fmt.Sprintf("/proc/%d/ns/%s", targetPid, ns.name)
		f, err := os.Open(nsPath)
		if err != nil {
			return fmt.Errorf("failed opening namespace %s at %s: %w", ns.name, nsPath, err)
		}

		err = unix.Setns(int(f.Fd()), ns.clone)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("setns failed for namespace %s: %w", ns.name, err)
		}
	}

	return nil
}

// ExecInContainer executes a command inside the namespaces of targetPid.
// A child process is forked so it inherits the target PID namespace and mount root.
func ExecInContainer(targetPid int, command string, args []string, env []string) error {
	if err := JoinNamespaces(targetPid); err != nil {
		return fmt.Errorf("namespace attachment failed: %w", err)
	}

	// Change working directory to root of joined mount namespace
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir / after setns failed: %w", err)
	}

	if len(env) == 0 {
		env = []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=/tmp",
			"TERM=xterm-256color",
		}
	}

	// Fork-exec child to become a member of the target PID namespace
	cmd := exec.Command(command, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: false,
	}

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("failed running exec command: %w", err)
	}

	return nil
}
