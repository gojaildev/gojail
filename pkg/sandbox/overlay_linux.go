package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// OverlayManager manages ephemeral union filesystem layers for a sandbox.
type OverlayManager struct {
	id        string
	baseDir   string
	lowerDir  string
	upperDir  string
	workDir   string
	mergedDir string
	storageMB int64
}

// NewOverlayManager prepares layer directories under /run/gojail/layers/<id> defaulting to host root "/" as lowerdir.
func NewOverlayManager(id string, storageLimitMB int64) (*OverlayManager, error) {
	return NewOverlayManagerWithLower(id, storageLimitMB, "/")
}

// NewOverlayManagerWithLower prepares layer directories under /run/gojail/layers/<id> with a custom lowerdir.
func NewOverlayManagerWithLower(id string, storageLimitMB int64, lowerDir string) (*OverlayManager, error) {
	if storageLimitMB <= 0 {
		storageLimitMB = 64
	}
	if lowerDir == "" {
		lowerDir = "/"
	}

	baseDir := filepath.Join("/run/gojail/layers", id)
	upperDir := filepath.Join(baseDir, "upper")
	workDir := filepath.Join(baseDir, "work")
	mergedDir := filepath.Join(baseDir, "merged")

	// Clean up any stale directory for this id before provisioning
	_ = syscall.Unmount(mergedDir, syscall.MNT_DETACH)
	_ = syscall.Unmount(baseDir, syscall.MNT_DETACH)
	_ = os.RemoveAll(baseDir)

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create overlay root %s: %w", baseDir, err)
	}

	// Mount dedicated tmpfs onto baseDir to strictly enforce storage quotas
	tmpfsOpts := fmt.Sprintf("size=%dm", storageLimitMB)
	if err := syscall.Mount("tmpfs", baseDir, "tmpfs", 0, tmpfsOpts); err != nil {
		_ = os.RemoveAll(baseDir)
		return nil, fmt.Errorf("failed to mount tmpfs for overlay storage limit: %w", err)
	}

	// Create subdirectories inside the tmpfs-backed layer
	for _, dir := range []string{upperDir, workDir, mergedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			_ = syscall.Unmount(baseDir, syscall.MNT_DETACH)
			_ = os.RemoveAll(baseDir)
			return nil, fmt.Errorf("failed to create overlay directory %s: %w", dir, err)
		}
	}

	// Pre-create /tmp in upperDir with sticky world-writable permissions so unprivileged UID 65534 can write to /tmp
	upperTmp := filepath.Join(upperDir, "tmp")
	if err := os.MkdirAll(upperTmp, 0777|os.ModeSticky); err != nil {
		_ = syscall.Unmount(baseDir, syscall.MNT_DETACH)
		_ = os.RemoveAll(baseDir)
		return nil, fmt.Errorf("failed to create upper /tmp: %w", err)
	}
	_ = os.Chmod(upperTmp, 0777|os.ModeSticky)

	return &OverlayManager{
		id:        id,
		baseDir:   baseDir,
		lowerDir:  lowerDir,
		upperDir:  upperDir,
		workDir:   workDir,
		mergedDir: mergedDir,
		storageMB: storageLimitMB,
	}, nil
}

// Mount merges the configured lowerdir (read-only) with the ephemeral upperdir.
func (om *OverlayManager) Mount() (string, error) {
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", om.lowerDir, om.upperDir, om.workDir)
	if err := syscall.Mount("overlay", om.mergedDir, "overlay", 0, opts); err != nil {
		return "", fmt.Errorf("failed to mount overlayfs: %w", err)
	}
	return om.mergedDir, nil
}

// MergedDir returns the root mount point to chroot into.
func (om *OverlayManager) MergedDir() string {
	return om.mergedDir
}

// Cleanup unmounts the overlay union, unmounts the tmpfs quota, and removes directories.
func (om *OverlayManager) Cleanup() error {
	var collectedErrors []error

	// 1. Unmount the merged overlay layer
	if err := syscall.Unmount(om.mergedDir, syscall.MNT_DETACH); err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.EINVAL) {
		collectedErrors = append(collectedErrors, fmt.Errorf("failed to unmount overlay merged dir %s: %w", om.mergedDir, err))
	}

	// 2. Unmount the underlying tmpfs quota backing baseDir
	if err := syscall.Unmount(om.baseDir, syscall.MNT_DETACH); err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.EINVAL) {
		collectedErrors = append(collectedErrors, fmt.Errorf("failed to unmount overlay tmpfs base %s: %w", om.baseDir, err))
	}

	// 3. Delete leftover layer directories
	if err := os.RemoveAll(om.baseDir); err != nil && !os.IsNotExist(err) {
		collectedErrors = append(collectedErrors, fmt.Errorf("failed to remove layer base %s: %w", om.baseDir, err))
	}

	if len(collectedErrors) > 0 {
		return collectedErrors[0]
	}
	return nil
}
