package image

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// securePath validates that the target path does not escape targetDir,
// satisfying static analyzers (Zip Slip) and checking symlink evaluation.
func securePath(targetDir, relPath string) (string, error) {
	cleanRel := filepath.Clean(relPath)
	if filepath.IsAbs(cleanRel) || strings.HasPrefix(cleanRel, "..") {
		return "", fmt.Errorf("insecure path traversal in archive: %s", relPath)
	}

	targetAbs, err := filepath.Abs(filepath.Clean(targetDir))
	if err != nil {
		return "", err
	}

	fullPath := filepath.Join(targetAbs, cleanRel)

	// Direct Zip Slip check recognized by CodeQL
	rel, err := filepath.Rel(targetAbs, fullPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry escapes destination directory: %s", relPath)
	}

	// Resolve symlinks on the parent directory if it exists
	parent := filepath.Dir(fullPath)
	if evalParent, err := filepath.EvalSymlinks(parent); err == nil {
		relParent, err := filepath.Rel(targetAbs, evalParent)
		if err != nil || relParent == ".." || strings.HasPrefix(relParent, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("parent directory escapes target root via symlink: %s -> %s", parent, evalParent)
		}
	}

	return fullPath, nil
}

// validateLinkTarget verifies that a symlink or hardlink destination remains within targetDir.
func validateLinkTarget(targetDir, linkDir, linkTarget string) error {
	targetAbs, err := filepath.Abs(filepath.Clean(targetDir))
	if err != nil {
		return err
	}

	var destination string
	if filepath.IsAbs(linkTarget) {
		destination = filepath.Join(targetAbs, filepath.Clean(linkTarget))
	} else {
		destination = filepath.Join(linkDir, filepath.Clean(linkTarget))
	}

	destClean := filepath.Clean(destination)
	rel, err := filepath.Rel(targetAbs, destClean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("link destination %q escapes root %q", linkTarget, targetDir)
	}

	return nil
}

// UnpackLayer unpacks a single tar or tar.gz layer archive into targetDir.
func UnpackLayer(reader io.Reader, targetDir string) error {
	targetAbs, err := filepath.Abs(filepath.Clean(targetDir))
	if err != nil {
		return fmt.Errorf("failed resolving absolute path for target directory: %w", err)
	}

	if err := os.MkdirAll(targetAbs, 0755); err != nil {
		return fmt.Errorf("failed creating target directory: %w", err)
	}

	br := bufio.NewReader(reader)

	var tr *tar.Reader
	magic, err := br.Peek(2)
	if err == nil && len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gzr, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return fmt.Errorf("failed initializing gzip reader: %w", gzErr)
		}
		defer gzr.Close()
		tr = tar.NewReader(gzr)
	} else {
		tr = tar.NewReader(br)
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed reading layer tar: %w", err)
		}

		// Immediate sanitization check on raw header Name
		cleanName := filepath.Clean(header.Name)
		if cleanName == "." || cleanName == "/" || cleanName == "" {
			continue
		}
		if filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, "..") {
			return fmt.Errorf("insecure archive entry name: %s", header.Name)
		}

		base := filepath.Base(cleanName)
		dir := filepath.Dir(cleanName)

		// 1. Check for Opaque Whiteout: clear entire directory contents
		if base == whiteoutOpaque {
			targetSubDir, err := securePath(targetAbs, dir)
			if err != nil {
				return fmt.Errorf("invalid opaque whiteout path: %w", err)
			}
			if err := clearDirectoryContents(targetSubDir); err != nil {
				return fmt.Errorf("failed clearing opaque directory %s: %w", targetSubDir, err)
			}
			continue
		}

		// 2. Check for Standard Whiteout: delete target file or directory
		if strings.HasPrefix(base, whiteoutPrefix) {
			deletedName := strings.TrimPrefix(base, whiteoutPrefix)
			targetPath, err := securePath(targetAbs, filepath.Join(dir, deletedName))
			if err != nil {
				return fmt.Errorf("invalid whiteout path: %w", err)
			}
			_ = os.RemoveAll(targetPath)
			continue
		}

		targetPath, err := securePath(targetAbs, cleanName)
		if err != nil {
			return fmt.Errorf("insecure path in layer tar %s: %w", header.Name, err)
		}

		// Double-check targetPath containment directly inline for static analysis tools
		relCheck, err := filepath.Rel(targetAbs, targetPath)
		if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
			return fmt.Errorf("insecure path in layer tar %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, header.FileInfo().Mode().Perm()); err != nil {
				return fmt.Errorf("failed creating directory %s: %w", targetPath, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			parent := filepath.Dir(targetPath)
			if err := os.MkdirAll(parent, 0755); err != nil {
				return err
			}
			_ = os.Remove(targetPath)
			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, header.FileInfo().Mode().Perm())
			if err != nil {
				return fmt.Errorf("failed creating file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return fmt.Errorf("failed writing file content %s: %w", targetPath, err)
			}
			_ = f.Close()

		case tar.TypeSymlink:
			parent := filepath.Dir(targetPath)
			if err := os.MkdirAll(parent, 0755); err != nil {
				return err
			}
			if err := validateLinkTarget(targetAbs, parent, header.Linkname); err != nil {
				return fmt.Errorf("insecure symlink target %s -> %s: %w", targetPath, header.Linkname, err)
			}
			_ = os.Remove(targetPath)
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return fmt.Errorf("failed creating symlink %s -> %s: %w", targetPath, header.Linkname, err)
			}

		case tar.TypeLink:
			parent := filepath.Dir(targetPath)
			if err := os.MkdirAll(parent, 0755); err != nil {
				return err
			}
			cleanLinkName := filepath.Clean(header.Linkname)
			if filepath.IsAbs(cleanLinkName) || strings.HasPrefix(cleanLinkName, "..") {
				return fmt.Errorf("insecure hardlink target: %s", header.Linkname)
			}
			oldPath, err := securePath(targetAbs, cleanLinkName)
			if err != nil {
				return fmt.Errorf("insecure hardlink target %s -> %s: %w", targetPath, header.Linkname, err)
			}
			_ = os.Remove(targetPath)
			if err := os.Link(oldPath, targetPath); err != nil {
				return fmt.Errorf("failed creating hardlink %s -> %s: %w", targetPath, oldPath, err)
			}
		}
	}

	return nil
}

func clearDirectoryContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		subPath := filepath.Join(dir, entry.Name())
		if err := os.RemoveAll(subPath); err != nil {
			return err
		}
	}
	return nil
}
