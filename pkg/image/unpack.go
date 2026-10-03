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

// resolvePathWithinRoot verifies that candidate resides within root,
// resolving existing intermediate symlinks on parent paths to prevent traversal.
func resolvePathWithinRoot(root, candidate string) (string, error) {
	if filepath.IsAbs(candidate) {
		return "", fmt.Errorf("absolute path is not allowed: %s", candidate)
	}

	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	rootAbsEval, err := filepath.EvalSymlinks(rootAbs)
	if err == nil {
		rootAbs = rootAbsEval
	}

	joined := filepath.Join(rootAbs, filepath.Clean(candidate))
	parent := filepath.Dir(joined)

	parentEval, err := filepath.EvalSymlinks(parent)
	if err == nil {
		joined = filepath.Join(parentEval, filepath.Base(joined))
	} else if !os.IsNotExist(err) {
		return "", err
	}

	joinedAbs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(rootAbs, joinedAbs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes root: %s", candidate)
	}

	return joinedAbs, nil
}

// validateLinkTarget verifies that a symlink or hardlink target does not escape targetDir.
func validateLinkTarget(targetDir, linkDir, linkTarget string) error {
	targetAbs, err := filepath.Abs(filepath.Clean(targetDir))
	if err != nil {
		return err
	}
	targetEval, err := filepath.EvalSymlinks(targetAbs)
	if err == nil {
		targetAbs = targetEval
	}

	var destination string
	if filepath.IsAbs(linkTarget) {
		// Absolute symlinks inside container rootfs are relative to container root
		destination = filepath.Join(targetAbs, filepath.Clean(linkTarget))
	} else {
		// Relative symlinks are resolved from the directory containing the symlink
		destination = filepath.Join(linkDir, filepath.Clean(linkTarget))
	}

	destAbs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}

	rel, err := filepath.Rel(targetAbs, destAbs)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("link destination %q escapes root %q", linkTarget, targetDir)
	}

	return nil
}

// UnpackLayer unpacks a single tar or tar.gz layer archive into targetDir,
// correctly applying OCI whiteout semantics and link validation.
func UnpackLayer(reader io.Reader, targetDir string) error {
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

		cleanName := filepath.Clean(header.Name)
		if cleanName == "." || cleanName == "/" {
			continue
		}

		base := filepath.Base(cleanName)
		dir := filepath.Dir(cleanName)

		// 1. Check for Opaque Whiteout: clear entire directory contents
		if base == whiteoutOpaque {
			targetSubDir, err := resolvePathWithinRoot(targetDir, dir)
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
			targetPath, err := resolvePathWithinRoot(targetDir, filepath.Join(dir, deletedName))
			if err != nil {
				return fmt.Errorf("invalid whiteout path: %w", err)
			}
			_ = os.RemoveAll(targetPath)
			continue
		}

		targetPath, err := resolvePathWithinRoot(targetDir, cleanName)
		if err != nil {
			return fmt.Errorf("insecure path in layer tar %s: %w", header.Name, err)
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
			if err := validateLinkTarget(targetDir, parent, header.Linkname); err != nil {
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
			oldPath, err := resolvePathWithinRoot(targetDir, header.Linkname)
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
