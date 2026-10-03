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

// validateParentSymlinks verifies that existing parent directories do not escape root via symlinks.
func validateParentSymlinks(root, path string) error {
	parent := filepath.Dir(path)
	evalParent, err := filepath.EvalSymlinks(parent)
	if err == nil {
		cleanRoot := filepath.Clean(root)
		if evalParent != cleanRoot && !strings.HasPrefix(evalParent, cleanRoot+string(filepath.Separator)) {
			return fmt.Errorf("parent directory escapes target root via symlink: %s -> %s", parent, evalParent)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// evalExistingPrefix resolves existing symlink prefixes on a path without failing if leaf paths do not yet exist.
func evalExistingPrefix(targetAbs, path string) (string, error) {
	current := path
	var uncreated []string

	for {
		eval, err := filepath.EvalSymlinks(current)
		if err == nil {
			result := eval
			for i := len(uncreated) - 1; i >= 0; i-- {
				result = filepath.Join(result, uncreated[i])
			}
			return filepath.Clean(result), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}

		uncreated = append(uncreated, filepath.Base(current))
		parent := filepath.Dir(current)
		if parent == current || parent == "." || parent == "/" {
			return filepath.Clean(path), nil
		}
		current = parent
	}
}

// UnpackLayer unpacks a single tar or tar.gz layer archive into targetDir,
// validating all paths and links against directory traversal and symlink attacks.
func UnpackLayer(reader io.Reader, targetDir string) error {
	cleanTargetDir := filepath.Clean(targetDir)
	targetAbs, err := filepath.Abs(cleanTargetDir)
	if err != nil {
		return fmt.Errorf("failed resolving absolute path for target directory: %w", err)
	}

	targetPrefix := targetAbs + string(filepath.Separator)

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

		cleanRel := filepath.Clean(header.Name)
		if cleanRel == "." || cleanRel == "/" || cleanRel == "" {
			continue
		}
		if filepath.IsAbs(cleanRel) {
			return fmt.Errorf("insecure path in layer tar (absolute path): %s", header.Name)
		}

		// 1. Sanitize the primary target path immediately (CodeQL-recognized pattern)
		targetPath := filepath.Join(targetAbs, cleanRel)
		if !strings.HasPrefix(targetPath, targetPrefix) && targetPath != targetAbs {
			return fmt.Errorf("insecure path in layer tar (escapes target root): %s", header.Name)
		}
		relCheck, err := filepath.Rel(targetAbs, targetPath)
		if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
			return fmt.Errorf("insecure path in layer tar: %s", header.Name)
		}

		// Prevent symlink traversal through existing directories
		if err := validateParentSymlinks(targetAbs, targetPath); err != nil {
			return fmt.Errorf("insecure path in layer tar (parent symlink): %w", err)
		}

		base := filepath.Base(cleanRel)
		dir := filepath.Dir(cleanRel)

		// 2. Opaque Whiteout: clear entire directory contents
		if base == whiteoutOpaque {
			opaqueSubDir := filepath.Join(targetAbs, dir)
			if !strings.HasPrefix(opaqueSubDir, targetPrefix) && opaqueSubDir != targetAbs {
				return fmt.Errorf("insecure opaque whiteout path: %s", header.Name)
			}
			relOpaque, oErr := filepath.Rel(targetAbs, opaqueSubDir)
			if oErr != nil || relOpaque == ".." || strings.HasPrefix(relOpaque, ".."+string(filepath.Separator)) {
				return fmt.Errorf("insecure opaque whiteout path: %s", header.Name)
			}
			if err := clearDirectoryContents(opaqueSubDir); err != nil {
				return fmt.Errorf("failed clearing opaque directory %s: %w", opaqueSubDir, err)
			}
			continue
		}

		// 3. Standard Whiteout: delete target file or directory
		if strings.HasPrefix(base, whiteoutPrefix) {
			deletedName := strings.TrimPrefix(base, whiteoutPrefix)
			whiteoutTarget := filepath.Join(targetAbs, dir, deletedName)
			if !strings.HasPrefix(whiteoutTarget, targetPrefix) && whiteoutTarget != targetAbs {
				return fmt.Errorf("insecure whiteout path: %s", header.Name)
			}
			relWhiteout, wErr := filepath.Rel(targetAbs, whiteoutTarget)
			if wErr != nil || relWhiteout == ".." || strings.HasPrefix(relWhiteout, ".."+string(filepath.Separator)) {
				return fmt.Errorf("insecure whiteout path: %s", header.Name)
			}
			_ = os.RemoveAll(whiteoutTarget)
			continue
		}

		parentDir := filepath.Dir(targetPath)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, header.FileInfo().Mode().Perm()); err != nil {
				return fmt.Errorf("failed creating directory %s: %w", targetPath, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(parentDir, 0755); err != nil {
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
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				return err
			}

			cleanLink := filepath.Clean(header.Linkname)
			var resolvedDest string
			if filepath.IsAbs(cleanLink) {
				resolvedDest = filepath.Join(targetAbs, cleanLink)
			} else {
				resolvedDest = filepath.Join(parentDir, cleanLink)
			}
			destClean := filepath.Clean(resolvedDest)

			evaluatedDest, evalErr := evalExistingPrefix(targetAbs, destClean)
			if evalErr != nil {
				return fmt.Errorf("failed resolving symlink target %s -> %s: %w", targetPath, header.Linkname, evalErr)
			}

			if !strings.HasPrefix(evaluatedDest, targetPrefix) && evaluatedDest != targetAbs {
				return fmt.Errorf("insecure symlink target %s -> %s: escapes root", targetPath, header.Linkname)
			}
			relDest, err := filepath.Rel(targetAbs, evaluatedDest)
			if err != nil || relDest == ".." || strings.HasPrefix(relDest, ".."+string(filepath.Separator)) {
				return fmt.Errorf("insecure symlink target %s -> %s: escapes root", targetPath, header.Linkname)
			}

			linkToWrite := cleanLink
			if filepath.IsAbs(cleanLink) {
				relFromParent, rErr := filepath.Rel(parentDir, evaluatedDest)
				if rErr == nil {
					linkToWrite = relFromParent
				}
			}

			cleanFinalLink := filepath.Clean(linkToWrite)
			var finalDestCheck string
			if filepath.IsAbs(cleanFinalLink) {
				finalDestCheck = filepath.Join(targetAbs, cleanFinalLink)
			} else {
				finalDestCheck = filepath.Join(parentDir, cleanFinalLink)
			}
			if !strings.HasPrefix(finalDestCheck, targetPrefix) && finalDestCheck != targetAbs {
				return fmt.Errorf("insecure symlink: %s", linkToWrite)
			}
			relFinal, fErr := filepath.Rel(targetAbs, finalDestCheck)
			if fErr != nil || relFinal == ".." || strings.HasPrefix(relFinal, ".."+string(filepath.Separator)) {
				return fmt.Errorf("insecure symlink: %s", linkToWrite)
			}

			_ = os.Remove(targetPath)
			if err := os.Symlink(cleanFinalLink, targetPath); err != nil {
				return fmt.Errorf("failed creating symlink %s -> %s: %w", targetPath, cleanFinalLink, err)
			}

		case tar.TypeLink:
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				return err
			}

			cleanLink := filepath.Clean(header.Linkname)
			oldPath := filepath.Join(targetAbs, cleanLink)
			oldClean := filepath.Clean(oldPath)

			evaluatedOld, evalErr := evalExistingPrefix(targetAbs, oldClean)
			if evalErr != nil {
				return fmt.Errorf("failed resolving hardlink target %s -> %s: %w", targetPath, header.Linkname, evalErr)
			}

			if !strings.HasPrefix(evaluatedOld, targetPrefix) && evaluatedOld != targetAbs {
				return fmt.Errorf("insecure hardlink target %s -> %s: escapes root", targetPath, header.Linkname)
			}
			relLink, err := filepath.Rel(targetAbs, evaluatedOld)
			if err != nil || relLink == ".." || strings.HasPrefix(relLink, ".."+string(filepath.Separator)) {
				return fmt.Errorf("insecure hardlink target %s -> %s: escapes root", targetPath, header.Linkname)
			}

			_ = os.Remove(targetPath)
			if err := os.Link(evaluatedOld, targetPath); err != nil {
				return fmt.Errorf("failed creating hardlink %s -> %s: %w", targetPath, evaluatedOld, err)
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
