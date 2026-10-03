package image

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestUnpackLayer_SymlinkSecurity(t *testing.T) {
	targetDir := t.TempDir()

	// 1. Escaping symlink must fail
	bufEscape := new(bytes.Buffer)
	tw := tar.NewWriter(bufEscape)
	_ = tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "escaped_symlink",
		Linkname: "../../etc/shadow",
	})
	_ = tw.Close()

	if err := UnpackLayer(bufEscape, targetDir); err == nil {
		t.Fatal("expected error unpacking escaping symlink, got nil")
	}

	// 2. Valid absolute symlink inside rootfs must succeed and be rewritten relative
	bufValid := new(bytes.Buffer)
	tw2 := tar.NewWriter(bufValid)
	_ = tw2.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     "usr/bin",
		Mode:     0755,
	})
	_ = tw2.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "bin",
		Linkname: "/usr/bin",
	})
	_ = tw2.Close()

	if err := UnpackLayer(bufValid, targetDir); err != nil {
		t.Fatalf("expected valid absolute symlink inside rootfs to succeed, got: %v", err)
	}

	linkTarget, err := os.Readlink(filepath.Join(targetDir, "bin"))
	if err != nil {
		t.Fatalf("failed reading created symlink: %v", err)
	}

	if filepath.IsAbs(linkTarget) {
		t.Errorf("symlink target should not be absolute to host root, got %q", linkTarget)
	}
	if linkTarget != "usr/bin" {
		t.Errorf("expected relative link target 'usr/bin', got %q", linkTarget)
	}
}
