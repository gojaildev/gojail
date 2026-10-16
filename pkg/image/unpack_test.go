package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

func TestUnpackLayer_OpaqueWhiteout(t *testing.T) {
	targetDir := t.TempDir()

	// Base layer: create a directory with multiple files
	baseBuf := new(bytes.Buffer)
	twBase := tar.NewWriter(baseBuf)
	_ = twBase.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     "var/log",
		Mode:     0755,
	})
	for _, fname := range []string{"var/log/syslog", "var/log/auth.log"} {
		_ = twBase.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     fname,
			Mode:     0644,
			Size:     int64(len("log entry\n")),
		})
		_, _ = twBase.Write([]byte("log entry\n"))
	}
	_ = twBase.Close()

	if err := UnpackLayer(baseBuf, targetDir); err != nil {
		t.Fatalf("failed unpacking base layer: %v", err)
	}

	// Diff layer: contains opaque whiteout marker and a replacement file
	diffBuf := new(bytes.Buffer)
	twDiff := tar.NewWriter(diffBuf)
	_ = twDiff.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "var/log/.wh..wh..opq",
		Mode:     0644,
		Size:     0,
	})
	_ = twDiff.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "var/log/new.log",
		Mode:     0644,
		Size:     int64(len("new log\n")),
	})
	_, _ = twDiff.Write([]byte("new log\n"))
	_ = twDiff.Close()

	if err := UnpackLayer(diffBuf, targetDir); err != nil {
		t.Fatalf("failed unpacking layer with opaque whiteout: %v", err)
	}

	// Opaque whiteout must have cleared previous files
	if _, err := os.Stat(filepath.Join(targetDir, "var/log/syslog")); !os.IsNotExist(err) {
		t.Errorf("expected var/log/syslog to be cleared by opaque whiteout")
	}
	if _, err := os.Stat(filepath.Join(targetDir, "var/log/auth.log")); !os.IsNotExist(err) {
		t.Errorf("expected var/log/auth.log to be cleared by opaque whiteout")
	}

	// New file must exist
	if _, err := os.Stat(filepath.Join(targetDir, "var/log/new.log")); err != nil {
		t.Errorf("expected var/log/new.log to exist: %v", err)
	}
}

func TestUnpackLayer_GzipAndHardlink(t *testing.T) {
	testCases := []struct {
		name        string
		buildTar    func(t *testing.T) []byte
		isGzip      bool
		expectError bool
		verify      func(t *testing.T, targetDir string)
	}{
		{
			name:   "gzip-compressed tar stream decompression",
			isGzip: true,
			buildTar: func(t *testing.T) []byte {
				buf := new(bytes.Buffer)
				tw := tar.NewWriter(buf)
				_ = tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeReg,
					Name:     "etc/motd",
					Mode:     0644,
					Size:     int64(len("Welcome to GoJail\n")),
				})
				_, _ = tw.Write([]byte("Welcome to GoJail\n"))
				_ = tw.Close()
				return buf.Bytes()
			},
			expectError: false,
			verify: func(t *testing.T, targetDir string) {
				data, err := os.ReadFile(filepath.Join(targetDir, "etc", "motd"))
				if err != nil {
					t.Fatalf("failed reading etc/motd: %v", err)
				}
				if string(data) != "Welcome to GoJail\n" {
					t.Errorf("content mismatch, got %q", string(data))
				}
			},
		},
		{
			name:   "valid hardlink within rootfs",
			isGzip: false,
			buildTar: func(t *testing.T) []byte {
				buf := new(bytes.Buffer)
				tw := tar.NewWriter(buf)
				_ = tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeReg,
					Name:     "bin/app",
					Mode:     0755,
					Size:     int64(len("binary content")),
				})
				_, _ = tw.Write([]byte("binary content"))
				_ = tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeLink,
					Name:     "bin/app-link",
					Linkname: "bin/app",
				})
				_ = tw.Close()
				return buf.Bytes()
			},
			expectError: false,
			verify: func(t *testing.T, targetDir string) {
				data, err := os.ReadFile(filepath.Join(targetDir, "bin", "app-link"))
				if err != nil {
					t.Fatalf("failed reading hardlink file: %v", err)
				}
				if string(data) != "binary content" {
					t.Errorf("content mismatch on hardlink, got %q", string(data))
				}
			},
		},
		{
			name:   "insecure escaping hardlink target rejected",
			isGzip: false,
			buildTar: func(t *testing.T) []byte {
				buf := new(bytes.Buffer)
				tw := tar.NewWriter(buf)
				_ = tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeLink,
					Name:     "bin/bad-hardlink",
					Linkname: "../../../etc/passwd",
				})
				_ = tw.Close()
				return buf.Bytes()
			},
			expectError: true,
			verify:      nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetDir := t.TempDir()
			rawPayload := tc.buildTar(t)

			var inputPayload []byte
			if tc.isGzip {
				gzBuf := new(bytes.Buffer)
				gw := gzip.NewWriter(gzBuf)
				_, _ = gw.Write(rawPayload)
				_ = gw.Close()
				inputPayload = gzBuf.Bytes()
			} else {
				inputPayload = rawPayload
			}

			err := UnpackLayer(bytes.NewReader(inputPayload), targetDir)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.verify != nil {
				tc.verify(t, targetDir)
			}
		})
	}
}
