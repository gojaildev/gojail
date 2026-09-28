package image

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTestTar(t *testing.T, entries map[string]string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for name, content := range entries {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar content: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}

	return buf.Bytes()
}

func TestUnpackLayer_Basic(t *testing.T) {
	tempDir := t.TempDir()

	entries := map[string]string{
		"etc/test.conf": "hello=world\n",
		"bin/dummy":     "echo dummy\n",
	}

	tarData := createTestTar(t, entries)
	if err := UnpackLayer(bytes.NewReader(tarData), tempDir); err != nil {
		t.Fatalf("failed to unpack layer: %v", err)
	}

	confPath := filepath.Join(tempDir, "etc", "test.conf")
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("expected etc/test.conf to exist: %v", err)
	}
	if string(data) != "hello=world\n" {
		t.Errorf("unexpected content: %s", string(data))
	}
}

func TestUnpackLayer_Whiteouts(t *testing.T) {
	tempDir := t.TempDir()

	// Base layer
	baseEntries := map[string]string{
		"app/config.json":  `{"version": 1}`,
		"app/old_file.txt": "delete me",
	}
	baseTar := createTestTar(t, baseEntries)
	if err := UnpackLayer(bytes.NewReader(baseTar), tempDir); err != nil {
		t.Fatalf("failed unpacking base layer: %v", err)
	}

	// Layer with whiteout deleting app/old_file.txt
	diffEntries := map[string]string{
		"app/.wh.old_file.txt": "",
		"app/config.json":      `{"version": 2}`,
	}
	diffTar := createTestTar(t, diffEntries)
	if err := UnpackLayer(bytes.NewReader(diffTar), tempDir); err != nil {
		t.Fatalf("failed unpacking diff layer: %v", err)
	}

	// old_file.txt should be gone
	deletedPath := filepath.Join(tempDir, "app", "old_file.txt")
	if _, err := os.Stat(deletedPath); !os.IsNotExist(err) {
		t.Errorf("expected %s to be removed by whiteout", deletedPath)
	}

	// config.json should be updated to version 2
	cfgPath := filepath.Join(tempDir, "app", "config.json")
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", cfgPath, err)
	}
	if string(cfgData) != `{"version": 2}` {
		t.Errorf("expected version 2 content, got: %s", string(cfgData))
	}
}

func TestStore_GetRootfsAndList(t *testing.T) {
	tempBase := t.TempDir()

	store, err := NewStore(tempBase)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ref, err := ParseReference("alpine:3.19")
	if err != nil {
		t.Fatalf("failed to parse reference: %v", err)
	}

	targetDir := filepath.Join(store.imageDir, ref.DirSafeName())
	targetRootfs := filepath.Join(targetDir, "rootfs")
	if err := os.MkdirAll(targetRootfs, 0755); err != nil {
		t.Fatalf("failed to create mock rootfs: %v", err)
	}

	img := StoredImage{
		Reference:  "alpine:3.19",
		FullName:   ref.FullName(),
		RootfsPath: targetRootfs,
		CreatedAt:  time.Now(),
		Layers:     []string{"sha256:dummy123"},
		Size:       1024,
	}

	data, err := json.Marshal(img)
	if err != nil {
		t.Fatalf("failed to marshal image metadata: %v", err)
	}

	if err := os.WriteFile(filepath.Join(targetDir, "image.json"), data, 0644); err != nil {
		t.Fatalf("failed to write image.json: %v", err)
	}

	rootfs, err := store.GetRootfs("alpine:3.19")
	if err != nil {
		t.Fatalf("GetRootfs failed: %v", err)
	}
	if rootfs != targetRootfs {
		t.Errorf("expected rootfs %s, got %s", targetRootfs, rootfs)
	}

	images, err := store.ListImages()
	if err != nil {
		t.Fatalf("ListImages failed: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(images))
	}
	if images[0].FullName != ref.FullName() {
		t.Errorf("expected %s, got %s", ref.FullName(), images[0].FullName)
	}
}
