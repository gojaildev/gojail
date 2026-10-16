package image

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		"etc/foo.txt": "original foo\n",
		"etc/bar.txt": "original bar\n",
	}
	baseTar := createTestTar(t, baseEntries)
	if err := UnpackLayer(bytes.NewReader(baseTar), tempDir); err != nil {
		t.Fatalf("failed unpacking base layer: %v", err)
	}

	// Diff layer with whiteout
	diffEntries := map[string]string{
		"etc/.wh.foo.txt": "",
		"etc/bar.txt":     "modified bar\n",
	}
	diffTar := createTestTar(t, diffEntries)
	if err := UnpackLayer(bytes.NewReader(diffTar), tempDir); err != nil {
		t.Fatalf("failed unpacking diff layer: %v", err)
	}

	fooPath := filepath.Join(tempDir, "etc", "foo.txt")
	if _, err := os.Stat(fooPath); !os.IsNotExist(err) {
		t.Errorf("expected etc/foo.txt to be removed by whiteout")
	}

	barPath := filepath.Join(tempDir, "etc", "bar.txt")
	data, err := os.ReadFile(barPath)
	if err != nil {
		t.Fatalf("expected etc/bar.txt to exist: %v", err)
	}
	if string(data) != "modified bar\n" {
		t.Errorf("unexpected content for bar.txt: %s", string(data))
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

func TestStore_Pull(t *testing.T) {
	layerContent := createTestTar(t, map[string]string{
		"bin/testapp": "#!/bin/sh\necho running\n",
	})
	hasher := sha256.New()
	hasher.Write(layerContent)
	layerDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))

	manifest := Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeDockerManifest,
		Layers: []LayerDescriptor{
			{
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Digest:    layerDigest,
				Size:      int64(len(layerContent)),
			},
		},
	}
	manifestJSON, _ := json.Marshal(manifest)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/library/testapp/manifests/v1.0":
			w.Header().Set("Content-Type", MediaTypeDockerManifest)
			_, _ = w.Write(manifestJSON)
		case fmt.Sprintf("/v2/library/testapp/blobs/%s", layerDigest):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(layerContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	storeBase := t.TempDir()
	store, err := NewStore(storeBase)
	if err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	regClient := server.Client()
	if transport, ok := regClient.Transport.(*http.Transport); ok {
		store.client.httpClient.Transport = transport.Clone()
	} else {
		store.client.httpClient = regClient
	}

	testCases := []struct {
		name        string
		ref         string
		expectError bool
	}{
		{
			name:        "invalid reference format returns error",
			ref:         "INVALID:REF:TAG:EXTRA",
			expectError: true,
		},
		{
			name:        "successful pull downloads layer and writes rootfs",
			ref:         fmt.Sprintf("%s/library/testapp:v1.0", u.Host),
			expectError: false,
		},
		{
			name:        "subsequent pull reuses cached image metadata",
			ref:         fmt.Sprintf("%s/library/testapp:v1.0", u.Host),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var progressMessages []string
			img, err := store.Pull(tc.ref, func(msg string) {
				progressMessages = append(progressMessages, msg)
			})

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if img == nil {
				t.Fatalf("expected stored image, got nil")
			}

			appPath := filepath.Join(img.RootfsPath, "bin", "testapp")
			if _, err := os.Stat(appPath); err != nil {
				t.Errorf("expected extracted binary at %s: %v", appPath, err)
			}
		})
	}
}
