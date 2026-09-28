package image

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	DefaultStoreDir = "/var/lib/gojail"
)

// StoredImage contains metadata about a locally unpacked container image.
type StoredImage struct {
	Reference  string    `json:"reference"`
	FullName   string    `json:"full_name"`
	RootfsPath string    `json:"rootfs_path"`
	CreatedAt  time.Time `json:"created_at"`
	Layers     []string  `json:"layers"`
	Size       int64     `json:"size"`
}

// Store coordinates image fetching, layer caching, and rootfs management.
type Store struct {
	baseDir  string
	cacheDir string
	imageDir string
	client   *RegistryClient
	mu       sync.RWMutex
}

// NewStore initializes an Image Store rooted at baseDir.
// If baseDir is empty, DefaultStoreDir (/var/lib/gojail) is used.
func NewStore(baseDir string) (*Store, error) {
	if baseDir == "" {
		baseDir = DefaultStoreDir
	}

	cacheDir := filepath.Join(baseDir, "cache", "layers")
	imageDir := filepath.Join(baseDir, "images")

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed creating layer cache directory: %w", err)
	}
	if err := os.MkdirAll(imageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed creating images directory: %w", err)
	}

	return &Store{
		baseDir:  baseDir,
		cacheDir: cacheDir,
		imageDir: imageDir,
		client:   NewRegistryClient(),
	}, nil
}

// Pull downloads the manifest, pulls missing layer blobs into the cache,
// and unpacks them into a canonical rootfs directory.
func (s *Store) Pull(refStr string, progress func(msg string)) (*StoredImage, error) {
	ref, err := ParseReference(refStr)
	if err != nil {
		return nil, fmt.Errorf("invalid reference: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	notify := func(msg string) {
		if progress != nil {
			progress(msg)
		}
	}

	notify(fmt.Sprintf("Resolving manifest for %s...", ref.FullName()))
	manifest, err := s.client.FetchManifest(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	targetDir := filepath.Join(s.imageDir, ref.DirSafeName())
	targetRootfs := filepath.Join(targetDir, "rootfs")
	metaPath := filepath.Join(targetDir, "image.json")

	// If image already exists, return cached metadata
	if _, err := os.Stat(metaPath); err == nil {
		data, rErr := os.ReadFile(metaPath)
		if rErr == nil {
			var img StoredImage
			if jErr := json.Unmarshal(data, &img); jErr == nil {
				notify(fmt.Sprintf("Image %s is up to date.", ref.ShortName()))
				return &img, nil
			}
		}
	}

	// Prepare fresh unpack target directory
	_ = os.RemoveAll(targetDir)
	if err := os.MkdirAll(targetRootfs, 0755); err != nil {
		return nil, fmt.Errorf("failed to initialize rootfs directory: %w", err)
	}

	var layerDigests []string
	var totalSize int64

	for idx, layer := range manifest.Layers {
		cleanDigest := strings.TrimPrefix(layer.Digest, "sha256:")
		cachedBlob := filepath.Join(s.cacheDir, cleanDigest+".tar")
		totalSize += layer.Size

		// 1. Download blob if not already in local layer cache
		if _, err := os.Stat(cachedBlob); err != nil {
			notify(fmt.Sprintf("[%d/%d] Downloading layer %s (%d KB)...",
				idx+1, len(manifest.Layers), cleanDigest[:12], layer.Size/1024))

			tmpBlob := cachedBlob + ".tmp"
			f, cErr := os.OpenFile(tmpBlob, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if cErr != nil {
				return nil, fmt.Errorf("failed to create temporary blob file: %w", cErr)
			}

			if dErr := s.client.DownloadBlob(ref, layer.Digest, f); dErr != nil {
				_ = f.Close()
				_ = os.Remove(tmpBlob)
				return nil, fmt.Errorf("blob download failed: %w", dErr)
			}
			_ = f.Close()

			if rErr := os.Rename(tmpBlob, cachedBlob); rErr != nil {
				return nil, fmt.Errorf("failed finalizing blob file: %w", rErr)
			}
		} else {
			notify(fmt.Sprintf("[%d/%d] Using cached layer %s", idx+1, len(manifest.Layers), cleanDigest[:12]))
		}

		// 2. Unpack layer into target rootfs
		notify(fmt.Sprintf("[%d/%d] Applying layer %s...", idx+1, len(manifest.Layers), cleanDigest[:12]))
		blobFile, oErr := os.Open(cachedBlob)
		if oErr != nil {
			return nil, fmt.Errorf("failed reading layer file: %w", oErr)
		}

		if uErr := UnpackLayer(blobFile, targetRootfs); uErr != nil {
			_ = blobFile.Close()
			return nil, fmt.Errorf("failed unpacking layer %s: %w", cleanDigest[:12], uErr)
		}
		_ = blobFile.Close()

		layerDigests = append(layerDigests, layer.Digest)
	}

	img := StoredImage{
		Reference:  refStr,
		FullName:   ref.FullName(),
		RootfsPath: targetRootfs,
		CreatedAt:  time.Now(),
		Layers:     layerDigests,
		Size:       totalSize,
	}

	data, err := json.MarshalIndent(img, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal image metadata: %w", err)
	}

	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write image metadata: %w", err)
	}

	notify(fmt.Sprintf("Successfully pulled and unpacked %s", ref.ShortName()))
	return &img, nil
}

// GetRootfs finds an unpacked image by reference and returns its rootfs path.
func (s *Store) GetRootfs(refStr string) (string, error) {
	ref, err := ParseReference(refStr)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	targetDir := filepath.Join(s.imageDir, ref.DirSafeName())
	metaPath := filepath.Join(targetDir, "image.json")

	if _, err := os.Stat(metaPath); err != nil {
		return "", fmt.Errorf("image %q not found locally (run 'gojail pull %s' first)", refStr, refStr)
	}

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata: %w", err)
	}

	var img StoredImage
	if err := json.Unmarshal(data, &img); err != nil {
		return "", fmt.Errorf("corrupted image metadata: %w", err)
	}

	if _, err := os.Stat(img.RootfsPath); err != nil {
		return "", fmt.Errorf("rootfs directory missing for %s: %w", refStr, err)
	}

	return img.RootfsPath, nil
}

// ListImages returns all stored container images.
func (s *Store) ListImages() ([]StoredImage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.imageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []StoredImage
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(s.imageDir, entry.Name(), "image.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var img StoredImage
		if err := json.Unmarshal(data, &img); err == nil {
			result = append(result, img)
		}
	}

	return result, nil
}
