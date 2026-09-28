package image

import (
	"fmt"
	"strings"
)

const (
	DefaultRegistry   = "registry-1.docker.io"
	DefaultAuthServer = "auth.docker.io"
	DefaultService    = "registry.docker.io"
	DefaultTag        = "latest"
)

// Reference represents a parsed container image identifier.
type Reference struct {
	Registry   string
	Repository string
	Tag        string
}

// ParseReference parses an image reference string like "alpine", "library/ubuntu:22.04",
// or "quay.io/coreos/etcd:v3.5.0".
func ParseReference(ref string) (*Reference, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("empty image reference")
	}

	var tag string
	var namePart string

	// Extract tag or digest separator
	if idx := strings.LastIndex(ref, ":"); idx != -1 && !strings.Contains(ref[idx:], "/") {
		namePart = ref[:idx]
		tag = ref[idx+1:]
	} else {
		namePart = ref
		tag = DefaultTag
	}

	parts := strings.Split(namePart, "/")
	var registry string
	var repository string

	// Determine if the first element is a registry domain/IP
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		registry = parts[0]
		repository = strings.Join(parts[1:], "/")
	} else {
		registry = DefaultRegistry
		if len(parts) == 1 {
			// Official library images on Docker Hub require "library/" prefix
			repository = "library/" + parts[0]
		} else {
			repository = strings.Join(parts, "/")
		}
	}

	if repository == "" {
		return nil, fmt.Errorf("invalid image repository in %q", ref)
	}

	return &Reference{
		Registry:   registry,
		Repository: repository,
		Tag:        tag,
	}, nil
}

// FullName returns the normalized canonical name with tag.
func (r *Reference) FullName() string {
	return fmt.Sprintf("%s/%s:%s", r.Registry, r.Repository, r.Tag)
}

// ShortName returns the repository and tag (e.g. "library/alpine:latest" or "alpine:latest").
func (r *Reference) ShortName() string {
	cleanRepo := strings.TrimPrefix(r.Repository, "library/")
	return fmt.Sprintf("%s:%s", cleanRepo, r.Tag)
}

// DirSafeName returns a filesystem-safe identifier used for directory storage.
func (r *Reference) DirSafeName() string {
	safe := strings.ReplaceAll(r.FullName(), "/", "_")
	safe = strings.ReplaceAll(safe, ":", "_")
	return safe
}
