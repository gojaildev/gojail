package image

import (
	"testing"
)

func TestParseReference_DefaultOfficial(t *testing.T) {
	ref, err := ParseReference("alpine")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref.Registry != DefaultRegistry {
		t.Errorf("expected registry %s, got %s", DefaultRegistry, ref.Registry)
	}
	if ref.Repository != "library/alpine" {
		t.Errorf("expected repository library/alpine, got %s", ref.Repository)
	}
	if ref.Tag != "latest" {
		t.Errorf("expected tag latest, got %s", ref.Tag)
	}
	if ref.ShortName() != "alpine:latest" {
		t.Errorf("expected short name alpine:latest, got %s", ref.ShortName())
	}
}

func TestParseReference_WithTag(t *testing.T) {
	ref, err := ParseReference("ubuntu:22.04")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref.Repository != "library/ubuntu" {
		t.Errorf("expected repository library/ubuntu, got %s", ref.Repository)
	}
	if ref.Tag != "22.04" {
		t.Errorf("expected tag 22.04, got %s", ref.Tag)
	}
}

func TestParseReference_MultiPartRepository(t *testing.T) {
	ref, err := ParseReference("prometheus/node-exporter:v1.6.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref.Registry != DefaultRegistry {
		t.Errorf("expected default registry, got %s", ref.Registry)
	}
	if ref.Repository != "prometheus/node-exporter" {
		t.Errorf("expected repository prometheus/node-exporter, got %s", ref.Repository)
	}
	if ref.Tag != "v1.6.0" {
		t.Errorf("expected tag v1.6.0, got %s", ref.Tag)
	}
}

func TestParseReference_CustomRegistry(t *testing.T) {
	ref, err := ParseReference("ghcr.io/containerd/nerdctl:v1.7.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref.Registry != "ghcr.io" {
		t.Errorf("expected registry ghcr.io, got %s", ref.Registry)
	}
	if ref.Repository != "containerd/nerdctl" {
		t.Errorf("expected repository containerd/nerdctl, got %s", ref.Repository)
	}
	if ref.Tag != "v1.7.0" {
		t.Errorf("expected tag v1.7.0, got %s", ref.Tag)
	}
}

func TestParseReference_DirSafeName(t *testing.T) {
	ref, err := ParseReference("alpine:3.19")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "registry-1.docker.io_library_alpine_3.19"
	if ref.DirSafeName() != expected {
		t.Errorf("expected dir safe name %s, got %s", expected, ref.DirSafeName())
	}
}

func TestParseReference_Invalid(t *testing.T) {
	_, err := ParseReference("")
	if err == nil {
		t.Errorf("expected error on empty reference, got nil")
	}
}
