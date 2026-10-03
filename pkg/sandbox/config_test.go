package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMountSpec_Success(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.Mkdir(sourceDir, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name              string
		input             string
		wantRO            bool
		wantContainerPath string
	}{
		{
			name:              "implicit read-write",
			input:             sourceDir + ":/app",
			wantRO:            false,
			wantContainerPath: "/app",
		},
		{
			name:              "explicit rw",
			input:             sourceDir + ":/workspace:rw",
			wantRO:            false,
			wantContainerPath: "/workspace",
		},
		{
			name:              "explicit ro",
			input:             sourceDir + ":/data:ro",
			wantRO:            true,
			wantContainerPath: "/data",
		},
		{
			name:              "relative container target normalized",
			input:             sourceDir + ":relative/dest",
			wantRO:            false,
			wantContainerPath: "/relative/dest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseMountSpec(tt.input)
			if err != nil {
				t.Fatalf("ParseMountSpec(%q) unexpected error: %v", tt.input, err)
			}
			if spec.ReadOnly != tt.wantRO {
				t.Errorf("expected ReadOnly=%v, got %v", tt.wantRO, spec.ReadOnly)
			}
			if spec.ContainerPath != tt.wantContainerPath {
				t.Errorf("expected ContainerPath=%q, got %q", tt.wantContainerPath, spec.ContainerPath)
			}
			if spec.HostPath != sourceDir {
				t.Errorf("expected HostPath=%q, got %q", sourceDir, spec.HostPath)
			}
		})
	}
}

func TestParseMountSpec_Invalid(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"single path missing delimiter", "/single/path"},
		{"too many colons", "/a:/b:ro:extra"},
		{"empty host path", ":/dest"},
		{"empty container path", tmpDir + ":"},
		{"nonexistent host source", "/nonexistent/path/for/sure:/target"},
		{"invalid mode", tmpDir + ":/target:invalid_mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseMountSpec(tt.input)
			if err == nil {
				t.Errorf("ParseMountSpec(%q) expected error, got spec: %+v", tt.input, spec)
			}
		})
	}
}
