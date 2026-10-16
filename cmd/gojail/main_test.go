package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePortMappings_Valid(t *testing.T) {
	inputs := []string{"8080:80", "53:53/udp", "3000:3000/tcp"}
	mappings, err := parsePortMappings(inputs)
	if err != nil {
		t.Fatalf("unexpected error parsing valid mappings: %v", err)
	}

	if len(mappings) != 3 {
		t.Fatalf("expected 3 mappings, got %d", len(mappings))
	}

	if mappings[0].HostPort != 8080 || mappings[0].ContainerPort != 80 || mappings[0].Protocol != "tcp" {
		t.Errorf("unexpected mapping[0]: %+v", mappings[0])
	}
	if mappings[1].HostPort != 53 || mappings[1].ContainerPort != 53 || mappings[1].Protocol != "udp" {
		t.Errorf("unexpected mapping[1]: %+v", mappings[1])
	}
	if mappings[2].HostPort != 3000 || mappings[2].ContainerPort != 3000 || mappings[2].Protocol != "tcp" {
		t.Errorf("unexpected mapping[2]: %+v", mappings[2])
	}
}

func TestParsePortMappings_Invalid(t *testing.T) {
	testCases := []struct {
		name  string
		input []string
	}{
		{"invalid format", []string{"8080"}},
		{"negative host port", []string{"-1:80"}},
		{"port out of bounds", []string{"70000:80"}},
		{"invalid protocol", []string{"8080:80/sctp"}},
		{"non-numeric port", []string{"http:80"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePortMappings(tc.input)
			if err == nil {
				t.Fatalf("expected error for input %v, got nil", tc.input)
			}
		})
	}
}

func TestStringListFlags(t *testing.T) {
	testCases := []struct {
		name     string
		values   []string
		expected string
	}{
		{
			name:     "empty flags",
			values:   []string{},
			expected: "[]",
		},
		{
			name:     "single flag",
			values:   []string{"/tmp:/tmp"},
			expected: "[/tmp:/tmp]",
		},
		{
			name:     "multiple flags",
			values:   []string{"8080:80", "9090:90"},
			expected: "[8080:80 9090:90]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var flags stringListFlags
			for _, val := range tc.values {
				if err := flags.Set(val); err != nil {
					t.Fatalf("unexpected error setting flag value %q: %v", val, err)
				}
			}

			if got := flags.String(); got != tc.expected {
				t.Errorf("expected string %q, got %q", tc.expected, got)
			}

			if len(flags) != len(tc.values) {
				t.Errorf("expected length %d, got %d", len(tc.values), len(flags))
			}
		})
	}
}

func TestParseMounts_Valid(t *testing.T) {
	tempDir := t.TempDir()
	src1 := filepath.Join(tempDir, "data1")
	src2 := filepath.Join(tempDir, "data2")

	if err := os.MkdirAll(src1, 0755); err != nil {
		t.Fatalf("failed to create temp dir src1: %v", err)
	}
	if err := os.MkdirAll(src2, 0755); err != nil {
		t.Fatalf("failed to create temp dir src2: %v", err)
	}

	testCases := []struct {
		name          string
		rawMounts     []string
		expectedCount int
	}{
		{
			name:          "empty mount list",
			rawMounts:     []string{},
			expectedCount: 0,
		},
		{
			name:          "single mount read-write default",
			rawMounts:     []string{src1 + ":/app/data"},
			expectedCount: 1,
		},
		{
			name:          "multiple mounts with explicit ro and rw modes",
			rawMounts:     []string{src1 + ":/app/data:ro", src2 + ":/app/logs:rw"},
			expectedCount: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			specs, err := parseMounts(tc.rawMounts)
			if err != nil {
				t.Fatalf("unexpected error parsing mounts: %v", err)
			}

			if len(specs) != tc.expectedCount {
				t.Fatalf("expected %d mount specs, got %d", tc.expectedCount, len(specs))
			}
		})
	}
}

func TestParseMounts_Invalid(t *testing.T) {
	tempDir := t.TempDir()
	validSrc := filepath.Join(tempDir, "valid")
	if err := os.MkdirAll(validSrc, 0755); err != nil {
		t.Fatalf("failed to create valid src: %v", err)
	}

	nonExistentSrc := filepath.Join(tempDir, "does-not-exist")

	testCases := []struct {
		name      string
		rawMounts []string
	}{
		{
			name:      "missing separator delimiter",
			rawMounts: []string{"/tmp"},
		},
		{
			name:      "too many colon segments",
			rawMounts: []string{validSrc + ":/data:ro:extra"},
		},
		{
			name:      "empty destination container path",
			rawMounts: []string{validSrc + ":"},
		},
		{
			name:      "nonexistent host source directory",
			rawMounts: []string{nonExistentSrc + ":/data"},
		},
		{
			name:      "invalid mount mode",
			rawMounts: []string{validSrc + ":/data:invalid_mode"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			specs, err := parseMounts(tc.rawMounts)
			if err == nil {
				t.Fatalf("expected error for mounts %v, got specs: %+v", tc.rawMounts, specs)
			}
		})
	}
}
