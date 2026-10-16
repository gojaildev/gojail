package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"testing"
)

func TestParseAuthHeader(t *testing.T) {
	testCases := []struct {
		name     string
		header   string
		expected map[string]string
	}{
		{
			name:   "standard docker bearer header",
			header: `realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`,
			expected: map[string]string{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
				"scope":   "repository:library/alpine:pull",
			},
		},
		{
			name:   "header with unquoted and spaced values",
			header: `realm=https://example.com/token, service=example.com , key="value"`,
			expected: map[string]string{
				"realm":   "https://example.com/token",
				"service": "example.com",
				"key":     "value",
			},
		},
		{
			name:   "header with malformed non-kv items",
			header: `realm="https://auth.docker.io/token", invalid_token_without_equals, service="registry.docker.io"`,
			expected: map[string]string{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
			},
		},
		{
			name:     "empty header string",
			header:   "",
			expected: map[string]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := parseAuthHeader(tc.header)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Fatalf("expected %+v, got %+v", tc.expected, actual)
			}
		})
	}
}

func TestRegistryClient_AcquireToken(t *testing.T) {
	testCases := []struct {
		name          string
		v2Status      int
		v2AuthHeader  string
		authStatus    int
		authResponse  string
		expectError   bool
		expectedToken string
	}{
		{
			name:          "anonymous public registry without authentication",
			v2Status:      http.StatusOK,
			expectError:   false,
			expectedToken: "",
		},
		{
			name:         "unsupported non-bearer authentication challenge",
			v2Status:     http.StatusUnauthorized,
			v2AuthHeader: `Basic realm="Registry Realm"`,
			expectError:  true,
		},
		{
			name:         "bearer challenge missing realm parameter",
			v2Status:     http.StatusUnauthorized,
			v2AuthHeader: `Bearer service="registry.example.com"`,
			expectError:  true,
		},
		{
			name:         "auth endpoint returns non-200 status",
			v2Status:     http.StatusUnauthorized,
			v2AuthHeader: `Bearer realm="%AUTH_URL%",service="registry.example.com"`,
			authStatus:   http.StatusForbidden,
			expectError:  true,
		},
		{
			name:          "successful token acquisition via token field",
			v2Status:      http.StatusUnauthorized,
			v2AuthHeader:  `Bearer realm="%AUTH_URL%",service="registry.example.com"`,
			authStatus:    http.StatusOK,
			authResponse:  `{"token": "test-jwt-token-123"}`,
			expectError:   false,
			expectedToken: "test-jwt-token-123",
		},
		{
			name:          "successful token acquisition via access_token fallback",
			v2Status:      http.StatusUnauthorized,
			v2AuthHeader:  `Bearer realm="%AUTH_URL%",service="registry.example.com"`,
			authStatus:    http.StatusOK,
			authResponse:  `{"access_token": "test-access-token-456"}`,
			expectError:   false,
			expectedToken: "test-access-token-456",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.authStatus != 0 {
					w.WriteHeader(tc.authStatus)
				}
				if tc.authResponse != "" {
					_, _ = w.Write([]byte(tc.authResponse))
				}
			}))
			defer authServer.Close()

			authHeaderVal := tc.v2AuthHeader
			if authServer != nil {
				authHeaderVal = replaceAuthURL(authHeaderVal, authServer.URL)
			}

			regServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if authHeaderVal != "" {
					w.Header().Set("Www-Authenticate", authHeaderVal)
				}
				w.WriteHeader(tc.v2Status)
			}))
			defer regServer.Close()

			regURL, _ := url.Parse(regServer.URL)
			client := NewRegistryClient()
			regClient := regServer.Client()
			if transport, ok := regClient.Transport.(*http.Transport); ok {
				client.httpClient.Transport = transport.Clone()
			} else {
				client.httpClient = regClient
			}

			ref := &Reference{
				Registry:   regURL.Host,
				Repository: "library/alpine",
				Tag:        "latest",
			}

			token, err := client.acquireToken(ref)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if token != tc.expectedToken {
				t.Errorf("expected token %q, got %q", tc.expectedToken, token)
			}

			if tc.expectedToken != "" {
				cachedToken, err := client.acquireToken(ref)
				if err != nil {
					t.Fatalf("expected cached token without error: %v", err)
				}
				if cachedToken != tc.expectedToken {
					t.Errorf("expected cached token %q, got %q", tc.expectedToken, cachedToken)
				}
			}
		})
	}
}

func TestRegistryClient_FetchManifest(t *testing.T) {
	matchingDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	nonMatchingDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	validManifest := Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeDockerManifest,
		Layers: []LayerDescriptor{
			{
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Digest:    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
				Size:      1024,
			},
		},
	}
	validManifestJSON, _ := json.Marshal(validManifest)

	manifestListMatching := ManifestList{
		SchemaVersion: 2,
		MediaType:     MediaTypeDockerManifestList,
		Manifests: []ManifestDescriptor{
			{
				MediaType: MediaTypeDockerManifest,
				Digest:    nonMatchingDigest,
				Size:      500,
				Platform: struct {
					Architecture string `json:"architecture"`
					OS           string `json:"os"`
				}{
					Architecture: "mips64",
					OS:           "plan9",
				},
			},
			{
				MediaType: MediaTypeDockerManifest,
				Digest:    matchingDigest,
				Size:      500,
				Platform: struct {
					Architecture string `json:"architecture"`
					OS           string `json:"os"`
				}{
					Architecture: runtime.GOARCH,
					OS:           "linux",
				},
			},
		},
	}
	manifestListMatchingJSON, _ := json.Marshal(manifestListMatching)

	manifestListNonMatching := ManifestList{
		SchemaVersion: 2,
		MediaType:     MediaTypeDockerManifestList,
		Manifests: []ManifestDescriptor{
			{
				MediaType: MediaTypeDockerManifest,
				Digest:    nonMatchingDigest,
				Size:      500,
				Platform: struct {
					Architecture string `json:"architecture"`
					OS           string `json:"os"`
				}{
					Architecture: "riscv64",
					OS:           "solaris",
				},
			},
		},
	}
	manifestListNonMatchingJSON, _ := json.Marshal(manifestListNonMatching)

	emptyLayersManifest := Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeDockerManifest,
		Layers:        []LayerDescriptor{},
	}
	emptyLayersManifestJSON, _ := json.Marshal(emptyLayersManifest)

	testCases := []struct {
		name         string
		tagOrDigest  string
		handler      http.HandlerFunc
		expectError  bool
		verifyLayers int
	}{
		{
			name:        "direct single-architecture manifest",
			tagOrDigest: "latest",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/":
					w.WriteHeader(http.StatusOK)
				case "/v2/library/test/manifests/latest":
					w.Header().Set("Content-Type", MediaTypeDockerManifest)
					_, _ = w.Write(validManifestJSON)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectError:  false,
			verifyLayers: 1,
		},
		{
			name:        "multi-arch manifest list resolves matching platform descriptor",
			tagOrDigest: "latest",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/":
					w.WriteHeader(http.StatusOK)
				case "/v2/library/test/manifests/latest":
					w.Header().Set("Content-Type", MediaTypeDockerManifestList)
					_, _ = w.Write(manifestListMatchingJSON)
				case fmt.Sprintf("/v2/library/test/manifests/%s", matchingDigest):
					w.Header().Set("Content-Type", MediaTypeDockerManifest)
					_, _ = w.Write(validManifestJSON)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectError:  false,
			verifyLayers: 1,
		},
		{
			name:        "multi-arch manifest list with no matching platform returns error",
			tagOrDigest: "latest",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/":
					w.WriteHeader(http.StatusOK)
				case "/v2/library/test/manifests/latest":
					w.Header().Set("Content-Type", MediaTypeDockerManifestList)
					_, _ = w.Write(manifestListNonMatchingJSON)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectError: true,
		},
		{
			name:        "manifest with empty layer list returns error",
			tagOrDigest: "empty",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/":
					w.WriteHeader(http.StatusOK)
				case "/v2/library/test/manifests/empty":
					w.Header().Set("Content-Type", MediaTypeDockerManifest)
					_, _ = w.Write(emptyLayersManifestJSON)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectError: true,
		},
		{
			name:        "manifest endpoint non-200 status returns error",
			tagOrDigest: "missing",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v2/":
					w.WriteHeader(http.StatusOK)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(tc.handler)
			defer server.Close()

			u, _ := url.Parse(server.URL)
			client := NewRegistryClient()
			regClient := server.Client()
			if transport, ok := regClient.Transport.(*http.Transport); ok {
				client.httpClient.Transport = transport.Clone()
			} else {
				client.httpClient = regClient
			}

			ref := &Reference{
				Registry:   u.Host,
				Repository: "library/test",
				Tag:        tc.tagOrDigest,
			}

			manifest, err := client.FetchManifest(ref)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(manifest.Layers) != tc.verifyLayers {
				t.Errorf("expected %d layers, got %d", tc.verifyLayers, len(manifest.Layers))
			}
		})
	}
}

func TestRegistryClient_DownloadBlob_Verification(t *testing.T) {
	blobContent := []byte("compressed container layer archive tar payload")
	hasher := sha256.New()
	hasher.Write(blobContent)
	validDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case fmt.Sprintf("/v2/library/test/blobs/%s", validDigest):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blobContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	ref := &Reference{
		Registry:   u.Host,
		Repository: "library/test",
		Tag:        "latest",
	}

	client := NewRegistryClient()
	client.httpClient = server.Client()

	// 1. Success validation
	var buf bytes.Buffer
	if err := client.DownloadBlob(ref, validDigest, &buf); err != nil {
		t.Fatalf("failed to download valid blob: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), blobContent) {
		t.Errorf("downloaded content mismatch")
	}

	// 2. Hash mismatch detection
	var failBuf bytes.Buffer
	invalidDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	err := client.DownloadBlob(ref, invalidDigest, &failBuf)
	if err == nil {
		t.Fatalf("expected error on blob download failure, got nil")
	}
}

func replaceAuthURL(header, authURL string) string {
	return bytes.NewBufferString(
		string(bytes.ReplaceAll([]byte(header), []byte("%AUTH_URL%"), []byte(authURL))),
	).String()
}
