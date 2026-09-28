package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

const (
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeOCIManifestIndex   = "application/vnd.oci.image.index.v1+json"
	MediaTypeOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
)

// ManifestDescriptor represents a sub-manifest in a multi-arch manifest list / index.
type ManifestDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform"`
}

// ManifestList models a Docker v2 manifest list or OCI index.
type ManifestList struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	Manifests     []ManifestDescriptor `json:"manifests"`
}

// LayerDescriptor describes a single filesystem layer in a container manifest.
type LayerDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// Manifest models a single-architecture Docker v2 or OCI image manifest.
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Layers        []LayerDescriptor `json:"layers"`
}

// RegistryClient interacts with an OCI/Docker v2 registry.
type RegistryClient struct {
	httpClient *http.Client
	tokenCache map[string]string
}

// NewRegistryClient initializes a registry HTTP client.
func NewRegistryClient() *RegistryClient {
	return &RegistryClient{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		tokenCache: make(map[string]string),
	}
}

// acquireToken extracts auth challenge parameters and fetches an anonymous bearer token.
func (c *RegistryClient) acquireToken(ref *Reference) (string, error) {
	cacheKey := fmt.Sprintf("%s/%s", ref.Registry, ref.Repository)
	if token, ok := c.tokenCache[cacheKey]; ok {
		return token, nil
	}

	testURL := fmt.Sprintf("https://%s/v2/", ref.Registry)
	resp, err := c.httpClient.Get(testURL)
	if err != nil {
		return "", fmt.Errorf("failed to probe registry: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "", nil // No authentication needed
	}

	authHeader := resp.Header.Get("Www-Authenticate")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("unsupported auth header: %s", authHeader)
	}

	params := parseAuthHeader(strings.TrimPrefix(authHeader, "Bearer "))
	realm := params["realm"]
	service := params["service"]

	if realm == "" {
		return "", fmt.Errorf("missing realm in auth challenge")
	}

	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("invalid token realm URL: %w", err)
	}

	q := tokenURL.Query()
	if service != "" {
		q.Set("service", service)
	}
	q.Set("scope", fmt.Sprintf("repository:%s:pull", ref.Repository))
	tokenURL.RawQuery = q.Encode()

	tResp, err := c.httpClient.Get(tokenURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to fetch auth token: %w", err)
	}
	defer tResp.Body.Close()

	if tResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth endpoint returned status %d", tResp.StatusCode)
	}

	var tokenBody struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tResp.Body).Decode(&tokenBody); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	token := tokenBody.Token
	if token == "" {
		token = tokenBody.AccessToken
	}

	c.tokenCache[cacheKey] = token
	return token, nil
}

func parseAuthHeader(header string) map[string]string {
	params := make(map[string]string)
	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.Trim(strings.TrimSpace(kv[1]), "\"")
			params[k] = v
		}
	}
	return params
}

// FetchManifest retrieves the image manifest, automatically resolving multi-arch manifest lists for the current OS/architecture.
func (c *RegistryClient) FetchManifest(ref *Reference) (*Manifest, error) {
	token, err := c.acquireToken(ref)
	if err != nil {
		return nil, fmt.Errorf("auth token error: %w", err)
	}

	return c.fetchManifestByTagOrDigest(ref, ref.Tag, token)
}

func (c *RegistryClient) fetchManifestByTagOrDigest(ref *Reference, tagOrDigest, token string) (*Manifest, error) {
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", ref.Registry, ref.Repository, tagOrDigest)
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	req.Header.Set("Accept", strings.Join([]string{
		MediaTypeDockerManifestList,
		MediaTypeDockerManifest,
		MediaTypeOCIManifestIndex,
		MediaTypeOCIManifest,
	}, ", "))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("manifest request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest request returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest response: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")

	// If this is a manifest list / OCI index, find the matching platform descriptor
	if strings.Contains(contentType, "manifest.list") || strings.Contains(contentType, "image.index") {
		var list ManifestList
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("failed to unmarshal manifest list: %w", err)
		}

		targetArch := runtime.GOARCH
		targetOS := "linux"

		for _, m := range list.Manifests {
			if m.Platform.OS == targetOS && m.Platform.Architecture == targetArch {
				return c.fetchManifestByTagOrDigest(ref, m.Digest, token)
			}
		}

		return nil, fmt.Errorf("no matching manifest found for %s/%s", targetOS, targetArch)
	}

	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if len(m.Layers) == 0 {
		return nil, fmt.Errorf("manifest contains no layers")
	}

	return &m, nil
}

// DownloadBlob streams a layer blob by digest and validates its sha256 checksum against writer w.
func (c *RegistryClient) DownloadBlob(ref *Reference, digest string, w io.Writer) error {
	token, err := c.acquireToken(ref)
	if err != nil {
		return fmt.Errorf("auth token error: %w", err)
	}

	blobURL := fmt.Sprintf("https://%s/v2/%s/blobs/%s", ref.Registry, ref.Repository, digest)
	req, err := http.NewRequest("GET", blobURL, nil)
	if err != nil {
		return err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download blob %s: %w", digest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("blob download failed with status %d", resp.StatusCode)
	}

	hasher := sha256.New()
	mw := io.MultiWriter(w, hasher)

	if _, err := io.Copy(mw, resp.Body); err != nil {
		return fmt.Errorf("error reading blob stream: %w", err)
	}

	expectedHash := strings.TrimPrefix(digest, "sha256:")
	actualHash := hex.EncodeToString(hasher.Sum(nil))

	if !strings.EqualFold(actualHash, expectedHash) {
		return fmt.Errorf("digest mismatch: expected sha256:%s, computed sha256:%s", expectedHash, actualHash)
	}

	return nil
}
