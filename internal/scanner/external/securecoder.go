package external

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ── SecureCoder API Types ────────────────────────────────────────────────────

// secureCoderScanResponse is the raw response from POST /scan.
type secureCoderScanResponse struct {
	Findings []secureCoderFinding `json:"findings"`
	Errors   []string             `json:"errors"`
}

type secureCoderFinding struct {
	Subcategory string `json:"subcategory"`
	Message     string `json:"message"`
	Location    struct {
		Path  string `json:"path"`
		Range struct {
			TextRange struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
				EndLine     int `json:"endLine"`
				EndColumn   int `json:"endColumn"`
			} `json:"textRange"`
		} `json:"range"`
	} `json:"location"`
	Labels struct {
		Severity           string `json:"severity"`
		CWE                string `json:"cwe"`
		Category           string `json:"category"`
		VulnerabilityClass string `json:"vulnerability_class"`
	} `json:"labels"`
}

// secureCoderConfigResponse is the response from GET /config.
type secureCoderConfigResponse struct {
	ScannerBackend *string `json:"scannerBackend"`
}

// DepFinding is a dependency vulnerability found by SecureCoder.
type DepFinding struct {
	Registry            string `json:"registry"`
	Package             string `json:"package"`
	Version             string `json:"version"`
	Reason              string `json:"reason"`
	Action              string `json:"action"`
	SuggestedVersion    string `json:"suggested_version,omitempty"`
	AlternativePackages string `json:"alternative_packages,omitempty"`
}

type secureCoderDepsRequest struct {
	Registry string              `json:"registry"`
	Packages []DepPackageRequest `json:"packages"`
}

// DepPackageRequest describes a package to check.
type DepPackageRequest struct {
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
}

type secureCoderDepsResponse struct {
	UnsafeDependencies []DepFinding `json:"unsafeDependencies"`
}

// IgnoreRequest is the payload for POST /ignore.
type IgnoreRequest struct {
	FilePath           string `json:"filePath"`
	RuleID             string `json:"ruleId"`
	CodeSnippet        string `json:"codeSnippet"`
	LineNumber         int    `json:"lineNumber"`
	VulnerabilityClass string `json:"vulnerabilityClass"`
	Reason             string `json:"reason"` // "False Positive", "Accepted Risk", "Won't Fix"
}

// IgnoreResponse is the response from POST /ignore.
type IgnoreResponse struct {
	Success     bool   `json:"success"`
	VulnID      string `json:"vulnId"`
	ContentHash string `json:"contentHash"`
}

// IgnoreEntry is an entry from GET /ignored.
type IgnoreEntry struct {
	VulnID      string `json:"vulnId"`
	RuleID      string `json:"ruleId"`
	FilePath    string `json:"filePath"`
	ContentHash string `json:"contentHash"`
	Reason      string `json:"reason"`
	Timestamp   int64  `json:"timestamp"`
}

// apiConfig holds the port from ~/.securecoder/api.json.
type apiConfig struct {
	Port int `json:"port"`
}

// ── Port Discovery ───────────────────────────────────────────────────────────

// DiscoverSecureCoderPort reads the SecureCoder API port from
// ~/.securecoder/api.json or the $SECURECODER_API_PORT env var.
func DiscoverSecureCoderPort() (int, error) {
	// 1. Try ~/.securecoder/api.json
	home, err := os.UserHomeDir()
	if err == nil {
		configPath := filepath.Join(home, ".securecoder", "api.json")
		data, err := os.ReadFile(configPath)
		if err == nil {
			var cfg apiConfig
			if json.Unmarshal(data, &cfg) == nil && cfg.Port > 0 {
				return cfg.Port, nil
			}
		}
	}

	// 2. Fallback: $SECURECODER_API_PORT
	if portStr := os.Getenv("SECURECODER_API_PORT"); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err == nil && port > 0 {
			return port, nil
		}
	}

	return 0, fmt.Errorf("SecureCoder API port not found: checked ~/.securecoder/api.json and $SECURECODER_API_PORT")
}

// baseURL returns the SecureCoder API base URL or an error.
func baseURL() (string, error) {
	port, err := DiscoverSecureCoderPort()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://127.0.0.1:%d", port), nil
}

// ── Availability Check ──────────────────────────────────────────────────────

// IsSecureCoderRunning checks if SecureCoder API is reachable (GET /config).
func IsSecureCoderRunning() bool {
	url, err := baseURL()
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url + "/config")
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

// SecureCoderBackend returns the active scanner backend ("semgrep", "wiz", or "").
func SecureCoderBackend() string {
	url, err := baseURL()
	if err != nil {
		return ""
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url + "/config")
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	var cfg secureCoderConfigResponse
	if json.NewDecoder(resp.Body).Decode(&cfg) != nil || cfg.ScannerBackend == nil {
		return ""
	}
	return *cfg.ScannerBackend
}

// ── Scan ─────────────────────────────────────────────────────────────────────

// RunSecureCoder scans a single file via SecureCoder API and returns unified findings.
func RunSecureCoder(ctx context.Context, filePath string) ([]UnifiedFinding, error) {
	url, err := baseURL()
	if err != nil {
		return nil, fmt.Errorf("securecoder not available: %w", err)
	}

	body, _ := json.Marshal(map[string]string{"filePath": filePath})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("securecoder scan request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securecoder returned status %d", resp.StatusCode)
	}

	var scanResp secureCoderScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, fmt.Errorf("failed to parse securecoder response: %w", err)
	}

	findings := make([]UnifiedFinding, 0, len(scanResp.Findings))
	for _, f := range scanResp.Findings {
		findings = append(findings, UnifiedFinding{
			Source:             "securecoder",
			RuleID:             f.Subcategory,
			Severity:           f.Labels.Severity,
			Message:            f.Message,
			File:               f.Location.Path,
			Line:               f.Location.Range.TextRange.StartLine,
			CWE:                f.Labels.CWE,
			VulnerabilityClass: f.Labels.VulnerabilityClass,
			EndLine:            f.Location.Range.TextRange.EndLine,
			StartColumn:        f.Location.Range.TextRange.StartColumn,
			EndColumn:          f.Location.Range.TextRange.EndColumn,
		})
	}
	return findings, nil
}

// ── Dependency Scan ──────────────────────────────────────────────────────────

// RunSecureCoderDeps checks packages for known vulnerabilities before importing.
// Supported registries: npm, pypi, gomodproxy, rubygems, crates.io, maven, nuget.
func RunSecureCoderDeps(ctx context.Context, registry string, packages []DepPackageRequest) ([]DepFinding, error) {
	url, err := baseURL()
	if err != nil {
		return nil, fmt.Errorf("securecoder not available: %w", err)
	}

	payload := secureCoderDepsRequest{
		Registry: registry,
		Packages: packages,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/dependency/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("securecoder dependency scan failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securecoder returned status %d", resp.StatusCode)
	}

	var depsResp secureCoderDepsResponse
	if err := json.NewDecoder(resp.Body).Decode(&depsResp); err != nil {
		return nil, fmt.Errorf("failed to parse securecoder deps response: %w", err)
	}
	return depsResp.UnsafeDependencies, nil
}

// ── Ignore / Suppress ────────────────────────────────────────────────────────

// IgnoreSecureCoderFinding suppresses a finding in SecureCoder.
func IgnoreSecureCoderFinding(ctx context.Context, params IgnoreRequest) (*IgnoreResponse, error) {
	url, err := baseURL()
	if err != nil {
		return nil, fmt.Errorf("securecoder not available: %w", err)
	}

	body, _ := json.Marshal(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/ignore", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("securecoder ignore request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securecoder returned status %d", resp.StatusCode)
	}

	var result IgnoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse securecoder ignore response: %w", err)
	}
	return &result, nil
}
