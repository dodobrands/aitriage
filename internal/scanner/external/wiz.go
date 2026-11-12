package external

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	wizBinaryPath = "/usr/local/bin/wizcli"
	wizAuthFile   = filepath.Join(os.Getenv("HOME"), ".wiz", "auth.json")

	// Global session for device-code login tracking
	loginSession *WizLoginSession
	sessionMutex sync.Mutex
)

type WizLoginSession struct {
	Status          string `json:"status"` // "starting", "prompt", "success", "failed"
	UserCode        string `json:"userCode"`
	VerificationURL string `json:"verificationUrl"`
	Error           string `json:"error,omitempty"`
	Completed       bool   `json:"completed"`
	cmd             *exec.Cmd
}

// EnsureWizCLI checks if wizcli binary exists and downloads it if missing.
func EnsureWizCLI(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("wizcli"); err == nil {
		return "wizcli", nil
	}
	if _, err := os.Stat(wizBinaryPath); err == nil {
		return wizBinaryPath, nil
	}

	// Determine download URL
	arch := runtime.GOARCH
	var url string
	switch runtime.GOOS {
	case "darwin":
		if arch == "arm64" {
			url = "https://downloads.wiz.io/v1/wizcli/latest/wizcli-darwin-arm64"
		} else {
			url = "https://downloads.wiz.io/v1/wizcli/latest/wizcli-darwin-amd64"
		}
	case "linux":
		if arch == "arm64" {
			url = "https://downloads.wiz.io/v1/wizcli/latest/wizcli-linux-arm64"
		} else {
			url = "https://downloads.wiz.io/v1/wizcli/latest/wizcli-linux-amd64"
		}
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	slog.Info("Downloading Wiz CLI", "url", url, "dest", wizBinaryPath)

	// Create parent dirs if not exist
	dir := filepath.Dir(wizBinaryPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		// Fallback to temp dir if /usr/local/bin is not writable
		wizBinaryPath = filepath.Join(os.TempDir(), "wizcli")
		slog.Warn("Failed to create dir, falling back to temp path", "dest", wizBinaryPath, "error", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	out, err := os.OpenFile(wizBinaryPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		return "", fmt.Errorf("failed to save binary: %w", err)
	}
	if err := out.Close(); err != nil {
		return "", fmt.Errorf("finalize downloaded binary: %w", err)
	}

	return wizBinaryPath, nil
}

// WizAuthStatus checks if Wiz is authenticated and parses JWT to get hours remaining.
func WizAuthStatus() (map[string]any, error) {
	if _, err := os.Stat(wizAuthFile); os.IsNotExist(err) {
		return map[string]any{"authenticated": false}, nil
	}

	data, err := os.ReadFile(wizAuthFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth file: %w", err)
	}

	var auth struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(data, &auth); err != nil || auth.RefreshToken == "" {
		return map[string]any{"authenticated": false}, nil
	}

	// Decode JWT refresh token
	parts := strings.Split(auth.RefreshToken, ".")
	if len(parts) < 2 {
		return map[string]any{"authenticated": false}, nil
	}

	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Fallback: standard base64 decoding with padding if raw fails
		payloadData, err = base64.StdEncoding.DecodeString(parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4))
		if err != nil {
			return map[string]any{"authenticated": false}, nil
		}
	}

	var claims struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(payloadData, &claims); err != nil || claims.ExpiresAt == "" {
		return map[string]any{"authenticated": false}, nil
	}

	expiry, err := time.Parse(time.RFC3339, claims.ExpiresAt)
	if err != nil {
		return map[string]any{"authenticated": false}, nil
	}

	hoursRemaining := int(time.Until(expiry).Hours())
	if hoursRemaining <= 0 {
		return map[string]any{"authenticated": false}, nil
	}

	return map[string]any{
		"authenticated":  true,
		"hoursRemaining": hoursRemaining,
	}, nil
}

// WizLogout removes the authentication file.
func WizLogout() error {
	if err := os.Remove(wizAuthFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// StartWizAuth starts the device-code login flow.
func StartWizAuth(ctx context.Context) (*WizLoginSession, error) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	if loginSession != nil && !loginSession.Completed {
		return loginSession, nil
	}

	binary, err := EnsureWizCLI(ctx)
	if err != nil {
		return nil, fmt.Errorf("wizcli not available: %w", err)
	}

	// Setup background temp scan target to trigger authentication
	tmpDir, err := os.MkdirTemp("", "wiz-auth-")
	if err != nil {
		return nil, err
	}
	tmpJSON := filepath.Join(os.TempDir(), fmt.Sprintf("wiz-auth-%d.json", time.Now().UnixNano()))

	cmd := exec.Command(binary, "scan", "dir", tmpDir,
		"--by-policy-hits=DISABLED",
		"--no-publish",
		"--disabled-scanners=Malware,Vulnerability,Secret,SensitiveData,Misconfiguration,SoftwareSupplyChain,AIModels",
		"--json-output-file="+tmpJSON,
		"--use-device-code",
	)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout // combine

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	session := &WizLoginSession{
		Status:    "starting",
		Completed: false,
		cmd:       cmd,
	}
	loginSession = session

	// Background reader for stdout
	go func() {
		defer func() {
			_ = os.RemoveAll(tmpDir)
			_ = os.Remove(tmpJSON)
		}()

		reader := bufio.NewReader(stdoutPipe)
		urlRegex := regexp.MustCompile(`https?://\S+`)
		codeRegex := regexp.MustCompile(`(?i)(?:user code if requested:|code:)\s*(\S+)`)

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			slog.Info("WizCLI Auth output", "line", strings.TrimSpace(line))

			// Check for device flow URL and code
			if strings.Contains(line, "verification") || strings.Contains(line, "code") || strings.Contains(line, "devicelogin") {
				urls := urlRegex.FindStringSubmatch(line)
				codeMatches := codeRegex.FindStringSubmatch(line)

				sessionMutex.Lock()
				if len(urls) > 0 && session.VerificationURL == "" {
					session.VerificationURL = urls[0]
				}
				if len(codeMatches) > 1 && session.UserCode == "" {
					session.UserCode = codeMatches[1]
				}
				if session.UserCode != "" && session.VerificationURL != "" {
					session.Status = "prompt"
				}
				sessionMutex.Unlock()
			}
		}

		err = cmd.Wait()
		sessionMutex.Lock()
		session.Completed = true
		if err == nil {
			session.Status = "success"
		} else {
			status, _ := WizAuthStatus()
			if authed, ok := status["authenticated"].(bool); ok && authed {
				session.Status = "success"
			} else {
				session.Status = "failed"
				session.Error = err.Error()
			}
		}
		sessionMutex.Unlock()
	}()

	return session, nil
}

// GetActiveLoginSession returns the current login session state.
func GetActiveLoginSession() *WizLoginSession {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	return loginSession
}
