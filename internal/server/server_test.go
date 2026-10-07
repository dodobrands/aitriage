package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"time"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/server/middleware"
	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

func setupTestServer(t *testing.T) *Server {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to run schema: %v", err)
	}
	return NewServer("", db)
}

func addAuthCookie(req *http.Request) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &middleware.Claims{
		UserID:   1,
		Username: "admin",
		Role:     "superadmin",
		IsAdmin:  true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	tokenString, _ := middleware.SignToken(claims)
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: tokenString,
	})
}

type summaryCaptureLLM struct {
	messages []llm.Message
	response string
}

func (m *summaryCaptureLLM) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	m.messages = append([]llm.Message(nil), messages...)
	return m.response, llm.Usage{}, nil
}

func TestNewServer(t *testing.T) {
	hostPrefix := "/custom-host"
	db, _ := sql.Open("sqlite", ":memory:")
	s := NewServer(hostPrefix, db)

	if s == nil {
		t.Fatal("expected NewServer to return a non-nil Server")
		return
	}

	if s.hostPrefix != hostPrefix {
		t.Errorf("expected hostPrefix to be %q, got %q", hostPrefix, s.hostPrefix)
	}

	// Verify routes are registered by hitting an API endpoint
	req, err := http.NewRequest("GET", "/api/health", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	// We expect a 200 OK because the route is registered and the health handler responds successfully.
	if rr.Code != http.StatusOK {
		t.Errorf("expected /api/health to return 200 OK, got %d", rr.Code)
	}

	// Verify static UI route is registered
	reqUI, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	rrUI := httptest.NewRecorder()
	s.ServeHTTP(rrUI, reqUI)

	if rrUI.Code != http.StatusOK {
		t.Errorf("expected / to return 200 OK, got %d", rrUI.Code)
	}

	// Verify unknown route
	reqUnknown, err := http.NewRequest("GET", "/api/unknown", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	addAuthCookie(reqUnknown)
	rrUnknown := httptest.NewRecorder()
	s.ServeHTTP(rrUnknown, reqUnknown)

	if rrUnknown.Code != http.StatusNotFound {
		t.Errorf("expected unknown API route to return 404, got %d", rrUnknown.Code)
	}
}

func TestServeHTTPCORSAllowsOnlyLoopbackOrigins(t *testing.T) {
	s := setupTestServer(t)

	allowed := httptest.NewRequest(http.MethodOptions, "/api/health", nil)
	allowed.Header.Set("Origin", "http://localhost:5173")
	allowedRecorder := httptest.NewRecorder()
	s.ServeHTTP(allowedRecorder, allowed)
	if allowedRecorder.Code != http.StatusNoContent {
		t.Fatalf("loopback preflight status = %d, want %d", allowedRecorder.Code, http.StatusNoContent)
	}
	if got := allowedRecorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("loopback Access-Control-Allow-Origin = %q", got)
	}

	rejected := httptest.NewRequest(http.MethodPost, "/api/admin/purge", nil)
	rejected.Header.Set("Origin", "https://example.invalid")
	rejectedRecorder := httptest.NewRecorder()
	s.ServeHTTP(rejectedRecorder, rejected)
	if rejectedRecorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin destructive request status = %d, want %d", rejectedRecorder.Code, http.StatusForbidden)
	}
	if got := rejectedRecorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("rejected origin was reflected: %q", got)
	}

	plain := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	plainRecorder := httptest.NewRecorder()
	s.ServeHTTP(plainRecorder, plain)
	if plainRecorder.Code != http.StatusOK {
		t.Fatalf("request without Origin status = %d, want %d", plainRecorder.Code, http.StatusOK)
	}
	if got := plainRecorder.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatal("server must never emit wildcard CORS")
	}
}

func TestDeleteRowsRollsBackOnFailure(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY); INSERT INTO items (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	err = s.deleteRows(context.Background(), []deleteQuery{
		{"items", "DELETE FROM items"},
		{"missing", "DELETE FROM missing_table"},
	})
	if err == nil {
		t.Fatal("deleteRows accepted a partial purge")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM items`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("failed transaction left %d rows, want rollback to 1", count)
	}
}

func TestRunwayHandoffAndArtifactRoutes(t *testing.T) {
	s := setupTestServer(t)
	s.db.SetMaxOpenConns(1)
	if _, err := s.db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	productResult, err := s.db.Exec(`INSERT INTO products (name) VALUES (?)`, "handoff-test")
	if err != nil {
		t.Fatal(err)
	}
	productID, _ := productResult.LastInsertId()
	session := &models.RunwaySession{ProductID: productID, Status: "completed", CurrentStep: 7, AutoMode: true}
	if err := s.runwayRepo.Create(context.Background(), session); err != nil {
		t.Fatal(err)
	}

	prompt := "### AI Remediation Prompt\n\n```markdown\nAudit first, then implement.\n```\n"
	agentData := `{"scan_date":"2026-07-15","score":72,"grade":"C","gate_status":"FAILED","policy":{"profile":"balanced","fail_on":"high"},"stats":{"true_positives":1,"needs_review":1,"false_positives":2,"total":4},"findings":[{"id":"CS-WEB-001","severity":"HIGH","title":"Unsafe output","disposition":"True Positive"}]}`
	artifacts := []models.RunwayArtifact{
		newRunwayArtifact(session.ID, models.RunwayArtifactRemediationPromptMarkdown, "text/markdown; charset=utf-8", 1, prompt),
		newRunwayArtifact(session.ID, models.RunwayArtifactAgentDataJSON, "application/json; charset=utf-8", 1, agentData),
	}
	if err := s.runwayArtifactRepo.UpsertMany(context.Background(), artifacts); err != nil {
		t.Fatal(err)
	}
	if err := s.runwayArtifactRepo.UpsertMany(context.Background(), artifacts); err != nil {
		t.Fatal(err)
	}
	var artifactCount int
	if err := s.db.QueryRow(`SELECT count(*) FROM runway_artifacts WHERE session_id = ?`, session.ID).Scan(&artifactCount); err != nil {
		t.Fatal(err)
	}
	if artifactCount != len(artifacts) {
		t.Fatalf("idempotent upsert stored %d rows, want %d", artifactCount, len(artifacts))
	}

	handoffRequest := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/runway/handoff/%d", session.ID), nil)
	handoffRecorder := httptest.NewRecorder()
	s.ServeHTTP(handoffRecorder, handoffRequest)
	if handoffRecorder.Code != http.StatusOK {
		t.Fatalf("handoff status = %d, body = %s", handoffRecorder.Code, handoffRecorder.Body.String())
	}
	var handoff map[string]any
	if err := json.Unmarshal(handoffRecorder.Body.Bytes(), &handoff); err != nil {
		t.Fatal(err)
	}
	if handoff["remediation_prompt_markdown"] != prompt {
		t.Fatalf("handoff prompt mismatch: %#v", handoff["remediation_prompt_markdown"])
	}
	if handoff["gate_status"] != "FAILED" {
		t.Fatalf("handoff gate = %#v", handoff["gate_status"])
	}

	manifestRequest := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/runway/artifacts/%d", session.ID), nil)
	manifestRecorder := httptest.NewRecorder()
	s.ServeHTTP(manifestRecorder, manifestRequest)
	if manifestRecorder.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, body = %s", manifestRecorder.Code, manifestRecorder.Body.String())
	}
	if strings.Contains(manifestRecorder.Body.String(), "Audit first") {
		t.Fatal("artifact manifest leaked artifact content")
	}

	downloadRequest := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/runway/artifacts/%d/%s", session.ID, models.RunwayArtifactRemediationPromptMarkdown), nil)
	downloadRecorder := httptest.NewRecorder()
	s.ServeHTTP(downloadRecorder, downloadRequest)
	if downloadRecorder.Code != http.StatusOK {
		t.Fatalf("download status = %d, body = %s", downloadRecorder.Code, downloadRecorder.Body.String())
	}
	if downloadRecorder.Body.String() != prompt {
		t.Fatal("downloaded prompt content mismatch")
	}
	if got := downloadRecorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := downloadRecorder.Header().Get("ETag"); got == "" {
		t.Fatal("artifact download is missing ETag")
	}

	invalidRequest := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/runway/artifacts/%d/not-a-real-kind", session.ID), nil)
	invalidRecorder := httptest.NewRecorder()
	s.ServeHTTP(invalidRecorder, invalidRequest)
	if invalidRecorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid kind status = %d, want 400", invalidRecorder.Code)
	}

	if err := s.runwayRepo.Delete(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM runway_artifacts WHERE session_id = ?`, session.ID).Scan(&artifactCount); err != nil {
		t.Fatal(err)
	}
	if artifactCount != 0 {
		t.Fatalf("cascade delete left %d artifacts", artifactCount)
	}
}

func TestHandleCreateUserValidation(t *testing.T) {
	s := setupTestServer(t)

	// Admin token
	req, _ := http.NewRequest("POST", "/api/admin/users", bytes.NewBuffer([]byte(`{}`)))
	addAuthCookie(req)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	// Since we added validation for Username, empty username returns 400.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing username (validation), got %d", rr.Code)
	}

	// Invalid ID query for delete
	reqDel, _ := http.NewRequest("DELETE", "/api/admin/users?id=abc", nil)
	addAuthCookie(reqDel)
	rrDel := httptest.NewRecorder()
	s.ServeHTTP(rrDel, reqDel)

	if rrDel.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid ID, got %d", rrDel.Code)
	}
}

func TestHandleSummaryUsesSecureCoderEvidenceContract(t *testing.T) {
	s := setupTestServer(t)
	projectDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
  "name": "sample-landing",
  "scripts": {"build": "tsc -b && vite build"},
  "dependencies": {"react": "19.2.6", "react-dom": "19.2.6"},
  "devDependencies": {"vite": "8.0.12", "@vitejs/plugin-react": "6.0.1"}
}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "vite.config.ts"), []byte("export default {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, "src"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "src", "main.tsx"), []byte("import React from 'react'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "src", "App.tsx"), []byte("export default function App() { return null }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "SECURITY_TRIAGE_REPORT.md"), []byte(`# Security triage report

Current application shape: static Vite + React landing page. The repository has no backend server, API routes, auth middleware, database client, form submission endpoint, cookies, or user-controlled HTML rendering.

Authentication Middleware Missing: false positive for the current repository.
Rate Limiting Missing: false positive for the current repository.
`), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := s.db.Exec(`INSERT INTO products (name, repo_url, tech_stack, business_criticality, lifecycle) VALUES (?, ?, ?, ?, ?)`, "sample-landing", projectDir, "Vite + React", "medium", "production")
	if err != nil {
		t.Fatalf("failed to insert product: %v", err)
	}
	productID, _ := res.LastInsertId()
	res, err = s.db.Exec(`INSERT INTO engagements (product_id, name, scan_path, status) VALUES (?, ?, ?, ?)`, productID, "scan", projectDir, "completed")
	if err != nil {
		t.Fatalf("failed to insert engagement: %v", err)
	}
	engagementID, _ := res.LastInsertId()

	_, err = s.db.Exec(`
		INSERT INTO findings (engagement_id, product_id, rule_id, title, severity, file_path, line_number, description, fix_suggestion, status, kanban_column, stack, is_false_positive, fp_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, engagementID, productID, "AUTH-MIDDLEWARE", "Authentication Middleware Missing", "CRITICAL", "", 0, "Project-level auth rule", "No backend/API route evidence in this static landing page.", "false_positive", "done", "nfr", 1, "static landing page")
	if err != nil {
		t.Fatalf("failed to insert false positive finding: %v", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO findings (engagement_id, product_id, rule_id, title, severity, file_path, line_number, description, fix_suggestion, status, kanban_column, stack)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, engagementID, productID, "SEC-HEADERS", "Missing Security Headers", "HIGH", "vite.config.ts", 10, "Preview server headers need verification.", "Set CSP and related headers.", "open", "backlog", "deploy")
	if err != nil {
		t.Fatalf("failed to insert active finding: %v", err)
	}

	capture := &summaryCaptureLLM{response: "**Security status:** evidence-based"}
	s.llmClient = capture

	req, _ := http.NewRequest("GET", "/api/ai-summary?product_id="+strconv.FormatInt(productID, 10)+"&lang=ru&generate=true", nil)
	addAuthCookie(req)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["summary"] != capture.response {
		t.Fatalf("unexpected summary response: %#v", resp)
	}
	if len(capture.messages) != 2 {
		t.Fatalf("expected two LLM messages, got %d", len(capture.messages))
	}

	systemPrompt := capture.messages[0].Content
	for _, want := range []string{
		"Do not infer backend/API/auth/rate-limit risk",
		"Scanner titles are hypotheses, not proof",
		"Respond in Russian",
	} {
		if !strings.Contains(systemPrompt, want) {
			t.Fatalf("system prompt missing %q:\n%s", want, systemPrompt)
		}
	}

	userPrompt := capture.messages[1].Content
	for _, want := range []string{
		"Product: sample-landing",
		"Active findings: 1",
		"Non-active/suppressed findings: 1",
		"Detected project markers: package.json, vite.config.ts, src/main.tsx, src/App.tsx",
		"Backend dependency markers: none",
		"Server/API route file markers: none",
		"[non-active][CRITICAL][AUTH-MIDDLEWARE] Authentication Middleware Missing",
		"status=false_positive",
		"[active][HIGH][SEC-HEADERS] Missing Security Headers at `vite.config.ts:10`",
		"Current application shape: static Vite + React landing page",
	} {
		if !strings.Contains(userPrompt, want) {
			t.Fatalf("user prompt missing %q:\n%s", want, userPrompt)
		}
	}

	// Persistence: a plain GET (no generate) must return the stored summary
	// without another LLM call, so it survives page refreshes.
	capture.messages = nil
	req2, _ := http.NewRequest("GET", "/api/ai-summary?product_id="+strconv.FormatInt(productID, 10)+"&lang=ru", nil)
	addAuthCookie(req2)
	rr2 := httptest.NewRecorder()
	s.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("stored GET expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 map[string]any
	if err := json.NewDecoder(rr2.Body).Decode(&resp2); err != nil {
		t.Fatalf("failed to decode stored response: %v", err)
	}
	if resp2["summary"] != capture.response {
		t.Fatalf("stored summary not returned on plain GET: %#v", resp2)
	}
	if len(capture.messages) != 0 {
		t.Fatalf("plain GET must not call the LLM, got %d messages", len(capture.messages))
	}
}

func TestHandleHealth(t *testing.T) {
	s := setupTestServer(t)

	req, err := http.NewRequest("GET", "/api/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if ok, exists := resp["ok"].(bool); !exists || !ok {
		t.Errorf("expected ok: true, got %v", resp)
	}
}

func TestHandleScan(t *testing.T) {
	s := setupTestServer(t)
	tempDir := t.TempDir()

	// 1. Test empty body
	req, _ := http.NewRequest("POST", "/api/scan", bytes.NewBuffer([]byte{}))
	addAuthCookie(req)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for empty body, got %d", rr.Code)
	}

	// 2. Test valid request
	body, err := json.Marshal(map[string]any{"path": tempDir, "external": false})
	if err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest("POST", "/api/scan", bytes.NewBuffer(body))
	addAuthCookie(req)
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var resp scanResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Ok field is lowercase in the struct (Ok, not OK)
	if !resp.Ok {
		t.Errorf("expected Ok to be true, got error: %s", resp.Error)
	}
	if resp.ScanID == "" {
		t.Errorf("expected ScanID to be populated")
	}
	// scanResponse does not include Path — verify via scan_id presence
	if resp.ScanID == "" {
		t.Errorf("expected ScanID to be non-empty, got %q", resp.ScanID)
	}
}

func TestHandleScanContainerModeFailsClosedWhenBundleExecutionsAreMissing(t *testing.T) {
	t.Setenv("AITRIAGE_RUNTIME", "container")
	// An empty PATH deterministically makes every external scanner unavailable.
	t.Setenv("PATH", t.TempDir())
	s := setupTestServer(t)
	tempDir := t.TempDir()
	body, err := json.Marshal(map[string]any{"path": tempDir})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "/api/scan", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("container partial scan status = %d, want 503: %s", rr.Code, rr.Body.String())
	}
	for _, scanner := range []string{"semgrep", "trivy_fs", "trivy_config", "gitleaks", "bandit"} {
		if !strings.Contains(rr.Body.String(), scanner) {
			t.Errorf("fail-closed response does not name %s: %s", scanner, rr.Body.String())
		}
	}
}

func TestResolveProjectPathConfinesContainerWebToOpenedRoot(t *testing.T) {
	s := setupTestServer(t)
	root := t.TempDir()
	s.hostPrefix = root
	nested := filepath.Join(root, "synthetic", "app")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	root, _ = filepath.EvalSymlinks(root)
	nested, _ = filepath.EvalSymlinks(nested)

	for _, input := range []string{".", "/", "/project", "/host"} {
		got, err := s.resolveProjectPath(input)
		if err != nil || got != root {
			t.Errorf("root alias %q = %q, %v; want %q", input, got, err, root)
		}
	}
	for _, input := range []string{"synthetic/app", "/synthetic/app", "/project/synthetic/app", "/host/synthetic/app", nested} {
		got, err := s.resolveProjectPath(input)
		if err != nil || got != nested {
			t.Errorf("nested path %q = %q, %v; want %q", input, got, err, nested)
		}
	}
	if _, err := s.resolveProjectPath("../escape"); err == nil {
		t.Fatal("parent traversal must be rejected")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := s.resolveProjectPath("escape"); err == nil {
		t.Fatal("symlink escape must be rejected")
	}
}

func TestContainerWebEndpointsRejectTraversal(t *testing.T) {
	s := setupTestServer(t)
	s.hostPrefix = t.TempDir()

	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/browser?path=../", ""},
		{http.MethodPost, "/api/scan", `{"path":"../"}`},
		{http.MethodPost, "/api/securecoder/scan-directory", `{"path":"../"}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s %s status = %d, want 403: %s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
}

func TestManagedWebRebuildCannotKillServer(t *testing.T) {
	s := setupTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/rebuild", nil)
	addAuthCookie(req)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("rebuild status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "aitriage setup --repair") {
		t.Fatalf("rebuild response is not actionable: %s", rr.Body.String())
	}
	if err := s.db.Ping(); err != nil {
		t.Fatalf("server database unavailable after rejected rebuild: %v", err)
	}
}

func TestRunwayProjectPathUsesSameContainerConfinement(t *testing.T) {
	s := setupTestServer(t)
	root := t.TempDir()
	s.hostPrefix = root
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := "nested"
	got, err := s.resolveRunwayProjectPath(&models.Product{RepoURL: &repo})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(nested)
	if got != want {
		t.Fatalf("runway root = %q, want %q", got, want)
	}
	escape := "../escape"
	if _, err := s.resolveRunwayProjectPath(&models.Product{RepoURL: &escape}); err == nil {
		t.Fatal("runway path traversal must be rejected")
	}
}

func seedFindingForRemediation(t *testing.T, s *Server, scanPath string) int64 {
	t.Helper()

	res, err := s.db.Exec(`INSERT INTO products (name, repo_url, business_criticality) VALUES (?, ?, ?)`, "Demo", scanPath, "high")
	if err != nil {
		t.Fatalf("failed to insert product: %v", err)
	}
	productID, _ := res.LastInsertId()

	res, err = s.db.Exec(`INSERT INTO engagements (product_id, name, scan_path, status) VALUES (?, ?, ?, ?)`, productID, "Demo scan", scanPath, "completed")
	if err != nil {
		t.Fatalf("failed to insert engagement: %v", err)
	}
	engagementID, _ := res.LastInsertId()

	desc := "Unsanitized user input reaches a sink."
	fix := "Validate input at the boundary."
	res, err = s.db.Exec(`
		INSERT INTO findings (engagement_id, product_id, rule_id, title, severity, file_path, line_number, description, fix_suggestion, status, kanban_column, stack)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, engagementID, productID, "TEST-RULE", "Unsafe input handling", "HIGH", "src/app.go", 2, desc, fix, "open", "backlog", "go")
	if err != nil {
		t.Fatalf("failed to insert finding: %v", err)
	}
	findingID, _ := res.LastInsertId()
	return findingID
}

func TestFindingAgentPromptPreservesLifecycle(t *testing.T) {
	s := setupTestServer(t)
	tempDir := t.TempDir()
	srcDir := filepath.Join(tempDir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8ifQ." +
		"fake_signature_here"
	if err := os.WriteFile(filepath.Join(srcDir, "app.go"), []byte("package main\n// token: "+jwt+"\nfunc handler(input string) {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	findingID := seedFindingForRemediation(t, s, tempDir)

	req, _ := http.NewRequest("POST", "/api/findings/"+strconv.FormatInt(findingID, 10)+"/agent-prompt", nil)
	addAuthCookie(req)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["ok"] != true {
		t.Fatalf("expected ok response, got %#v", resp)
	}
	prompt, _ := resp["prompt"].(string)
	if !strings.Contains(prompt, "Unsafe input handling") || !strings.Contains(prompt, "src/app.go:2") {
		t.Fatalf("prompt missing finding context: %s", prompt)
	}
	if !strings.Contains(prompt, "AITriage generated this AGENT PROMPT") ||
		!strings.Contains(prompt, "## Remediation Guidance") ||
		!strings.Contains(prompt, "## Source Excerpt (redacted)") {
		t.Fatalf("prompt missing expected sections: %s", prompt)
	}
	if strings.Contains(prompt, jwt) || !strings.Contains(prompt, "[REDACTED]") {
		t.Fatalf("prompt did not redact source secret: %s", prompt)
	}

	finding, err := s.findingRepo.GetByID(req.Context(), findingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Status != "open" || finding.KanbanColumn != "backlog" {
		t.Fatalf("unexpected finding lifecycle: status=%q kanban=%q", finding.Status, finding.KanbanColumn)
	}
	if finding.AgentPrompt == nil || !strings.Contains(*finding.AgentPrompt, "Required Workflow") {
		t.Fatalf("expected stored agent prompt, got %#v", finding.AgentPrompt)
	}
}

func TestLocalPathForHostPrefixUsesDockerMountInfo(t *testing.T) {
	mountInfo := "315 306 0:43 /example/workspace /host rw,nosuid,nodev,relatime - fakeowner /run/host_mark/home rw,fakeowner"
	got, ok := localPathForHostPrefix("/host", "/host/demo-app/app.py", mountInfo)
	if !ok {
		t.Fatal("expected host path to be derived from mount info")
	}
	want := "/home/example/workspace/demo-app/app.py"
	if got != want {
		t.Fatalf("unexpected local path: got %q want %q", got, want)
	}
}

func TestRepositoryRelativePathPrefersPathInsideScanRoot(t *testing.T) {
	got := repositoryRelativePath("/host/demo-app", "/host/demo-app/thirdparty/VAmPI/app.py", "/host/demo-app/thirdparty/VAmPI/app.py")
	want := "thirdparty/VAmPI/app.py"
	if got != want {
		t.Fatalf("unexpected repository-relative path: got %q want %q", got, want)
	}
}

func TestFindingVerificationTransitions(t *testing.T) {
	s := setupTestServer(t)
	findingID := seedFindingForRemediation(t, s, t.TempDir())

	if err := s.findingRepo.MarkPendingVerification(context.Background(), findingID); err != nil {
		t.Fatalf("MarkPendingVerification failed: %v", err)
	}
	finding, err := s.findingRepo.GetByID(context.Background(), findingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Status != "pending_verification" || finding.VerificationStatus == nil || *finding.VerificationStatus != "running" {
		t.Fatalf("unexpected pending state: status=%q verification=%v", finding.Status, finding.VerificationStatus)
	}

	if err := s.findingRepo.MarkVerificationResult(context.Background(), findingID, false, "still detected"); err != nil {
		t.Fatalf("MarkVerificationResult(false) failed: %v", err)
	}
	finding, err = s.findingRepo.GetByID(context.Background(), findingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Status != "verification_failed" || finding.IsVerified {
		t.Fatalf("unexpected failed verification state: status=%q verified=%v", finding.Status, finding.IsVerified)
	}

	if err := s.findingRepo.MarkVerificationResult(context.Background(), findingID, true, "not detected"); err != nil {
		t.Fatalf("MarkVerificationResult(true) failed: %v", err)
	}
	finding, err = s.findingRepo.GetByID(context.Background(), findingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Status != "resolved" || !finding.IsVerified || finding.ResolvedAt == nil || finding.VerifiedAt == nil {
		t.Fatalf("unexpected resolved state: status=%q verified=%v resolved_at=%v verified_at=%v", finding.Status, finding.IsVerified, finding.ResolvedAt, finding.VerifiedAt)
	}
}

func TestServeUI(t *testing.T) {
	s := setupTestServer(t)

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") && !strings.Contains(rr.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("expected Content-Type text/html or text/plain, got %v", rr.Header().Get("Content-Type"))
	}
}
