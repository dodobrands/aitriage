package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/server/handlers"
	"github.com/dodobrands/aitriage/internal/server/repositories"
)

func TestConcurrentLLMInitializationAndReads(t *testing.T) {
	s := &Server{}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.initializeLLMClient(llm.Config{Provider: "openai", APIKey: "fixture-unused", BaseURL: "http://127.0.0.1:1"})
			_ = s.getLLMClient()
		}()
	}
	wg.Wait()
	if s.getLLMClient() == nil {
		t.Fatal("client initialization lost")
	}
}

func TestFindingWritesRejectInvalidInputAndMissingRows(t *testing.T) {
	s := setupTestServer(t)
	t.Cleanup(func() { _ = s.db.Close() })
	id := seedFindingForRemediation(t, s, t.TempDir())
	h := handlers.NewFindingHandler(s.findingRepo)
	for _, tc := range []struct {
		path, body string
		code       int
	}{
		{"-1", `{"action":"status","status":"open"}`, 400},
		{"1/status", `{"action":"status","status":"open"}`, 400},
		{"999999", `{"action":"status","status":"open"}`, 404},
		{fmt.Sprint(id), `{"action":"status","status":"invented"}`, 400},
		{fmt.Sprint(id), `{"action":"kanban","kanban_column":"invented"}`, 400},
		{fmt.Sprint(id), `{"action":"status","status":" FIXED "}`, 200},
	} {
		rr := httptest.NewRecorder()
		h.HandleUpdateFinding(rr, httptest.NewRequest(http.MethodPut, "/api/findings/"+tc.path, strings.NewReader(tc.body)))
		if rr.Code != tc.code {
			t.Fatalf("%s %s: %d, want %d: %s", tc.path, tc.body, rr.Code, tc.code, rr.Body)
		}
	}
	f, err := s.findingRepo.GetByID(context.Background(), id)
	if err != nil || f.Status != "resolved" || f.ResolvedAt == nil {
		t.Fatalf("legacy fixed alias: %+v, %v", f, err)
	}
	if err := s.findingRepo.UpdateStatus(context.Background(), id, "accepted_risk"); err != nil {
		t.Fatal(err)
	}
	f, err = s.findingRepo.GetByID(context.Background(), id)
	if err != nil || f.Status != "risk_accepted" || !f.RiskAccepted {
		t.Fatalf("legacy risk alias: %+v, %v", f, err)
	}
}

func TestReopeningVerifiedFindingResetsLifecycleFlags(t *testing.T) {
	s := setupTestServer(t)
	t.Cleanup(func() { _ = s.db.Close() })
	id := seedFindingForRemediation(t, s, t.TempDir())
	if _, err := s.db.Exec(`UPDATE findings SET status='resolved', kanban_column='done', verification_status='fixed', is_verified=1, verified_at=CURRENT_TIMESTAMP, is_false_positive=1, risk_accepted=1, resolved_at=CURRENT_TIMESTAMP WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err := s.findingRepo.UpdateStatus(context.Background(), id, "open"); err != nil {
		t.Fatal(err)
	}
	f, err := s.findingRepo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != "open" || f.IsVerified || f.IsFalsePositive || f.RiskAccepted || f.VerifiedAt != nil || f.ResolvedAt != nil || f.VerificationStatus != nil || f.KanbanColumn == "done" {
		t.Fatalf("stale lifecycle flags: %+v", f)
	}
}

func TestPromptGenerationDoesNotReopenVerifiedFinding(t *testing.T) {
	s := setupTestServer(t)
	t.Cleanup(func() { _ = s.db.Close() })
	id := seedFindingForRemediation(t, s, t.TempDir())
	if err := s.findingRepo.MarkVerificationResult(context.Background(), id, true, "not detected"); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleFindingAgentPrompt(rr, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/findings/%d/agent-prompt", id), nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("generate prompt: %d %s", rr.Code, rr.Body)
	}
	f, err := s.findingRepo.GetByID(context.Background(), id)
	if err != nil || f.Status != "resolved" || f.KanbanColumn != "done" || f.VerificationStatus == nil || *f.VerificationStatus != "fixed" || f.AgentPrompt == nil {
		t.Fatalf("generation changed verified lifecycle: %+v, %v", f, err)
	}
}

func TestBulkCreateHonorsIgnoresWithSingleDatabaseConnection(t *testing.T) {
	s := setupTestServer(t)
	t.Cleanup(func() { _ = s.db.Close() })
	s.db.SetMaxOpenConns(1)
	id := seedFindingForRemediation(t, s, t.TempDir())
	f, err := s.findingRepo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	snippet := "fixture ignored code"
	if _, err := s.db.Exec(`INSERT INTO ignored_findings(vuln_id,rule_id,file_path,code_snippet,content_hash,reason) VALUES ('fixture','TEST-RULE','app.go',?,?,'False Positive')`, snippet, repositories.ContentHash(snippet)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.findingRepo.BulkCreate(ctx, []models.Finding{{EngagementID: f.EngagementID, ProductID: f.ProductID, RuleID: "TEST-RULE", Title: "ignored", Severity: "HIGH", CodeSnippet: &snippet, Status: "open", KanbanColumn: "backlog", Stack: "core"}}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := s.db.QueryRow(`SELECT status FROM findings WHERE title='ignored'`).Scan(&status); err != nil || status != "false_positive" {
		t.Fatalf("ignore lost or transaction blocked: status=%q err=%v", status, err)
	}
}

func TestScanPersistenceFailureIsNotReportedAsSuccess(t *testing.T) {
	t.Setenv("AITRIAGE_RUNTIME", "native")
	t.Setenv("AITRIAGE_REPORTS_DIR", "")
	s := setupTestServer(t)
	t.Cleanup(func() { _ = s.db.Close() })
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"fixture","dependencies":{"axios":"^1.0.0"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER reject_scan BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT,'fixture persistence failure'); END`); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"path": root})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(string(body))))
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("failed write claimed success: %d %s", rr.Code, rr.Body)
	}
	var status string
	if err := s.db.QueryRow(`SELECT status FROM engagements`).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("scan left unfinished engagement: %q, %v", status, err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial findings persisted: %d, %v", count, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_scan`); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(string(body))))
	if rr.Code != http.StatusOK {
		t.Fatalf("healthy scan failed: %d %s", rr.Code, rr.Body)
	}
	if err := s.db.QueryRow(`SELECT status FROM engagements ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil || status != "completed" {
		t.Fatalf("healthy scan marked failed: %q, %v", status, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&count); err != nil || count == 0 {
		t.Fatalf("healthy scan lost findings: %d, %v", count, err)
	}
}

func TestScanRejectsIncompleteCoreAndWrongMethod(t *testing.T) {
	t.Setenv("AITRIAGE_RUNTIME", "native")
	s := setupTestServer(t)
	t.Cleanup(func() { _ = s.db.Close() })
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodGet, "/api/scan", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET scan: %d", rr.Code)
	}
	body, err := json.Marshal(map[string]string{"path": filepath.Join(t.TempDir(), "missing")})
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(string(body))))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("incomplete scan: %d %s", rr.Code, rr.Body)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM engagements`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("incomplete scan persisted: %d, %v", count, err)
	}
}

func TestSourcePreviewBounds(t *testing.T) {
	root := t.TempDir()
	if _, err := readSourceFile(root); err == nil {
		t.Fatal("directory accepted as source")
	}
	path := filepath.Join(root, "oversized.go")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSourceBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readSourceFile(path); err == nil {
		t.Fatal("oversized source accepted")
	}
	if err := os.WriteFile(path, []byte("package fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readSourceFile(path)
	if err != nil || string(data) != "package fixture\n" {
		t.Fatalf("regular source: %q, %v", data, err)
	}
}
