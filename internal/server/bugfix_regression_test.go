package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

func TestFindingProductFilterAndMetricsLifecycle(t *testing.T) {
	s := setupTestServer(t)
	defer func() { _ = s.db.Close() }()
	for _, query := range []string{
		`INSERT INTO products (id,name) VALUES (1,'app'),(2,'other'),(3,'empty')`,
		`INSERT INTO engagements (id,product_id,name) VALUES (1,1,'scan'),(2,2,'scan')`,
		`INSERT INTO findings (id,engagement_id,product_id,rule_id,title,severity,status,stack,file_path) VALUES
   (1,1,1,'ENTR-02','active','HIGH','open','core','package.json'),
   (2,1,1,'ENTR-02','fixed','HIGH','fixed','core','fixed.json'),
   (3,1,1,'ENTR-02','closed','HIGH','closed','core','closed.json'),
   (4,1,1,'ENTR-02','false positive','HIGH','false_positive','core','fp.json'),
   (5,1,1,'ENTR-02','accepted','HIGH','accepted_risk','core','accepted.json'),
   (6,1,1,'ENTR-02','triage','HIGH','triage','core','triage.json'),
   (7,2,2,'ENTR-02','other','CRITICAL','open','core','other.json'),
   (8,1,1,'ENTR-02','legacy verified','HIGH','open','core','legacy.json')`,
		`UPDATE findings SET verification_status = 'fixed' WHERE id = 8`,
	} {
		if _, err := s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings?product_id=1", nil)
	addAuthCookie(req)
	s.ServeHTTP(rr, req)
	var data struct {
		Findings []models.Finding `json:"findings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || len(data.Findings) != 7 {
		t.Fatalf("product findings: %d %s", rr.Code, rr.Body)
	}
	for _, f := range data.Findings {
		if *f.ProductID != 1 {
			t.Fatalf("another product leaked: %+v", f)
		}
		if f.ID == 8 && f.Status != "resolved" {
			t.Fatalf("legacy verification not normalized: %+v", f)
		}
	}
	m, err := s.metricsRepo.GetProductMetrics(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalFindings != 7 || m.OpenFindings != 2 || m.ResolvedFindings != 3 || m.SecurityScore >= 100 {
		t.Fatalf("wrong product metrics: %+v", m)
	}
	global, err := s.metricsRepo.GetDashboardMetrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if global.OpenFindings != 3 || global.ResolvedFindings != 3 || global.SecurityScore >= 100 {
		t.Fatalf("wrong global metrics: %+v", global)
	}
	empty, err := s.metricsRepo.GetProductMetrics(context.Background(), 3)
	if err != nil || empty.TotalFindings != 0 || empty.SecurityScore != 100 {
		t.Fatalf("empty: %+v, %v", empty, err)
	}
	for _, url := range []string{"/api/findings?product_id=no", "/api/metrics?product_id=-1"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, url, nil)
		addAuthCookie(req)
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", url, rr.Code)
		}
	}
}

func TestReopenClearsStaleVerification(t *testing.T) {
	s := setupTestServer(t)
	defer func() { _ = s.db.Close() }()
	_, err := s.db.Exec(`INSERT INTO findings (id,engagement_id,rule_id,title,severity,status,stack,verification_status,resolved_at) VALUES (1,1,'ENTR-02','test','HIGH','resolved','core','fixed',CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.findingRepo.UpdateStatus(context.Background(), 1, "open"); err != nil {
		t.Fatal(err)
	}
	f, err := s.findingRepo.GetByID(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != "open" || f.VerificationStatus != nil || f.ResolvedAt != nil {
		t.Fatalf("stale resolved state: %+v", f)
	}
	if err := s.findingRepo.MarkVerificationError(context.Background(), 1, "open", "scanner unavailable"); err != nil {
		t.Fatal(err)
	}
	f, err = s.findingRepo.GetByID(context.Background(), 1)
	if err != nil || f.Status != "open" || *f.VerificationStatus != "error" {
		t.Fatalf("failed verification changed lifecycle: %+v %v", f, err)
	}
}

func TestVerificationRequiresCompletedRelevantScanner(t *testing.T) {
	for _, tc := range []struct {
		name, stack, scanner string
		status               external.ScannerStatus
		ok                   bool
	}{
		{"core success", "core", "aitriage", external.StatusCompleted, true},
		{"core failed", "core", "aitriage", external.StatusFailed, false},
		{"external missing", "semgrep", "semgrep", external.StatusMissing, false},
		{"external timeout", "bandit", "bandit", external.StatusTimedOut, false},
		{"other scanner cannot prove a fix", "semgrep", "aitriage", external.StatusCompleted, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rich := llm.RichScanResult{ScannerExecutions: []external.ScannerExecution{{Scanner: tc.scanner, Status: tc.status}}}
			if err := verificationScanError(context.Background(), &models.Finding{Stack: tc.stack}, &rich); (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestCoreScannerConfigPersistsAndRejectsInvalidSeverity(t *testing.T) {
	s := setupTestServer(t)
	defer func() { _ = s.db.Close() }()
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"min_severity":"HIGH","exclude_paths":["**/generated/**"]}`, 200},
		{`{"min_severity":"INVALID"}`, 400},
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/scanner-config/core", strings.NewReader(tc.body))
		addAuthCookie(req)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != tc.code {
			t.Fatalf("config: %d %s", rr.Code, rr.Body)
		}
	}
	cfg := s.loadCoreScannerConfig()
	if cfg.MinSeverity != "HIGH" || len(cfg.ExcludePaths) != 1 {
		t.Fatalf("not persisted: %+v", cfg)
	}
}

func TestFindingSourceDoesNotRequireAI(t *testing.T) {
	s := setupTestServer(t)
	defer func() { _ = s.db.Close() }()
	root := t.TempDir()
	file := filepath.Join(root, "app.go")
	if err := os.WriteFile(file, []byte("package app\nfunc sample() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.db.Exec(`INSERT INTO findings (id,engagement_id,rule_id,title,severity,status,stack,file_path,line_number) VALUES (1,1,'test','test','LOW','open','core',?,2)`, file)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/findings/1/source", nil)
	addAuthCookie(req)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	var body struct {
		Available bool   `json:"source_available"`
		Source    string `json:"source"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || !body.Available || !strings.Contains(body.Source, "func sample") {
		t.Fatalf("source: %d %s", rr.Code, rr.Body)
	}
}

func TestBulkVerificationUpdatesSelectedFindingsAndReportsMissingIDs(t *testing.T) {
	s := setupTestServer(t)
	defer func() { _ = s.db.Close() }()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("clean fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`INSERT INTO products (id,name) VALUES (1,'fixture')`,
		`INSERT INTO engagements (id,product_id,name,scan_path) VALUES (1,1,'scan',?)`,
		`INSERT INTO findings (id,engagement_id,product_id,rule_id,title,severity,status,stack) VALUES (1,1,1,'ENTR-02','missing lockfile','HIGH','open','core'),(2,1,1,'ENTR-02','missing lockfile','HIGH','open','core'),(3,1,1,'ENTR-02','not selected','HIGH','open','core')`,
	} {
		var err error
		if strings.Contains(query, "scan_path") {
			_, err = s.db.Exec(query, root)
		} else {
			_, err = s.db.Exec(query)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/findings/verify-bulk", strings.NewReader(`{"ids":[1,2,999]}`))
	addAuthCookie(req)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	var response struct {
		OK      bool                     `json:"ok"`
		Results []bulkVerificationResult `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || !response.OK || len(response.Results) != 3 || !response.Results[0].Fixed || !response.Results[1].Fixed || response.Results[2].Error == "" {
		t.Fatalf("bulk: %d %s", rr.Code, rr.Body)
	}
	for _, id := range []int64{1, 2, 3} {
		f, err := s.findingRepo.GetByID(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		expected := "resolved"
		if id == 3 {
			expected = "open"
		}
		if f.Status != expected {
			t.Fatalf("finding %d status %s want %s", id, f.Status, expected)
		}
	}
}
