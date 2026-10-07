package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardFreshnessUsesSuccessfulScopedRuns(t *testing.T) {
	s := setupTestServer(t)
	defer func() { _ = s.db.Close() }()
	for _, query := range []string{
		`INSERT INTO products (id,name) VALUES (1,'app'),(2,'other'),(3,'no timestamps')`,
		`INSERT INTO engagements (id,product_id,name,status,completed_at) VALUES
		 (1,1,'scan','completed','2026-10-07T15:00:00+05:00'),
		 (2,1,'new scan','completed','2026-10-07 11:00:00'),
		 (3,1,'failed','failed','2026-10-07T17:00:00Z'),
		 (4,1,'running','in_progress','2026-10-07T18:00:00Z'),
		 (5,2,'other','completed','2026-10-07T12:00:00Z'),
		 (6,3,'missing','completed',NULL),
		 (7,3,'invalid','completed','bad date')`,
		`INSERT INTO findings (id,engagement_id,product_id,rule_id,title,severity,stack,verification_status,verification_last_run_at) VALUES
		 (1,1,1,'test','fixed','HIGH','core','fixed','2026-10-07T15:00:00+05:00'),
		 (2,1,1,'test','present','HIGH','core','not_fixed','2026-10-07 11:00:00'),
		 (3,1,1,'test','error','HIGH','core','error','2026-10-07T18:00:00Z'),
		 (4,5,2,'test','other','HIGH','core','fixed','2026-10-07T12:00:00Z')`,
	} {
		if _, err := s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		product int64
		want    string
	}{{1, "2026-10-07T11:00:00Z"}, {2, "2026-10-07T12:00:00Z"}, {0, "2026-10-07T12:00:00Z"}, {3, ""}} {
		metrics, err := s.metricsRepo.GetProductMetrics(context.Background(), tc.product)
		if tc.product == 0 {
			metrics, err = s.metricsRepo.GetDashboardMetrics(context.Background())
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, timestamp := range []*string{metrics.LastSuccessfulScanAt, metrics.LastSuccessfulVerificationAt} {
			if tc.want == "" {
				if timestamp != nil {
					t.Fatalf("invented timestamp: %s", *timestamp)
				}
				continue
			}
			if timestamp == nil || *timestamp != tc.want {
				t.Fatalf("product %d: got %v, want %s", tc.product, timestamp, tc.want)
			}
		}
	}
	if err := s.findingRepo.MarkVerificationResult(context.Background(), 2, false, "present"); err != nil {
		t.Fatal(err)
	}
	before, err := s.metricsRepo.GetProductMetrics(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.findingRepo.MarkPendingVerification(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if err := s.findingRepo.MarkVerificationError(context.Background(), 2, "open", "scanner failed"); err != nil {
		t.Fatal(err)
	}
	if err := s.findingRepo.UpdateStatus(context.Background(), 2, "open"); err != nil {
		t.Fatal(err)
	}
	after, err := s.metricsRepo.GetProductMetrics(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastSuccessfulVerificationAt == nil || *after.LastSuccessfulVerificationAt != *before.LastSuccessfulVerificationAt {
		t.Fatal("unsuccessful attempt or reopening lost the successful verification timestamp")
	}
}

func TestVerificationFreshnessMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	oldSchema := strings.Replace(schema, "verification_last_run_at DATETIME,\n  verification_last_success_at DATETIME", "verification_last_run_at DATETIME", 1)
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO findings (id,engagement_id,rule_id,title,severity,stack,verification_status,verification_last_run_at) VALUES (1,1,'test','test','HIGH','core','fixed','2026-10-07 10:00:00'),(2,1,'test','test','HIGH','core','error','2026-10-07 11:00:00')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	for range 2 {
		db, err = InitDB(path)
		if err != nil {
			t.Fatal(err)
		}
		var successful string
		var failed sql.NullString
		if err := db.QueryRow("SELECT CAST(verification_last_success_at AS TEXT) FROM findings WHERE id=1").Scan(&successful); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow("SELECT CAST(verification_last_success_at AS TEXT) FROM findings WHERE id=2").Scan(&failed); err != nil {
			t.Fatal(err)
		}
		if successful != "2026-10-07 10:00:00" || failed.Valid {
			t.Fatalf("invalid backfill: %s %v", successful, failed)
		}
		_ = db.Close()
	}
}

func TestSourceAPIProvidesRedactedNumberedLines(t *testing.T) {
	s := setupTestServer(t)
	defer func() { _ = s.db.Close() }()
	root := t.TempDir()
	file := filepath.Join(root, "app.go")
	if err := os.WriteFile(file, []byte("package app\npassword = \"sensitive_value_here\"\nfunc sample() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO findings (id,engagement_id,rule_id,title,severity,stack,file_path,line_number) VALUES (1,1,'test','test','HIGH','core',?,2)`, file); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/findings/1/source", nil)
	addAuthCookie(req)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	var response struct {
		Available bool         `json:"source_available"`
		Lines     []sourceLine `json:"lines"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || !response.Available || len(response.Lines) != 4 || response.Lines[1].Number != 2 || !response.Lines[1].Highlight {
		t.Fatalf("numbered source: %s", rr.Body)
	}
	if strings.Contains(rr.Body.String(), "sensitive_value_here") || !strings.Contains(response.Lines[1].Text, "[REDACTED]") {
		t.Fatalf("unredacted source: %s", rr.Body)
	}
	excerpt := s.readFindingSourceExcerpt(root, "app.go", "app.go", 999, 4)
	for _, line := range excerpt.Lines {
		if line.Highlight {
			t.Fatal("invalid finding line was highlighted")
		}
	}
}
