package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
)

// baselineTestProject creates a project with one finding the built-in engine
// always reports, plus its aitriage-reports directory. External scanners are
// made unavailable so the tests stay fast and deterministic.
func baselineTestProject(t *testing.T) (root, reports string) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	root = t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("document.body.innerHTML = location.hash;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reports = filepath.Join(root, "aitriage-reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	return root, reports
}

// containerBaselineEnv reproduces the environment the Web container runs in.
func containerBaselineEnv(t *testing.T, reports string) {
	t.Helper()
	t.Setenv("AITRIAGE_RUNTIME", "container")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
}

// mountReadOnly makes the project root unwritable, as the container's
// read-only /workspace mount does, while the reports directory inside it stays
// writable. Permission bits do not restrict root or Windows, so there the
// assertions about where the file lands still hold but the failure mode of
// writing into the project is not reproduced.
func mountReadOnly(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

func callBaseline(t *testing.T, s *Server, method, target, body string) baselineStatusResponse {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s %s = %d: %s", method, target, rr.Code, rr.Body.String())
	}
	var resp baselineStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode %s %s: %v", method, target, err)
	}
	return resp
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent, stat err = %v", path, err)
	}
}

// In the container the project is mounted read-only, so the Web UI must keep
// the baseline it creates under the writable reports directory, and every
// reader must find it there.
func TestWebBaselineInContainerIsWrittenUnderReports(t *testing.T) {
	root, reports := baselineTestProject(t)
	containerBaselineEnv(t, reports)
	mountReadOnly(t, root)
	s := setupTestServer(t)
	s.hostPrefix = root

	created := callBaseline(t, s, http.MethodPost, "/api/baseline", `{}`)
	want := filepath.Join(reports, webBaselinesDir, baseline.BaselineFile)
	if !created.Exists || created.Total == 0 || created.Path != want || created.ReadOnly {
		t.Fatalf("create response = %+v, want an existing, writable baseline at %s", created, want)
	}
	mustExist(t, want)
	mustNotExist(t, filepath.Join(root, baseline.BaselineFile))

	status := callBaseline(t, s, http.MethodGet, "/api/baseline", "")
	if !status.Exists || status.Path != want || status.Total != created.Total || status.ReadOnly {
		t.Fatalf("status after create = %+v, want the copy under reports", status)
	}
	// A scan of the same folder applies the same file.
	if got := s.effectiveBaselineDir(root); got != filepath.Dir(want) {
		t.Fatalf("scan reads the baseline from %s, want %s", got, filepath.Dir(want))
	}
}

// A baseline that ships with the project (committed, or written by
// `aitriage baseline`) keeps applying in the container. Updating it writes a
// copy that takes precedence; clearing removes only that copy and reports the
// project's file, which the Web UI cannot change.
func TestWebBaselineInContainerHonoursTheProjectFile(t *testing.T) {
	root, reports := baselineTestProject(t)
	containerBaselineEnv(t, reports)

	committed := baseline.NewFromItems(nil)
	committed.CreatedAt = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := baseline.Save(root, committed); err != nil {
		t.Fatal(err)
	}
	projectFile := filepath.Join(root, baseline.BaselineFile)
	original, err := os.ReadFile(projectFile)
	if err != nil {
		t.Fatal(err)
	}
	mountReadOnly(t, root)
	s := setupTestServer(t)
	s.hostPrefix = root

	status := callBaseline(t, s, http.MethodGet, "/api/baseline", "")
	if !status.Exists || status.Path != projectFile || !status.ReadOnly {
		t.Fatalf("status = %+v, want the project's own read-only baseline", status)
	}
	if got := s.effectiveBaselineDir(root); got != root {
		t.Fatalf("scan reads the baseline from %s, want the project %s", got, root)
	}

	copyFile := filepath.Join(reports, webBaselinesDir, baseline.BaselineFile)
	updated := callBaseline(t, s, http.MethodPost, "/api/baseline", `{"path":"."}`)
	if updated.Path != copyFile || updated.ReadOnly || updated.Total == 0 {
		t.Fatalf("update response = %+v, want a populated copy at %s", updated, copyFile)
	}
	if updated.CreatedAt != "2025-01-02T03:04:05Z" {
		t.Fatalf("update created_at = %q, want the project baseline's creation date", updated.CreatedAt)
	}
	if got := s.effectiveBaselineDir(root); got != filepath.Dir(copyFile) {
		t.Fatalf("after update the scan reads %s, want the copy in %s", got, filepath.Dir(copyFile))
	}

	cleared := callBaseline(t, s, http.MethodDelete, "/api/baseline", "")
	if !cleared.Exists || !cleared.ReadOnly || cleared.Path != projectFile {
		t.Fatalf("clear response = %+v, want the project's baseline reported as still applying", cleared)
	}
	mustNotExist(t, copyFile)
	after, err := os.ReadFile(projectFile)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("the project's baseline file changed (err=%v)", err)
	}
}

// Folders of one project are baselined independently, so their copies must not
// share a file.
func TestWebBaselineInContainerMirrorsTheScannedFolder(t *testing.T) {
	root, reports := baselineTestProject(t)
	containerBaselineEnv(t, reports)
	nested := filepath.Join(root, "services", "api")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "index.js"), []byte("el.innerHTML = input;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mountReadOnly(t, root)
	s := setupTestServer(t)
	s.hostPrefix = root

	created := callBaseline(t, s, http.MethodPost, "/api/baseline", `{"path":"services/api"}`)
	want := filepath.Join(reports, webBaselinesDir, "services", "api", baseline.BaselineFile)
	if created.Path != want {
		t.Fatalf("nested baseline written to %s, want %s", created.Path, want)
	}
	mustExist(t, want)
	mustNotExist(t, filepath.Join(reports, webBaselinesDir, baseline.BaselineFile))
	mustNotExist(t, filepath.Join(nested, baseline.BaselineFile))

	root2 := callBaseline(t, s, http.MethodGet, "/api/baseline", "")
	if root2.Exists {
		t.Fatalf("the project root reports a baseline it never had: %+v", root2)
	}
}

// Natively the project is writable and the Web UI keeps sharing the project
// file with the CLI and the IDE tools.
func TestWebBaselineNativeWritesTheProjectFile(t *testing.T) {
	root, reports := baselineTestProject(t)
	t.Setenv("AITRIAGE_RUNTIME", "")
	t.Setenv("AITRIAGE_REPORTS_DIR", reports)
	s := setupTestServer(t)
	s.hostPrefix = root

	created := callBaseline(t, s, http.MethodPost, "/api/baseline", `{}`)
	want := filepath.Join(root, baseline.BaselineFile)
	if created.Path != want || created.ReadOnly {
		t.Fatalf("native baseline response = %+v, want the project file %s", created, want)
	}
	mustExist(t, want)
	mustNotExist(t, filepath.Join(reports, webBaselinesDir))

	cleared := callBaseline(t, s, http.MethodDelete, "/api/baseline", "")
	if cleared.Exists || cleared.Path != want {
		t.Fatalf("native clear response = %+v", cleared)
	}
	mustNotExist(t, want)
}

// The scan request's use_baseline flag, which the Web UI sends, hides exactly
// the accepted findings and says how many it hid.
func TestWebScanUseBaselineHidesAcceptedFindings(t *testing.T) {
	root, _ := baselineTestProject(t)
	t.Setenv("AITRIAGE_RUNTIME", "")
	t.Setenv("AITRIAGE_REPORTS_DIR", "")
	s := setupTestServer(t)
	s.hostPrefix = root

	scan := func(useBaseline bool) scanResponse {
		t.Helper()
		body, err := json.Marshal(map[string]any{"path": ".", "use_baseline": useBaseline})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("scan = %d: %s", rr.Code, rr.Body.String())
		}
		var resp scanResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	reports := func(resp scanResponse, rule string) bool {
		for _, f := range resp.Findings {
			if f.ID == rule {
				return true
			}
		}
		return false
	}

	before := scan(false)
	if !reports(before, "ENTR-INNERHTML") {
		t.Fatalf("fixture finding missing before the baseline: %+v", before.Findings)
	}

	callBaseline(t, s, http.MethodPost, "/api/baseline", `{}`)

	ignored := scan(false)
	if !reports(ignored, "ENTR-INNERHTML") || ignored.BaselinedFindings != 0 {
		t.Fatalf("without use_baseline the scan must report everything: baselined=%d", ignored.BaselinedFindings)
	}
	applied := scan(true)
	if reports(applied, "ENTR-INNERHTML") {
		t.Fatal("use_baseline left an accepted finding in the result")
	}
	if applied.BaselinedFindings == 0 {
		t.Fatal("use_baseline hid findings without counting them")
	}
}
