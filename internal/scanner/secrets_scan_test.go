package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanDetectsHardcodedSecrets is an end-to-end check that a deterministic
// scan of a project containing hardcoded secrets surfaces CRITICAL/HIGH secret
// findings (so the CI/pre-commit gate blocks).
func TestScanDetectsHardcodedSecrets(t *testing.T) {
	dir := t.TempDir()
	src := strings.Join([]string{
		`const AWS = "AKIA` + `Z7Q4XWVB3NMK2PLT";`,
		`const GH  = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";`,
		`const DB  = "postgres://admin:S3cretDbPass@db.internal:5432/app";`,
		`const OAI = "sk-Xq7Lm2Np9Rt4Vw8Yz1Ab` + `T3BlbkFJCd5Ef6Gh7Ij8Kl9Mn0Op";`,
		`const apiKey = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";`,
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "config.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Scan(context.Background(), dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var secretHits int
	var allIDs []string
	for _, r := range report.Results {
		allIDs = append(allIDs, r.ID)
		if strings.HasPrefix(r.ID, "SECRET") {
			secretHits++
			if r.Severity != "CRITICAL" && r.Severity != "HIGH" {
				t.Errorf("secret finding %s has non-blocking severity %q", r.ID, r.Severity)
			}
		}
	}
	if secretHits < 5 {
		t.Fatalf("expected >=5 secret findings, got %d\nall result IDs: %s", secretHits, strings.Join(allIDs, ", "))
	}
}

// TestScanRelativePathDetectsSecrets is a regression test for the bug where
// `aitriage scan .` (the form used by the pre-commit hook and CI) ran only
// project-level checks and silently skipped per-file secret detection because
// the workspace root was a relative path.
func TestScanRelativePathDetectsSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.js"),
		[]byte(`const k = "AKIA`+`Z7Q4XWVB3NMK2PLT";`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir) // scan with a relative "." root

	for _, root := range []string{".", "./"} {
		report, err := Scan(context.Background(), root, ScanOptions{})
		if err != nil {
			t.Fatalf("scan %q: %v", root, err)
		}
		found := false
		for _, r := range report.Results {
			if strings.HasPrefix(r.ID, "SECRET") {
				found = true
			}
		}
		if !found {
			t.Errorf("scan %q did not detect the hardcoded secret", root)
		}
	}
}
