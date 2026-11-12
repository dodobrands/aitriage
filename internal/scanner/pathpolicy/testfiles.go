package pathpolicy

import (
	"path/filepath"
	"strings"
)

// IsTestLike reports whether path names test, mock, fixture, or spec code.
// Matching is deliberately structural: a substring check would incorrectly
// classify production files such as contest.go or latest.py as tests and could
// hide real findings.
func IsTestLike(path string) bool {
	portable := strings.ReplaceAll(path, `\`, "/")
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(portable)))
	parts := strings.Split(clean, "/")
	for _, part := range parts {
		switch part {
		case "test", "tests", "testdata", "__tests__",
			"mock", "mocks", "__mocks__", "fixture", "fixtures", "__fixtures__",
			"spec", "specs", "__specs__":
			return true
		}
	}

	base := filepath.Base(clean)
	// conftest.py holds pytest fixtures; tests.py is Django's per-app test
	// module (startapp creates it next to models.py and views.py).
	if base == "conftest.py" || base == "tests.py" {
		return true
	}
	for _, marker := range []string{".test.", ".spec.", ".mock."} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	return strings.HasPrefix(stem, "test_") || strings.HasSuffix(stem, "_test") ||
		strings.HasPrefix(stem, "mock_") || strings.HasSuffix(stem, "_mock") ||
		strings.HasPrefix(stem, "spec_") || strings.HasSuffix(stem, "_spec")
}
