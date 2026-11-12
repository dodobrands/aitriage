package scanner

import (
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
)

// WithRelativePaths returns a copy of the report for output: every finding
// path is relative to the project root with forward slashes, and the project
// root is removed from evidence text ("Rule X found issue in
// /github/workspace/main.py"). The engine works with absolute paths, which
// leaked the checkout location (in CI, /github/workspace) into JSON, SARIF and
// terminal output. A path outside the root is kept as it is.
func (r ScanReport) WithRelativePaths() ScanReport {
	out := r
	if len(r.Results) == 0 {
		return out
	}
	root := ""
	if strings.TrimSpace(r.ProjectPath) != "" {
		if abs, err := filepath.Abs(r.ProjectPath); err == nil {
			root = strings.TrimSuffix(filepath.ToSlash(abs), "/")
		}
	}
	out.Results = make([]core.CheckResult, len(r.Results))
	for i, res := range r.Results {
		res.File = baseline.RelativePath(r.ProjectPath, res.File)
		if root != "" {
			res.Evidence = strings.ReplaceAll(res.Evidence, root+"/", "")
		}
		out.Results[i] = res
	}
	return out
}
