package baseline

import "testing"

func TestStripRootFromTextSlashForm(t *testing.T) {
	cases := map[string]string{
		"Rule X found issue in /github/workspace/src/main.py":   "Rule X found issue in src/main.py",
		"scanned /github/workspace, 3 files":                    "scanned ., 3 files",
		"see /github/workspace/a.py and /github/workspace/b.py": "see a.py and b.py",
		"other repo /github/workspace-old/main.py stays":        "other repo /github/workspace-old/main.py stays",
		"nothing to strip": "nothing to strip",
	}
	for in, want := range cases {
		if got := StripRootFromText("/github/workspace", in); got != want {
			t.Errorf("StripRootFromText(%q) = %q, want %q", in, got, want)
		}
	}
}

// Windows messages carry the root with backslashes. The native form is only
// produced on Windows, so the form-level function is exercised directly here;
// the Windows CI job runs the end-to-end artifact tests as well.
func TestStripRootFormNativeWindowsSeparators(t *testing.T) {
	root := `D:\a\_temp\repo`
	cases := map[string]string{
		`Rule FAST-SUBPROCESS found issue in D:\a\_temp\repo\src\main.py`: "Rule FAST-SUBPROCESS found issue in src/main.py",
		`project D:\a\_temp\repo: done`:                                   "project .: done",
		`sibling D:\a\_temp\repo2\main.py stays`:                          `sibling D:\a\_temp\repo2\main.py stays`,
	}
	for in, want := range cases {
		if got := stripRootForm(in, root, `\`); got != want {
			t.Errorf("stripRootForm(%q) = %q, want %q", in, got, want)
		}
	}
}
