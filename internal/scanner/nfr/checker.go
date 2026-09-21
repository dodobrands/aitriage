package nfr

import (
	"context"
	"embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yaml
var rulesFS embed.FS

var (
	cachedRules   []Rule
	loadRulesOnce sync.Once
	loadRulesErr  error
)

type Rule struct {
	ID                     string   `yaml:"id"`
	Name                   string   `yaml:"name"`
	Severity               string   `yaml:"severity"`
	Message                string   `yaml:"message"`
	Advice                 string   `yaml:"advice"`
	Check                  string   `yaml:"check"`   // "file_contains" | "file_exists" | "file_not_exists" | "file_tracked_by_git"
	Pattern                string   `yaml:"pattern"` // regex for file_contains
	Files                  []string `yaml:"files"`   // basename globs to inspect recursively
	AppliesPattern         string   `yaml:"applies_pattern"`
	AppliesFiles           []string `yaml:"applies_files"`
	compiledRegex          *regexp.Regexp
	compiledAppliesPattern *regexp.Regexp
}

func getRules() ([]Rule, error) {
	loadRulesOnce.Do(func() {
		entries, err := rulesFS.ReadDir("rules")
		if err != nil {
			loadRulesErr = fmt.Errorf("cannot read embedded NFR rules: %w", err)
			return
		}

		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml") {
				continue
			}
			data, err := rulesFS.ReadFile("rules/" + e.Name())
			if err != nil {
				continue
			}
			var rules []Rule
			if err := yaml.Unmarshal(data, &rules); err != nil {
				continue
			}

			// Precompile regular expressions
			for i := range rules {
				if rules[i].Check == "file_contains" {
					re, err := regexp.Compile(rules[i].Pattern)
					if err == nil {
						rules[i].compiledRegex = re
					}
				}
				if rules[i].AppliesPattern != "" {
					re, err := regexp.Compile(rules[i].AppliesPattern)
					if err == nil {
						rules[i].compiledAppliesPattern = re
					}
				}
			}

			cachedRules = append(cachedRules, rules...)
		}
	})
	return cachedRules, loadRulesErr
}

type NFRFinding struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Advice   string `json:"advice"`
}

// CheckNFR checks the project against built-in NFR rules
func CheckNFR(projectPath string) ([]NFRFinding, error) {
	allRules, err := getRules()
	if err != nil {
		return nil, err
	}

	var findings []NFRFinding
	for _, rule := range allRules {
		triggered, err := evaluateRule(projectPath, rule)
		if err != nil {
			continue
		}
		if triggered {
			findings = append(findings, NFRFinding{
				RuleID:   rule.ID,
				Name:     rule.Name,
				Severity: rule.Severity,
				Message:  rule.Message,
				Advice:   rule.Advice,
			})
		}
	}

	return findings, nil
}

func evaluateRule(projectPath string, rule Rule) (bool, error) {
	applies, err := ruleApplies(projectPath, rule)
	if err != nil || !applies {
		return false, err
	}
	switch rule.Check {
	case "file_contains":
		var re *regexp.Regexp
		if rule.compiledRegex != nil {
			re = rule.compiledRegex
		} else {
			var err error
			re, err = regexp.Compile(rule.Pattern)
			if err != nil {
				return false, err
			}
		}

		matches, err := matchingFiles(projectPath, rule.Files)
		if err != nil {
			return false, err
		}
		if len(matches) == 0 {
			return false, nil
		}
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if re.Match(data) {
				return false, nil
			}
		}
		return true, nil // NFR violated if pattern is NOT found
	case "file_exists":
		_, err := os.Stat(filepath.Join(projectPath, rule.Pattern))
		return os.IsNotExist(err), nil // violated if file does NOT exist
	case "file_not_exists":
		_, err := os.Stat(filepath.Join(projectPath, rule.Pattern))
		return err == nil, nil // violated if file EXISTS
	case "file_tracked_by_git":
		// Violated only when the file is actually exposed: either git tracks it,
		// or it sits in the tree with nothing ignoring it. A developer's local
		// .env that .gitignore covers is correct practice, not a critical leak.
		return fileIsExposedToGit(projectPath, rule.Pattern), nil
	default:
		return false, nil
	}
}

func ruleApplies(projectPath string, rule Rule) (bool, error) {
	if rule.AppliesPattern == "" {
		return true, nil
	}
	re := rule.compiledAppliesPattern
	if re == nil {
		var err error
		re, err = regexp.Compile(rule.AppliesPattern)
		if err != nil {
			return false, err
		}
	}
	files := rule.AppliesFiles
	if len(files) == 0 {
		files = rule.Files
	}
	matches, err := matchingFiles(projectPath, files)
	if err != nil {
		return false, err
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err == nil && re.Match(data) {
			return true, nil
		}
	}
	return false, nil
}

func matchingFiles(projectPath string, globs []string) ([]string, error) {
	var matches []string
	err := filepath.WalkDir(projectPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".aitriage", "aitriage-reports", "node_modules", "vendor", "dist", "build", ".next":
				if path != projectPath {
					return filepath.SkipDir
				}
			}
			return nil
		}
		for _, glob := range globs {
			if ok, matchErr := filepath.Match(glob, entry.Name()); matchErr == nil && ok {
				matches = append(matches, path)
				break
			}
		}
		return nil
	})
	return matches, err
}

// GetAllRulesAsText returns all NFR rules serialized as text for LLM consumption
func GetAllRulesAsText() string {
	allRules, err := getRules()
	if err != nil {
		return ""
	}

	var builder strings.Builder
	for _, r := range allRules {
		builder.WriteString(fmt.Sprintf("- [%s] %s (%s)\n  Advice: %s\n", r.ID, r.Name, r.Severity, r.Advice))
	}
	return builder.String()
}

// fileIsExposedToGit reports whether a sensitive file would reach the
// repository. It asks git itself, because only git knows what is tracked; when
// the project is not a git repository at all, the presence of the file is the
// only signal available and is reported as exposure.
func fileIsExposedToGit(projectPath, name string) bool {
	if _, err := os.Stat(filepath.Join(projectPath, name)); err != nil {
		return false // nothing to expose
	}

	if _, err := os.Stat(filepath.Join(projectPath, ".git")); err != nil {
		return true // not a repository: cannot prove the file is ignored
	}

	// Tracked by git: the file is in the repository right now.
	if runGitQuiet(projectPath, "ls-files", "--error-unmatch", "--", name) == nil {
		return true
	}

	// Untracked but ignored: correctly excluded, nothing to report.
	if runGitQuiet(projectPath, "check-ignore", "-q", "--", name) == nil {
		return false
	}

	// Untracked and not ignored: one `git add .` away from being committed.
	return true
}

// runGitQuiet runs a git query in the project and reports only success.
func runGitQuiet(projectPath string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = projectPath
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
