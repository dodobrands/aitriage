package healthcheck

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ── Canonical finding classes ────────────────────────────────────────────────
//
// Several scanners routinely report one defect. A hardcoded secret on one line
// came back as SECRET-ASSIGN, Bandit B105, Gitleaks generic-api-key and Semgrep
// detected-generic-secret: four confirmed findings, four penalties, four rows in
// the summary, for a single line of code. A canonical class names the defect
// independently of the detector, so the triage graph can merge such reports
// into one finding and the score and the gate count it once.
//
// Two rules keep merging honest:
//   - Only findings of the same class merge. SQL injection and XSS reported on
//     the same line stay two findings.
//   - A rule no class lists keeps its own identity and never merges with
//     anything; adding a rule here is a deliberate decision.

// ClassScope says which locations of one class describe the same defect.
type ClassScope int

const (
	// ScopeLine: one defect per file and line (the default).
	ScopeLine ClassScope = iota
	// ScopeFile: one defect per file, whichever line a detector points at.
	// A Dockerfile without USER runs its container as root no matter whether
	// a scanner reports the missing instruction at CMD, at FROM or nowhere.
	ScopeFile
	// ScopeRule: one defect per rule (and package). Advisories never merge
	// with each other: fifty CVEs in one manifest are fifty findings.
	ScopeRule
)

// FindingClass describes one canonical defect class.
type FindingClass struct {
	// Key is the stable snake_case name, e.g. "hardcoded_secret".
	Key string
	// Code is the short class code used in display ids (CS-<CODE>-...).
	Code string
	// Scope decides which locations merge.
	Scope ClassScope
	// Severity, when set, is the severity of a merged finding of this class
	// whatever its detectors reported. Empty means the highest reported one.
	Severity string
}

// Class keys referenced outside this table.
const (
	ClassHardcodedSecret      = "hardcoded_secret"
	ClassCommandInjection     = "command_injection"
	ClassExceptionSwallow     = "exception_swallow"
	ClassContainerRunsAsRoot  = "container_runs_as_root"
	ClassVulnerableDependency = "vulnerable_dependency"
)

var findingClasses = map[string]FindingClass{}

func init() {
	for _, c := range []FindingClass{
		{Key: ClassHardcodedSecret, Code: "SECRETS"},
		{Key: ClassCommandInjection, Code: "CMDI"},
		{Key: "code_eval", Code: "EVAL"},
		{Key: "sql_injection", Code: "SQLI"},
		{Key: "nosql_injection", Code: "NOSQLI"},
		{Key: "xss", Code: "XSS"},
		{Key: "path_traversal", Code: "PATH"},
		{Key: "ssrf", Code: "SSRF"},
		{Key: "open_redirect", Code: "REDIR"},
		{Key: "template_injection", Code: "SSTI"},
		{Key: "insecure_deserialization", Code: "DESER"},
		{Key: "xxe", Code: "XXE"},
		{Key: "weak_hash", Code: "CRYPTO"},
		{Key: "insecure_randomness", Code: "RAND"},
		{Key: "tls_verification_disabled", Code: "TLS"},
		{Key: "weak_tls", Code: "TLS"},
		{Key: "debug_mode", Code: "DEBUG"},
		{Key: "bind_all_interfaces", Code: "BIND"},
		{Key: "insecure_temp_file", Code: "TEMP"},
		{Key: "assert_as_guard", Code: "ASSERT"},
		// A swallowed exception is a reliability problem (CWE-703), not an
		// exploitable vulnerability; Bandit rates B110 LOW as well. Merging it
		// with a detector that says HIGH must not promote it.
		{Key: ClassExceptionSwallow, Code: "ERROR", Severity: SeverityLow},
		{Key: "sensitive_data_in_logs", Code: "LOG"},
		{Key: "jwt_unverified_signature", Code: "JWT"},
		{Key: "prototype_pollution", Code: "PROTO"},
		{Key: "insecure_cookie", Code: "COOKIE"},
		{Key: "permissive_cors", Code: "CORS"},
		{Key: "missing_cors_policy", Code: "CORS"},
		{Key: "missing_authentication", Code: "AUTH"},
		{Key: "missing_authorization", Code: "AUTHZ"},
		{Key: "missing_rate_limiting", Code: "RATELIMIT"},
		{Key: "missing_csrf_protection", Code: "CSRF"},
		{Key: "missing_security_headers", Code: "HEADERS"},
		{Key: "privileged_container", Code: "PRIV"},
		{Key: ClassContainerRunsAsRoot, Code: "ROOT", Scope: ScopeFile},
		{Key: "image_latest_tag", Code: "CONFIG"},
		{Key: "dockerfile_add_instruction", Code: "CONFIG"},
		{Key: ClassVulnerableDependency, Code: "DEP", Scope: ScopeRule},
	} {
		findingClasses[c.Key] = c
	}
	for class, ids := range classRules {
		if _, ok := findingClasses[class]; !ok {
			panic(fmt.Sprintf("healthcheck: rule table names unknown class %q", class))
		}
		for _, id := range ids {
			ruleClasses[strings.ToUpper(id)] = class
		}
	}
	for _, p := range semgrepClassPatterns {
		if _, ok := findingClasses[p.class]; !ok {
			panic(fmt.Sprintf("healthcheck: semgrep pattern names unknown class %q", p.class))
		}
	}
	for _, class := range trivyCheckClasses {
		if _, ok := findingClasses[class]; !ok {
			panic(fmt.Sprintf("healthcheck: trivy table names unknown class %q", class))
		}
	}
}

// classRules lists, per class, the rule ids of the built-in engine, NFR and
// deploy checks, and Bandit tests. Ids are matched case-insensitively.
var classRules = map[string][]string{
	ClassHardcodedSecret: {
		// Every SECRET-* heuristic of the built-in engine is matched by prefix
		// in ClassifyRule.
		"ENTROPY-SECRET", "ENTROPY-SECRET-LEAK", "ENTR-17", "ENTR-19", "ENTR-PRIVATE-KEY",
		"ASP-CONN-STRING", "ASP-HARDCODED-CREDS", "DJANGO-SECRET", "FAST-HARDCODED-SECRET",
		"FLASK-SECRET-HARDCODED", "GO-HARDCODED-CREDS", "JWT-HARDCODED", "DOCKER-SECRET-ENV",
		"DOCKER-SECRET-ARG", "LLM-API-KEY-EXPOSED",
		"B105", "B106", "B107",
		"dockerfile_hardcoded_secret", "compose_hardcoded_secret", "makefile_hardcoded_secret",
	},
	ClassCommandInjection: {
		"FAST-SUBPROCESS", "PY-SUBPROCESS", "EXPRESS-CHILD-PROC", "GO-CMD-INJECTION", "JS-COMMAND-INJECTION",
		"B602", "B603", "B604", "B605",
	},
	"code_eval": {
		"FAST-EVAL", "PY-EXEC", "PY-COMPILE-EXEC", "EXPRESS-EVAL", "ENTR-EVAL-FUNC", "LLM-OUTPUT-EXEC",
		"B102", "B307",
	},
	"sql_injection": {
		"ASP-SQLI", "DJANGO-RAW-SQL", "DJANGO-SQLI-EXTRA", "EXPRESS-SQLI", "FAST-SQLI", "FLASK-RAW-SQL",
		"GO-SQLI", "GO-SQL-SPRINTF", "NEXT-SQLI", "LLM-OUTPUT-SQL",
		"B608", "B610", "B611",
	},
	"nosql_injection": {"EXPRESS-NOSQL", "NEXT-NOSQL", "ENTR-NOSQL-INJECTION"},
	"xss": {
		"FAST-XSS", "EXPRESS-XSS", "REACT-XSS", "NEXT-UNSAFE-HREF", "ENTR-INNERHTML",
		"DJANGO-MARK-SAFE", "DJANGO-SAFE-FILTER",
		"B308", "B703", "B704",
	},
	"path_traversal": {
		"ASP-PATH-TRAVERSAL", "FAST-PATH-TRAVERSAL", "GO-PATH-TRAVERSAL", "JS-PATH-TRAVERSAL",
		"FLASK-SEND-FILE", "PY-TARFILE", "B202",
	},
	"ssrf":               {"EXPRESS-SSRF", "FAST-SSRF", "GO-SSRF", "NEXT-SSRF", "ENTR-SSRF"},
	"open_redirect":      {"EXPRESS-OPEN-REDIRECT", "FAST-OPEN-REDIRECT", "FLASK-OPEN-REDIRECT", "ENTR-OPEN-REDIRECT"},
	"template_injection": {"FAST-SSTI", "FLASK-SSTI"},
	"insecure_deserialization": {
		"ASP-DESER", "FAST-PICKLE", "FLASK-PICKLE", "PY-PICKLE", "FAST-YAML", "PY-YAML-LOAD",
		"B301", "B302", "B506",
	},
	"xxe":                       {"ASP-XXE", "B313", "B314", "B315", "B316", "B317", "B318", "B319", "B320"},
	"weak_hash":                 {"PY-HASHLIB-WEAK", "ENTR-21", "ENTR-WEAK-CRYPTO", "B303", "B324"},
	"insecure_randomness":       {"GO-MATH-RAND", "NEXT-MATH-RANDOM", "ENTR-INSECURE-RANDOM", "B311"},
	"tls_verification_disabled": {"PY-REQUESTS-NOVERIFY", "GO-TLS-SKIP", "B501", "B323"},
	"weak_tls":                  {"GO-WEAK-TLS", "B502", "B503", "B504"},
	"debug_mode":                {"FLASK-DEBUG", "DJANGO-DEBUG", "B201"},
	"bind_all_interfaces":       {"PY-BINDING-ALL", "B104"},
	"insecure_temp_file":        {"FAST-TEMPFILE", "PY-TEMPFILE", "B306"},
	"assert_as_guard":           {"PY-ASSERT-GUARD", "B101"},
	ClassExceptionSwallow:       {"FAST-LAZY-EXC", "B110", "B112"},
	"sensitive_data_in_logs":    {"ASP-LOGGING-SENSITIVE", "PY-LOGGING-SENSITIVE", "ENTR-SENSITIVE-LOG"},
	"jwt_unverified_signature":  {"ENTR-03", "ENTR-JWT-NONE"},
	"prototype_pollution":       {"ENTR-PROTO-POLLUTION"},
	"insecure_cookie": {
		"DJANGO-SESSION-SECURE", "DJANGO-CSRF-COOKIE", "EXPRESS-SESSION-INSECURE", "FLASK-UNSAFE-COOKIE",
		"ENTR-INSECURE-COOKIE",
	},
	"permissive_cors":     {"ASP-INSECURE-CORS", "FAST-CORS-WILDCARD", "ENTR-CORS-WILDCARD"},
	"missing_cors_policy": {"FAST-CORS", "NFR-API-002", "EXPRESS-CORS", "NEXT-CORS"},
	"missing_authentication": {
		"FAST-AUTH", "NFR-API-003", "EXPRESS-AUTH", "FLASK-AUTH", "DJANGO-AUTH", "NEXT-AUTH",
		"ASP-AUTH-MISSING", "NEXT-SERVER-ACTION-EXPOSED",
	},
	"missing_authorization":    {"FAST-AUTHZ", "NEXT-AUTHZ"},
	"missing_rate_limiting":    {"FAST-RATELIMIT", "NFR-API-001", "EXPRESS-RATELIMIT", "FLASK-RATELIMIT", "NEXT-RATELIMIT"},
	"missing_csrf_protection":  {"FAST-CSRF", "FLASK-CSRF", "NEXT-CSRF", "DJANGO-CSRF-EXEMPT", "ASP-ANTIFORGERY"},
	"missing_security_headers": {"FLASK-HEADERS", "NEXT-HEADERS", "EXPRESS-HELMET", "DJANGO-MIDDLEWARE"},
	"privileged_container":     {"DOCKER-PRIVILEGED", "compose_privileged_mode", "k8s_privileged_container"},
	ClassContainerRunsAsRoot:   {"DOCKER-NO-USER", "dockerfile_root_user", "k8s_run_as_root"},
	"image_latest_tag":         {"DOCKER-LATEST"},
	"dockerfile_add_instruction": {
		"DOCKER-ADD", "dockerfile_add_instead_of_copy",
	},
}

// ruleClasses maps an upper-cased rule id to its class key.
var ruleClasses = map[string]string{}

// trivyCheckClasses maps normalized Trivy misconfiguration ids (see
// normalizeTrivyCheckID) to classes.
var trivyCheckClasses = map[string]string{
	"DS-0001":  "image_latest_tag",
	"DS-0002":  ClassContainerRunsAsRoot,
	"DS-0005":  "dockerfile_add_instruction",
	"KSV-0012": ClassContainerRunsAsRoot,
	"KSV-0017": "privileged_container",
}

// semgrepClassPatterns classify Semgrep registry rules by fragments of their
// check id (for example python.lang.security.audit.subprocess-shell-true).
// The first matching entry wins, so the more specific classes come first.
var semgrepClassPatterns = []struct {
	class     string
	fragments []string
}{
	{ClassHardcodedSecret, []string{".secrets.", ".detected-", "hardcoded-secret", "hardcoded-password", "hardcoded-credential", "hardcoded-token", "hardcoded-key", "hardcoded-api-key"}},
	{ClassContainerRunsAsRoot, []string{"missing-user", "last-user-is-root"}},
	{ClassCommandInjection, []string{"subprocess", "shell-true", "system-call", "child-process", "exec-command", "exec-cmd", "command-injection", "spawn-shell", "os-system", "shell-injection"}},
	{"code_eval", []string{"eval", "exec-detected", "exec-use", "code-injection", "user-exec"}},
	{"nosql_injection", []string{"nosql"}},
	{"sql_injection", []string{"sql"}},
	{"template_injection", []string{"ssti", "template-injection", "render-template-string"}},
	{"xss", []string{"xss", "innerhtml", "mark-safe", "raw-html", "html-safe", "unescaped"}},
	{"path_traversal", []string{"path-traversal", "tainted-path", "path-join", "zip-slip", "zipslip", "tarfile", "directory-traversal"}},
	{"ssrf", []string{"ssrf"}},
	{"open_redirect", []string{"open-redirect", "unvalidated-redirect"}},
	{"insecure_deserialization", []string{"pickle", "deserializ", "marshal", "yaml-load", "pyyaml", "unsafe-yaml", "shelve"}},
	{"xxe", []string{"xxe", "xml-external", "external-entit"}},
	{"weak_hash", []string{"md5", "sha1", "insecure-hash", "weak-hash"}},
	{"insecure_randomness", []string{"insecure-random", "math-random", "weak-random", "pseudo-random"}},
	{"tls_verification_disabled", []string{"verify-false", "disabled-cert", "cert-validation", "insecure-skip-verify", "unverified-ssl", "unverified-context", "ssl-verify", "tls-verify"}},
	{"weak_tls", []string{"weak-tls", "ssl-version", "tls-version", "sslv2", "sslv3"}},
	{"debug_mode", []string{"debug-enabled", "debug-true", "debug-mode", "flask-debug"}},
	{"jwt_unverified_signature", []string{"jwt-none", "none-alg", "unverified-jwt", "jwt-decode-without-verify", "jwt-not-verified", "jwt-unverified"}},
	{"missing_csrf_protection", []string{"csrf"}},
	{"permissive_cors", []string{"cors"}},
	{"bind_all_interfaces", []string{"all-interfaces", "bind-all"}},
	{"insecure_temp_file", []string{"mktemp", "tempfile-insecure", "insecure-temp"}},
	{"prototype_pollution", []string{"prototype-pollution"}},
	{"sensitive_data_in_logs", []string{"sensitive-log", "logging-sensitive", "log-sensitive", "logger-credential"}},
	{"insecure_cookie", []string{"cookie"}},
	{"privileged_container", []string{"privileged"}},
	{"image_latest_tag", []string{"latest-tag", "latest-version"}},
	{"dockerfile_add_instruction", []string{"copy-over-add", "instead-of-add"}},
}

// RuleRef identifies the rule behind one scanner report.
type RuleRef struct {
	// Type is the finding family: "core", "external", "nfr", "deploy", "network".
	Type string
	// Source is the scanner: "aitriage", "semgrep", "bandit", "gitleaks", "trivy", ...
	Source string
	// RuleID is the rule, check or advisory id as the scanner reported it.
	RuleID string
	// Package is set for dependency advisories.
	Package string
}

// ClassifyRule returns the canonical class of a scanner report, or false when
// no class covers its rule.
func ClassifyRule(ref RuleRef) (FindingClass, bool) {
	id := strings.ToUpper(strings.TrimSpace(ref.RuleID))
	source := strings.ToLower(strings.TrimSpace(ref.Source))
	kind := strings.ToLower(strings.TrimSpace(ref.Type))
	if kind == "network" {
		return FindingClass{}, false
	}
	// An advisory names a package; which scanner found it does not matter.
	if strings.TrimSpace(ref.Package) != "" {
		return findingClasses[ClassVulnerableDependency], true
	}
	if key, ok := ruleClasses[id]; ok {
		return findingClasses[key], true
	}
	switch source {
	case "gitleaks":
		// Gitleaks detects nothing but secrets.
		return findingClasses[ClassHardcodedSecret], true
	case "trivy":
		if key, ok := trivyCheckClasses[normalizeTrivyCheckID(id)]; ok {
			return findingClasses[key], true
		}
	case "semgrep":
		if key, ok := semgrepClass(ref.RuleID); ok {
			return findingClasses[key], true
		}
	}
	// The built-in engine's secret heuristics (SECRET-ASSIGN, SECRET-AWS-AKID,
	// SECRET-LEAK-LOG, ...); some callers label their source by stack.
	if strings.HasPrefix(id, "SECRET-") {
		return findingClasses[ClassHardcodedSecret], true
	}
	return FindingClass{}, false
}

// LookupClass returns the class with the given key. Hyphens are accepted for
// underscores ("hardcoded-secret"), the spelling the configuration examples use.
func LookupClass(key string) (FindingClass, bool) {
	c, ok := findingClasses[canonicalClassKey(key)]
	return c, ok
}

func canonicalClassKey(key string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
}

func semgrepClass(checkID string) (string, bool) {
	id := strings.ToLower(strings.TrimSpace(checkID))
	if id == "" {
		return "", false
	}
	for _, p := range semgrepClassPatterns {
		for _, fragment := range p.fragments {
			if strings.Contains(id, fragment) {
				return p.class, true
			}
		}
	}
	return "", false
}

var trivyCheckIDPattern = regexp.MustCompile(`^([A-Z]+)-?0*([0-9]+)$`)

// normalizeTrivyCheckID maps the spellings Trivy releases use for one check
// ("DS002", "AVD-DS-0002", "DS-0002") to one form.
func normalizeTrivyCheckID(id string) string {
	id = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(id)), "AVD-")
	m := trivyCheckIDPattern.FindStringSubmatch(id)
	if m == nil {
		return id
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return id
	}
	return fmt.Sprintf("%s-%04d", m[1], n)
}

// findingClassOf resolves a health-check finding's class: Class is either a
// canonical class key or the id of the rule that produced the finding.
func findingClassOf(f Finding) (FindingClass, bool) {
	if c, ok := LookupClass(f.Class); ok {
		return c, true
	}
	return ClassifyRule(RuleRef{Source: f.Source, RuleID: f.Class})
}
