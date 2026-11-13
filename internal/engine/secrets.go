package engine

import (
	"encoding/base64"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/dodobrands/aitriage/internal/scanner/secretvalue"
)

// This file implements deterministic detection of hardcoded secrets and
// credential/data leaks. It combines two strategies:
//
//  1. Signatures for well-known credential formats (AWS keys, GitHub, Slack,
//     Stripe, OpenAI and other vendor tokens, private-key blocks, JWTs, and
//     connection strings that embed a password). A format match alone is not
//     proof: every signature has a check that rejects placeholders ("sk-xxxx",
//     "%s", "${DB_PASSWORD}"), documentation samples and look-alikes (a CSS
//     class named "sk-fading-circle-…"), and decides the severity of a real hit.
//
//  2. A keyword-guarded assignment heuristic (`api_key = "…"`, `password: "…"`,
//     `API_TOKEN := "…"`, unquoted `SESSION_SECRET=…` in .env files) for
//     random-looking secrets that do not match a known vendor format.
//
// All detected values are collected (not just the first per file), so multiple
// secrets in one file are all reported.

// Severities the detector assigns. Each signature states its own, and
// TestSecretSeverityPerID pins them.
const (
	sevCritical = "CRITICAL"
	sevHigh     = "HIGH"
	sevMedium   = "MEDIUM"
)

// Advice shown with a finding. It is plain advice: the severity is a separate
// field, so no text here starts with a severity word.
const (
	adviceVendorToken  = "Revoke the token with the provider and issue a new one, then load it from a secret manager or an environment variable. Deleting it from the code is not enough: it stays in the git history."
	advicePrivateKey   = "Treat the key as compromised: replace it and revoke whatever it signs or authenticates. Keep private keys out of the repository, in a secret manager or a file that git ignores."
	adviceAWSKeyID     = "Remove the access key ID and check whether its secret access key was committed as well; if it was, deactivate the key pair in IAM. Prefer roles or short-lived credentials over static keys."
	adviceAWSKeyPair   = "An AWS access key ID and a secret access key are both in this file. Deactivate the key pair in IAM, then load credentials from a role, the environment or a secret manager."
	adviceSlackWebhook = "Anyone with this URL can post to the channel. Regenerate the webhook in Slack and load the URL from the environment."
	adviceGoogleAPIKey = "Restrict the key in the Google Cloud console (API, referrer or app restrictions) or rotate it if it is unrestricted, and load it from configuration."
	adviceTwilioSID    = "A Twilio API key SID cannot authenticate without its secret, but check whether the secret was committed too, and keep both in the environment."
	adviceJWT          = "If this is a real token, revoke it or rotate the signing key, and do not keep tokens in code. If it is a sample or a fixture, move it into test data or mark the line with an aitriage-ignore comment."
	adviceConnRemote   = "Move the password out of the connection string into an environment variable or a secret manager, and rotate it: anyone who can read the repository can use it."
	adviceConnLocal    = "The connection string carries a password for a local or container service. Read it from the environment so the value cannot slip into a deployed configuration, and do not reuse it elsewhere."
	adviceAssign       = "Move the value to a secret manager or an environment variable, and rotate it if it is a live credential."
	adviceLeakLog      = "The secret is hardcoded and also passed to a log or print call, so it reaches log storage too. Remove the value and the log statement, then rotate the credential."
)

// secretHit is a single detected secret occurrence.
type secretHit struct {
	id       string
	name     string
	line     int
	evidence string
	severity string
	advice   string
	varName  string // identifier the value is assigned to, for leak-to-logger correlation
}

// secretSignature is one known credential format. classify receives the
// submatch indexes of a match and decides whether it is a real credential
// (ok) and how severe it is.
type secretSignature struct {
	id       string
	name     string
	re       *regexp.Regexp
	classify func(src string, m []int) (severity, advice string, ok bool)
}

// secretSignatures are ordered most-specific first so overlapping matches
// (e.g. sk-ant- vs sk-) are attributed to the more precise vendor.
var secretSignatures = []secretSignature{
	{"SECRET-PRIVATE-KEY", "Private Key Block", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`), classifyPrivateKey},
	{"SECRET-AWS-AKID", "AWS Access Key ID", regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`), classifyAWSKeyID},
	{"SECRET-GH-PAT", "GitHub Fine-grained PAT", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{40,}`), vendorToken(sevCritical, adviceVendorToken)},
	{"SECRET-GH-TOKEN", "GitHub Token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36}\b`), vendorToken(sevCritical, adviceVendorToken)},
	{"SECRET-SLACK-TOKEN", "Slack Token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`), vendorToken(sevCritical, adviceVendorToken)},
	{"SECRET-SLACK-WEBHOOK", "Slack Webhook URL", regexp.MustCompile(`https://hooks\.slack\.com/services/([A-Za-z0-9_/]{20,})`), classifySlackWebhook},
	{"SECRET-ANTHROPIC", "Anthropic API Key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}`), vendorToken(sevCritical, adviceVendorToken)},
	{"SECRET-OPENAI", "OpenAI API Key", regexp.MustCompile(`\bsk-(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_\-]{20,}`), classifyOpenAIKey},
	{"SECRET-STRIPE", "Stripe Secret Key", regexp.MustCompile(`\b[rs]k_live_[0-9A-Za-z]{16,}\b`), vendorToken(sevCritical, adviceVendorToken)},
	{"SECRET-SENDGRID", "SendGrid API Key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b`), vendorToken(sevCritical, adviceVendorToken)},
	{"SECRET-GOOGLE-API", "Google API Key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{30,45}`), vendorToken(sevHigh, adviceGoogleAPIKey)},
	{"SECRET-NPM", "npm Token", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`), vendorToken(sevCritical, adviceVendorToken)},
	{"SECRET-TWILIO", "Twilio API Key", regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`), vendorToken(sevHigh, adviceTwilioSID)},
	{"SECRET-JWT", "JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), classifyJWT},
	// Groups: 1 user (may be empty: redis://:pw@host), 2 password, 3 host.
	// A "+driver" suffix covers SQLAlchemy URLs (postgresql+asyncpg://).
	{"SECRET-CONN-STRING", "Credentialed Connection String", regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|rediss|amqps?|mssql|sqlserver)(?:\+[a-z0-9]+)?://([^:@\s/"'\x60]*):([^@\s/"'\x60]+)@(\[[^\]\s]*\]|[^/\s"'\x60:?#,;@]+)`), classifyConnString},
}

// Ids of the keyword heuristic and of the leak escalation.
const (
	secretAssignID  = "SECRET-ASSIGN"
	secretLeakLogID = "SECRET-LEAK-LOG"
)

// SecretRuleIDs returns every rule id the hardcoded-secret detector can emit.
func SecretRuleIDs() []string {
	ids := make([]string, 0, len(secretSignatures)+2)
	for _, sig := range secretSignatures {
		ids = append(ids, sig.id)
	}
	return append(ids, secretAssignID, secretLeakLogID)
}

// secretScanKind selects which detectors run on a file.
type secretScanKind int

const (
	scanSignaturesOnly secretScanKind = iota + 1 // structured config, key files
	scanCode                                     // signatures + quoted keyword assignments
	scanEnvFile                                  // code + unquoted KEY=value lines
)

// privateKeyFileExts are key containers: only signatures run there.
var privateKeyFileExts = map[string]bool{".pem": true, ".key": true, ".p8": true}

// privateKeyBaseNames are OpenSSH private keys, which have no extension.
var privateKeyBaseNames = map[string]bool{"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true}

// secretScanKindFor decides which detectors run on a file, or false to skip it.
// .env templates (.env.example, .env.sample, .env.template, .env.dist,
// example.env) document the variables rather than configure them, and are
// skipped entirely.
func secretScanKindFor(path, ext string) (secretScanKind, bool) {
	base := strings.ToLower(filepath.Base(path))
	ext = strings.ToLower(ext)
	switch {
	case isEnvTemplateName(base):
		return 0, false
	case looksLikeEnvName(base):
		return scanEnvFile, true
	case entropyAllowedExts[ext]:
		return scanCode, true
	case secretConfigExts[ext], privateKeyFileExts[ext], privateKeyBaseNames[base]:
		return scanSignaturesOnly, true
	}
	return 0, false
}

// looksLikeEnvName reports whether a lower-cased base name is a dotenv file
// or a variant of one: .env, .env.local, .env.production, prod.env, .envrc.
func looksLikeEnvName(base string) bool {
	return base == ".env" || base == ".envrc" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

// isEnvTemplateName reports a dotenv template: .env.example, .env.sample,
// .env.template, .env.dist, example.env and their variants.
func isEnvTemplateName(base string) bool {
	if !looksLikeEnvName(base) {
		return false
	}
	for _, part := range strings.Split(base, ".") {
		switch part {
		case "example", "sample", "template", "dist":
			return true
		}
	}
	return false
}

// assignmentRegex matches a quoted string assigned to an identifier:
// `name = "v"`, `name := "v"`, `name: "v"`, `"name": "v"`, `self.name = "v"`,
// and typed forms such as `name: str = "v"`. Group 1 is the identifier,
// group 2 the value. Whether the identifier names a secret is decided by
// isSecretName, which is easier to read and test than one large regex.
var assignmentRegex = regexp.MustCompile(`(?:^|[^\w$.])((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$-]*)["']?[ \t]*(?::[ \t]*[A-Za-z_][\w\[\]., |]*?[ \t]*)?(?::=|=|:)[ \t]*[fbr]?["'\x60]([^"'\x60\n]{6,})["'\x60]`)

// envAssignRegex matches an unquoted value in a dotenv file: `KEY=value` or
// `export KEY=value`. Quoted values are handled by assignmentRegex.
var envAssignRegex = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.]*)[ \t]*=[ \t]*([^\s"'\x60#][^\s#]*)`)

// placeholderValueRegex matches values that are clearly not real secrets:
// template interpolation, env lookups, or obvious dummy words. It intentionally
// does NOT reject bare `$`/`%`/`{` characters, since strong passwords contain
// those — only actual interpolation/format syntax.
var placeholderValueRegex = regexp.MustCompile(`(?i)(\$\{|\{\{|%\(|%[svd]\b|\{[A-Za-z_][\w.]*\}|process\.env|os\.(getenv|environ)|getenv\(|^\$[A-Za-z_]\w*$|^<[^>]*>$|^(your[_-]|change[_-]?me|replace[_-]|example|placeholder|dummy|sample|xxx+|test|todo|none|null|undefined|foobar|lorem)$)`)

// passwordHashRegex matches stored password hashes in self-describing
// formats: bcrypt ($2a$10$...), argon2, Django PBKDF2/bcrypt/argon2
// encodings and crypt(3) ($1$, $5$, $6$).
var passwordHashRegex = regexp.MustCompile(`^(?:\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2(?:id|i|d)\$\S+|(?:pbkdf2_sha(?:1|256)|bcrypt_sha256|argon2)\$\S+|\$[156]\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]+)$`)

// hexDigestRegex matches a bare hex digest the length of MD5, SHA-1,
// SHA-256 or SHA-512.
var hexDigestRegex = regexp.MustCompile(`^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$`)

// isStoredPasswordDigest reports a hex digest stored under a password or hash
// name: that is the hash an application keeps, not the password. Under other
// names (SESSION_SECRET, API_KEY) a hex string is usually a random secret.
func isStoredPasswordDigest(name, val string) bool {
	lower := strings.ToLower(name)
	return hexDigestRegex.MatchString(strings.TrimSpace(val)) &&
		(strings.Contains(lower, "passw") || strings.Contains(lower, "hash") || strings.Contains(lower, "digest"))
}

// tokenPlaceholderRegex matches placeholder text inside a token-shaped value:
// "sk-xxxxxxxx", "AKIA****", "ghp_your_token_here", "…EXAMPLEKEY".
var tokenPlaceholderRegex = regexp.MustCompile(`(?i)x{4,}|\*{3,}|\.{3,}|example|placeholder|your[_-]|dummy|sample|redacted|change_?me|insert[_-]|fake`)

// resourceNameRegex matches lower-case kebab, snake or path-like names: a
// Kubernetes secret name ("payments-api-db-credentials") or a secret manager
// path ("projects/p/secrets/db-password/versions/latest"). Assigned to a
// variable called SECRET they name a secret; they are not one.
var resourceNameRegex = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_./:]+[a-z0-9]+)+$`)

// uuidRegex: UUID-shaped tokens are real credentials for some providers, so
// they are never treated as resource names.
var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// envVarNameRegex matches an environment variable name used as a value
// (`token = "GITHUB_TOKEN"`): a reference, not a secret.
var envVarNameRegex = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)

// proseRegex matches a value made only of words and spaces: UI copy such as
// `password: "Enter your password"`.
var proseRegex = regexp.MustCompile(`^\pL[\pL'’]*(?:[ \t]+[\pL'’.,!?:-]+)+$`)

// filePathRegex matches a filesystem path used as a value
// (`secret = "/run/secrets/db_password"`).
var filePathRegex = regexp.MustCompile(`^(?:/|\./|\.\./|~/)[\w.@/-]+$`)

// detectSecretHits returns every secret occurrence in src. Line numbers are
// 1-based. It does not apply suppression or file-type gating — callers do that.
//
// kind selects the detectors: signatures always run; the keyword-guarded
// assignment heuristic runs for code and .env files, where `name = "value"` is
// meaningful; unquoted `KEY=value` lines are read only in .env files.
func detectSecretHits(src string, kind secretScanKind) []secretHit {
	var hits []secretHit
	seen := map[string]bool{} // dedup by "line:matchedText"
	claim := func(line int, text string) bool {
		key := text
		if len(key) > 24 {
			key = key[:24]
		}
		dedup := itoa(line) + ":" + key
		if seen[dedup] {
			return false
		}
		seen[dedup] = true
		return true
	}

	// 1. Known-format signatures.
	for _, sig := range secretSignatures {
		for _, m := range sig.re.FindAllStringSubmatchIndex(src, -1) {
			severity, advice, ok := sig.classify(src, m)
			if !ok {
				continue
			}
			matched := src[m[0]:m[1]]
			line := lineAt(src, m[0])
			if !claim(line, matched) {
				continue
			}
			hits = append(hits, secretHit{
				id:       sig.id,
				name:     sig.name,
				line:     line,
				evidence: redactSecret(matched),
				severity: severity,
				advice:   advice,
				varName:  assignedName(src, m[0]),
			})
		}
	}

	if kind != scanCode && kind != scanEnvFile {
		return hits
	}

	// 2. Keyword-guarded assignment heuristic.
	addAssign := func(varName, val string, valStart int) {
		if !isSecretName(varName) || !isLikelySecretValue(val) || isStoredPasswordDigest(varName, val) {
			return
		}
		line := lineAt(src, valStart)
		if !claim(line, val) { // already reported by a vendor-format signature
			return
		}
		hits = append(hits, secretHit{
			id:       secretAssignID,
			name:     "Hardcoded Secret Assignment",
			line:     line,
			evidence: redactSecret(val),
			severity: sevHigh,
			advice:   adviceAssign,
			varName:  varName,
		})
	}
	for _, m := range assignmentRegex.FindAllStringSubmatchIndex(src, -1) {
		addAssign(src[m[2]:m[3]], src[m[4]:m[5]], m[4])
	}
	if kind == scanEnvFile {
		for _, m := range envAssignRegex.FindAllStringSubmatchIndex(src, -1) {
			addAssign(src[m[2]:m[3]], src[m[4]:m[5]], m[4])
		}
	}
	return hits
}

// lineAt returns the 1-based line of byte offset idx.
func lineAt(src string, idx int) int {
	return strings.Count(src[:idx], "\n") + 1
}

// vendorToken is the classifier for a vendor token whose format is the
// signature itself: it only has to reject placeholders and low-entropy
// look-alikes.
func vendorToken(severity, advice string) func(string, []int) (string, string, bool) {
	return func(src string, m []int) (string, string, bool) {
		if !plausibleToken(src[m[0]:m[1]]) {
			return "", "", false
		}
		return severity, advice, true
	}
}

// plausibleToken rejects placeholder and dummy tokens: "sk-xxxxxxxx",
// "ghp_your_token_here", a run of one character, or text with too little
// variety to be random.
func plausibleToken(s string) bool {
	if tokenPlaceholderRegex.MatchString(s) || longestRun(s) >= 6 {
		return false
	}
	return CalculateShannonEntropy(s) >= 3.0
}

// longestRun returns the length of the longest run of one repeated byte.
func longestRun(s string) int {
	best, run := 0, 0
	for i := 0; i < len(s); i++ {
		if i > 0 && s[i] == s[i-1] {
			run++
		} else {
			run = 1
		}
		if run > best {
			best = run
		}
	}
	return best
}

// classifyPrivateKey reports a private-key header only when key material
// follows it. A bare header is what PEM-parsing code compares against.
func classifyPrivateKey(src string, m []int) (string, string, bool) {
	if !hasKeyBody(src[m[1]:]) {
		return "", "", false
	}
	return sevCritical, advicePrivateKey, true
}

var (
	base64RunRegex = regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)
	keyBodyCleaner = strings.NewReplacer(`\n`, "", `\r`, "", "\n", "", "\r", "", " ", "", "\t", "", `"`, "", "'", "", "`", "")
)

// hasKeyBody reports whether the text after a BEGIN line holds base64 key
// material, also when the key is a string literal with \n escapes or split
// over concatenated lines.
func hasKeyBody(rest string) bool {
	if len(rest) > 8192 {
		rest = rest[:8192]
	}
	if i := strings.Index(rest, "-----END"); i >= 0 {
		rest = rest[:i]
	}
	for _, run := range base64RunRegex.FindAllString(keyBodyCleaner.Replace(rest), -1) {
		if !strings.Contains(strings.ToLower(run), "xxxx") && CalculateShannonEntropy(run) >= 3.5 {
			return true
		}
	}
	return false
}

// awsSecretKeyRegex matches an AWS secret access key assigned by name.
var awsSecretKeyRegex = regexp.MustCompile(`(?i)secret_?access_?key["']?\s*(?::=|=|:)\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`)

// classifyAWSKeyID: an access key ID alone cannot authenticate, so it is HIGH;
// with a secret access key in the same file it is a usable key pair. The AWS
// documentation key (…EXAMPLE) is skipped.
func classifyAWSKeyID(src string, m []int) (string, string, bool) {
	id := src[m[0]:m[1]]
	if strings.HasSuffix(id, "EXAMPLE") || !plausibleToken(id) {
		return "", "", false
	}
	if hasAWSSecretKey(src) {
		return sevCritical, adviceAWSKeyPair, true
	}
	return sevHigh, adviceAWSKeyID, true
}

func hasAWSSecretKey(src string) bool {
	for _, m := range awsSecretKeyRegex.FindAllStringSubmatch(src, -1) {
		if !strings.Contains(m[1], "EXAMPLE") && CalculateShannonEntropy(m[1]) >= 3.5 {
			return true
		}
	}
	return false
}

func classifySlackWebhook(src string, m []int) (string, string, bool) {
	if !plausibleToken(src[m[2]:m[3]]) {
		return "", "", false
	}
	return sevHigh, adviceSlackWebhook, true
}

// classifyOpenAIKey: "sk-" is a common prefix (CSS classes, slugs), so the
// signature needs more than the prefix. Real keys carry the "T3BlbkFJ" marker
// (base64 of "OpenAI"); anything else must be a long, random-looking
// alphanumeric body with mixed case and digits.
func classifyOpenAIKey(src string, m []int) (string, string, bool) {
	key := src[m[0]:m[1]]
	if strings.HasPrefix(key, "sk-ant-") || !plausibleToken(key) {
		return "", "", false
	}
	if strings.Contains(key, "T3BlbkFJ") {
		return sevCritical, adviceVendorToken, true
	}
	body := strings.TrimPrefix(key, "sk-")
	for _, kind := range []string{"proj-", "svcacct-", "admin-"} {
		body = strings.TrimPrefix(body, kind)
	}
	if len(body) < 40 || longestAlnumRun(body) < 20 || !mixedCaseWithDigit(body) || CalculateShannonEntropy(body) < 4.0 {
		return "", "", false
	}
	return sevCritical, adviceVendorToken, true
}

// longestAlnumRun returns the length of the longest run of ASCII letters and
// digits.
func longestAlnumRun(s string) int {
	best, run := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			run++
			if run > best {
				best = run
			}
		} else {
			run = 0
		}
	}
	return best
}

func mixedCaseWithDigit(s string) bool {
	var upper, lower, digit bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

// jwtIOSampleSignature is the signature of the sample token on jwt.io, copied
// into countless READMEs, OpenAPI examples and tests.
const jwtIOSampleSignature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

// classifyJWT: a JWT is usually short-lived and often a sample, so it is
// MEDIUM. The jwt.io sample token is skipped, also with an edited payload.
func classifyJWT(src string, m []int) (string, string, bool) {
	parts := strings.Split(src[m[0]:m[1]], ".")
	if len(parts) == 3 {
		if parts[2] == jwtIOSampleSignature {
			return "", "", false
		}
		if payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "=")); err == nil {
			p := string(payload)
			if strings.Contains(p, `"sub":"1234567890"`) && strings.Contains(p, `"name":"John Doe"`) {
				return "", "", false
			}
		}
	}
	return sevMedium, adviceJWT, true
}

// connPlaceholderRegex matches a connection-string password that is a
// template or a documentation stand-in rather than a value: {password},
// %s, %(pw)s, ${DB_PASSWORD}, $DB_PASSWORD, <password>, ****, xxx, changeme.
var connPlaceholderRegex = regexp.MustCompile(`(?i)[{}<>]|%[sdv]|%\(|\$\{|^\$[A-Za-z_]\w*$|^\[.*\]$|x{3,}|\*{3,}|\.{3,}|change[_-]?me|^your[_-]?|^(?:password|passwd|pass|pwd|pw|secret|mypassword|dbpassword)$`)

// classifyConnString: placeholders and documentation hosts are skipped; a
// password for a local or single-label (compose/Kubernetes service) host is
// MEDIUM; a password for any other host is HIGH.
func classifyConnString(src string, m []int) (string, string, bool) {
	password := src[m[4]:m[5]]
	host := strings.ToLower(strings.Trim(src[m[6]:m[7]], "[]"))
	if connPlaceholderRegex.MatchString(password) || isDocumentationHost(host) {
		return "", "", false
	}
	if isLocalHost(host) {
		return sevMedium, adviceConnLocal, true
	}
	return sevHigh, adviceConnRemote, true
}

// isDocumentationHost reports the domains reserved for examples (RFC 2606).
func isDocumentationHost(host string) bool {
	for _, d := range []string{"example.com", "example.org", "example.net"} {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return strings.HasSuffix(host, ".example")
}

// isLocalHost reports loopback addresses and single-label names, which in a
// connection string are compose or Kubernetes service names ("db", "redis").
func isLocalHost(host string) bool {
	switch {
	case host == "localhost", strings.HasSuffix(host, ".localhost"), host == "host.docker.internal",
		host == "0.0.0.0", host == "::1", strings.HasPrefix(host, "127."):
		return true
	}
	return !strings.ContainsAny(host, ".:")
}

// assignedNameRegex captures the identifier at the end of a line prefix that
// opens a string assigned to it: `k = "`, `token: '`, `apiKey := "`.
var assignedNameRegex = regexp.MustCompile(`((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*)["']?\s*(?::\s*[A-Za-z_][\w\[\]., |]*?\s*)?(?::=|=|:)\s*[fbr]?["'\x60]$`)

// assignedName returns the identifier a literal starting at idx is assigned
// to on its line, or "".
func assignedName(src string, idx int) string {
	start := strings.LastIndexByte(src[:idx], '\n') + 1
	m := assignedNameRegex.FindStringSubmatch(src[start:idx])
	if m == nil {
		return ""
	}
	return m[1]
}

// isSecretName reports whether an identifier names a credential: its last
// word (or last two words) is a secret keyword. Words are split on "_", "-",
// "." and camelCase, so API_TOKEN, self.api_key, dbPassword and
// aws_secret_access_key all qualify, while tokenizer, SECRET_NAME and
// passwordField do not.
func isSecretName(ident string) bool {
	if i := strings.LastIndexByte(ident, '.'); i >= 0 {
		ident = ident[i+1:]
	}
	words := splitIdentifier(ident)
	n := len(words)
	if n == 0 {
		return false
	}
	switch words[n-1] {
	case "secret", "token", "password", "passwd", "passphrase", "credential", "credentials",
		"apikey", "secretkey", "accesskey", "privatekey", "authkey", "signingkey", "dbpass", "dbpassword":
		return true
	case "key":
		if n >= 2 {
			switch words[n-2] {
			case "api", "secret", "access", "private", "auth", "signing":
				return true
			}
		}
	case "pass":
		return n >= 2 && words[n-2] == "db"
	}
	return false
}

// splitIdentifier splits an identifier into lower-case words on "_", "-",
// "$" and camelCase boundaries (APIKey → api, key).
func splitIdentifier(ident string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(ident)
	for i, r := range runes {
		if r == '_' || r == '-' || r == '$' {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(cur) > 0 {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

// isLikelySecretValue decides whether a value assigned to a secret-named
// variable is a real secret rather than a placeholder, a reference or a name.
func isLikelySecretValue(val string) bool {
	v := strings.TrimSpace(val)
	if len(v) < 8 {
		return false
	}
	if placeholderValueRegex.MatchString(v) || tokenPlaceholderRegex.MatchString(v) {
		return false
	}
	// A password hash (bcrypt, argon2, PBKDF2, crypt, or a bare hex digest)
	// is what an application should store; it is not a usable credential.
	if passwordHashRegex.MatchString(v) {
		return false
	}
	// Names and references, not values: a Kubernetes secret name, a secret
	// manager path or ARN, a file path, an environment variable name, UI copy.
	if (resourceNameRegex.MatchString(v) && !uuidRegex.MatchString(v) && maxSegmentLen(v) <= 16) ||
		strings.HasPrefix(v, "arn:") || filePathRegex.MatchString(v) ||
		envVarNameRegex.MatchString(v) || proseRegex.MatchString(v) || looksLikeProse(v) {
		return false
	}
	// A plain URL without embedded credentials is not itself a secret;
	// credentialed connection strings are caught by a dedicated signature.
	if (strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")) && !strings.Contains(v, "@") {
		return false
	}
	// High-entropy random blob (API key / token) or a reasonably complex
	// password. Structured vendor tokens are already caught by signatures.
	// The deploy audit shares the threshold (secretvalue.LooksGenerated).
	return secretvalue.LooksGenerated(v)
}

// looksLikeProse reports a value of three or more words with almost no
// symbols: a label or a description ("A02:2021 – Cryptographic Failures" in a
// map keyed by rule ids). A passphrase padded with symbols
// ("A String Very Strong!!@##$") still counts as a secret.
func looksLikeProse(v string) bool {
	if len(strings.Fields(v)) < 3 {
		return false
	}
	symbols := 0
	for _, r := range v {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) && !strings.ContainsRune(".,:;'’()–—-/&?!", r) {
			symbols++
		}
	}
	return symbols < 3
}

// maxSegmentLen returns the length of the longest part of v between
// separators. Words in a resource name are short; random tokens are not.
func maxSegmentLen(v string) int {
	best := 0
	for _, seg := range strings.FieldsFunc(v, func(r rune) bool { return strings.ContainsRune("-_./:", r) }) {
		if len(seg) > best {
			best = len(seg)
		}
	}
	return best
}

// leakSinkPattern matches the start of a log or print call. Words that merely
// begin with "log" (login, logout) are not sinks.
const leakSinkPattern = `(?i:\b(?:console|log|logger|logging|slog|klog|logrus|zap)\b(?:\.\w+)*|\bprint\w*|\bputs)\s*\(`

// leaksToLogger reports whether the identifier varName is passed to a log or
// print call anywhere in src.
func leaksToLogger(src, varName string) bool {
	if i := strings.LastIndexByte(varName, '.'); i >= 0 {
		varName = varName[i+1:]
	}
	if varName == "" {
		return false
	}
	re, err := regexp.Compile(leakSinkPattern + `[^)]*\b` + regexp.QuoteMeta(varName) + `\b[^)]*\)`)
	return err == nil && re.MatchString(src)
}

// redactSecret returns a safe, non-reversible preview of a detected secret so
// evidence never re-emits the full credential.
func redactSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 4 {
		return "****"
	}
	prefix := s
	if len(prefix) > 4 {
		prefix = prefix[:4]
	}
	return prefix + "…(redacted, " + itoa(len(s)) + " chars)"
}

// itoa is a tiny strconv.Itoa to avoid an extra import churn in this file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
