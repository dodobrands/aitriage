package deployaudit

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Default and weak credentials in Compose files.
//
// A Compose file that starts a database for local development or a test run
// usually commits its password, and that password is usually a stock default
// ("postgres"), a placeholder ("changeme") or the user name again. Such a value
// is worth reporting: nothing stops the file, or the habit, from reaching a
// shared or deployed environment. It is not a live secret, though, and
// reporting it as a CRITICAL hardcoded secret, next to real ones, drowned them.
//
// A value is reported as compose_default_credential (MEDIUM) when it falls in a
// category of the blocklist NIST SP 800-63B asks password verifiers to check
// new passwords against:
//   - shorter than eight characters, the shortest password the guideline
//     allows, and the shortest value the built-in secret detector considers;
//   - a context-specific word: the name of a service or an image in the file,
//     or a user or database name it sets ("DB_PASSWORD: inventory" next to
//     "DB_USER: inventory");
//   - a dictionary or default word: a default account name, a documented
//     default of a widely used image, a placeholder word or the top of public
//     breached-password lists;
//   - such a word with a password word or a short run of digits or symbols
//     appended ("admin123", "inventory_pass");
//   - a documentation placeholder ("your-password-here", "<password>", "xxxx");
//   - repetitive or sequential characters ("aaaaaaaa", "12345678").
//
// Every other literal value is reported as compose_hardcoded_secret, CRITICAL,
// as before. Values the stack resolves when it starts (${DB_PASSWORD},
// $DB_PASSWORD) and paths of files that hold the secret are not reported.

// Issue ids of the Compose secret checks.
const (
	IssueComposeHardcodedSecret   = "compose_hardcoded_secret"
	IssueComposeDefaultCredential = "compose_default_credential"
)

// PreviousIssue returns the id findings of issue were reported under in
// earlier releases, or "". A default credential in a Compose file was a
// compose_hardcoded_secret until it got an issue of its own; an ignore.rules
// entry, an inline directive, a baseline entry or a recorded dismissal written
// for that id must keep covering it, so the split resurfaces nothing a project
// had already silenced or accepted.
func PreviousIssue(issue string) string {
	if issue == IssueComposeDefaultCredential {
		return IssueComposeHardcodedSecret
	}
	return ""
}

const (
	adviceComposeSecret            = "Use environment variable substitution: ${MY_PASSWORD}"
	adviceComposeDefaultCredential = "A default or easily guessed value (a stock default, a placeholder, or a name used elsewhere in the file). Acceptable only for a stack that runs on a developer's machine; anywhere else, read a strong value from the environment (${MY_PASSWORD}) or a Docker secret."
)

// minCredentialLength is the shortest password NIST SP 800-63B allows.
const minCredentialLength = 8

// defaultCredentialWords are the default and dictionary values weak
// credentials are made of, lower-cased. A word shorter than
// minCredentialLength is weak on its own; it is listed as the base of longer
// values ("admin123", "guestpass").
var defaultCredentialWords = map[string]bool{
	// Default account names, the ones the built-in rule ENTR-19 recognises as
	// default credentials in a connection URL.
	"admin": true, "root": true, "toor": true, "guest": true, "user": true, "sa": true,
	// Documented defaults and documentation examples of widely used images:
	// the postgres superuser and the password of the postgres image's
	// examples, the example root password of the mysql and mariadb images,
	// MinIO's default root credentials, the example sa passwords of the SQL
	// Server images.
	"postgres": true, "mysecretpassword": true, "my-secret-pw": true, "minioadmin": true,
	"yourstrong@passw0rd": true, "yourstrong(!)password": true,
	// Placeholder words, which the built-in secret detector does not report at
	// all. Other placeholders are matched by placeholderCredential.
	"password": true, "passwd": true, "pass": true, "pwd": true, "secret": true,
	"test": true, "demo": true, "default": true,
	// The top of public breached-password lists.
	"qwerty": true, "letmein": true, "welcome": true, "passw0rd": true, "p@ssw0rd": true, "1234567890": true,
}

// credentialWords are appended to a base word to make a weak value
// ("guestpass", "inventory_password"); longer words come first.
var credentialWords = []string{"password", "passwd", "secret", "pass", "pwd", "pw"}

// maxWeakSuffix bounds the run of digits and symbols that may follow a base
// word: a year or a counter and a punctuation mark or two ("2024!").
const maxWeakSuffix = 6

// placeholderCredential matches the documentation stand-ins the built-in secret
// detector also rejects in a token. Values are matched lower-cased.
var placeholderCredential = regexp.MustCompile(`example|sample|dummy|placeholder|redacted|fake|change[_-]?me|your[_-]|replace[_-]|insert[_-]|^<.*>$|x{4,}|\*{3,}|\.{3,}`)

// composeVariable matches a value that is one Compose variable, "$DB_PASSWORD".
// Compose substitutes it when the stack starts, as it does "${DB_PASSWORD}"; a
// literal dollar sign has to be written "$$".
var composeVariable = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)

// composeLiteral reports whether the value of a password or secret key is a
// literal the file commits. Empty values, interpolations and the path of a
// file that holds the secret (POSTGRES_PASSWORD_FILE: /run/secrets/db, the
// convention of the official database images) are not.
func composeLiteral(key, value string) bool {
	switch {
	case value == "", strings.Contains(value, "${"), composeVariable.MatchString(value):
		return false
	case strings.HasSuffix(strings.ToLower(key), "_file") && strings.Contains(value, "/"):
		return false
	}
	return true
}

// isWeakCredential reports whether a committed value is a default or weak
// credential rather than a secret someone generated. context holds the
// lower-cased context-specific words of the file (see composeContextWords).
func isWeakCredential(value string, context map[string]bool) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if utf8.RuneCountInString(v) < minCredentialLength {
		return true
	}
	if placeholderCredential.MatchString(v) || repetitiveOrSequential(v) {
		return true
	}
	if defaultCredentialWords[v] || context[v] {
		return true
	}
	stem := credentialStem(v)
	return stem != "" && (defaultCredentialWords[stem] || context[stem])
}

// credentialStem returns the base word of a lower-cased value: without a
// trailing run of at most maxWeakSuffix digits and symbols ("admin123",
// "postgres!"), then without a trailing password word and the separator
// before it ("guestpass", "inventory_password").
func credentialStem(v string) string {
	end := len(v)
	for end > 0 && len(v)-end < maxWeakSuffix && isWeakSuffixByte(v[end-1]) {
		end--
	}
	stem := v[:end]
	for _, word := range credentialWords {
		if base, ok := strings.CutSuffix(stem, word); ok && base != "" {
			return strings.TrimRight(base, "-_.")
		}
	}
	return stem
}

func isWeakSuffixByte(b byte) bool {
	return b >= '0' && b <= '9' || strings.IndexByte("!@#$%^&*?+=~._-", b) >= 0
}

// repetitiveOrSequential reports a value made of one repeated character or of
// characters that rise or fall by one: "aaaaaaaa", "12345678", "87654321".
func repetitiveOrSequential(v string) bool {
	if len(v) < 2 {
		return false
	}
	step := int(v[1]) - int(v[0])
	if step < -1 || step > 1 {
		return false
	}
	for i := 2; i < len(v); i++ {
		if int(v[i])-int(v[i-1]) != step {
			return false
		}
	}
	return true
}

// composeContextWords returns the context-specific words of a Compose file,
// lower-cased: the names of its services and their images, and every user or
// database name it sets, in mapping or list form.
func composeContextWords(root *yaml.Node) map[string]bool {
	words := map[string]bool{}
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !strings.Contains(value, "$") {
			words[value] = true
		}
	}
	if services := mappingValue(documentMapping(root), "services"); services != nil && services.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(services.Content); i += 2 {
			add(services.Content[i].Value)
			if image := mappingValue(services.Content[i+1], "image"); image != nil && image.Kind == yaml.ScalarNode {
				add(imageName(image.Value))
			}
		}
	}
	walkYamlNode(root, "", func(key, val *yaml.Node) {
		switch {
		case val.Kind == yaml.ScalarNode && namesAccount(key.Value):
			add(val.Value)
		case val.Kind == yaml.SequenceNode && strings.EqualFold(key.Value, "environment"):
			for _, item := range val.Content {
				if item.Kind != yaml.ScalarNode {
					continue
				}
				if name, value, ok := strings.Cut(item.Value, "="); ok && namesAccount(name) {
					add(value)
				}
			}
		}
	})
	return words
}

// namesAccount reports whether a setting names a user or a database:
// MYSQL_USER, POSTGRES_DB, MONGO_INITDB_ROOT_USERNAME, APP_DB_NAME.
func namesAccount(key string) bool {
	words := strings.FieldsFunc(strings.ToLower(key), func(r rune) bool { return r == '_' || r == '-' || r == '.' })
	n := len(words)
	if n == 0 {
		return false
	}
	switch words[n-1] {
	case "user", "username", "login", "db", "database", "dbname":
		return true
	case "name":
		return n >= 2 && (words[n-2] == "db" || words[n-2] == "database" || words[n-2] == "user")
	}
	return false
}

// imageName returns the repository name of an image reference, without
// registry, namespace, tag or digest: "postgres" for
// "registry.example.test/library/postgres:16@sha256:…".
func imageName(ref string) string {
	ref = strings.TrimSpace(ref)
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.IndexByte(ref, ':'); i >= 0 {
		ref = ref[:i]
	}
	return ref
}

// documentMapping returns the top-level mapping of a parsed YAML document.
func documentMapping(root *yaml.Node) *yaml.Node {
	if root != nil && root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	return root
}

// mappingValue returns the value of key in a mapping node, or nil.
func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}
