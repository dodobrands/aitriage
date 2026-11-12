package engine

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dodobrands/aitriage/internal/engine/core"
)

// Credential-shaped values in this file are assembled from fragments at run
// time (fake), so the source holds no literal that a secret scanner would
// report as a live secret. The fragments are random and belong to no account.
func fake(parts ...string) string { return strings.Join(parts, "") }

const (
	rnd20   = "q08r6pzabncfUt7WfIWN"
	rnd24   = "AornV2XNpMtoaEI9V7Pxp6rv"
	rnd36   = "denryyo0a9HTeYXHrvT9TIjdiE6yRCxbTHEM"
	rnd40   = "vyHvBfR3BFl94GEmceaIK0GongXdxLPQxE6mf1hl"
	rnd64a  = "jEr6tHUQfeiNOYFqfK7F3Ud4SxFWkIySmSvTofun9T15lwpgRiY4zEVftqh9RU5p"
	rnd64b  = "jfJvJxjeLP8jLUYHVMSqBYj3wgxy0mRQYVRY0cHjwXrc8WsWhxRUQqGqYCdeLiPr"
	rnd64c  = "RHtS2iTJe77GQN9hythoaagc4Cg5bdsOzZpf3hQzchptYuWu7NQGtNnHE9f3V9h0"
	hex32   = "23efd7f548968e265e0e8c363327f7b1"
	b64Line = "whQrAgIh729lr8l+L88l2sSDWe80nJxTBZ86c1fvUFMiOVB9Y1gumLHCxfxkhGUh"
	upper16 = "GV7GU89VJDR9U381"
	aws40   = "wBr1ZVtZUo1boU/pi7zC75WGpYEcjegFjlPwfEu7"
	jwtHead = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"HS256","typ":"JWT"}
)

var (
	awsKeyID     = fake("AK", "IA", upper16)
	awsDocKeyID  = fake("AKIAIOSFODNN7", "EXAMPLE")
	ghToken      = fake("gh", "p_", rnd36)
	ghPAT        = fake("github", "_pat_", "11", rnd20, "_", rnd40)
	slackToken   = fake("xo", "xb-", "2849017365-", "4810293847561-", rnd24)
	slackWebhook = fake("https://hooks.slack.com/services/", "T04B9K7QZ2/", "B05HN3XW8L/", rnd24)
	anthropicKey = fake("sk-", "ant-api03-", rnd64a, "AA")
	openAIKey    = fake("sk-", rnd20, "T3Blbk", "FJ", rnd20)
	openAIProj   = fake("sk-", "proj-", rnd64b)
	stripeKey    = fake("sk_", "live_", rnd24)
	sendgridKey  = fake("S", "G.", rnd20, "AB.", rnd40)
	googleKey    = fake("AI", "za", "Sy", rnd36[:33])
	npmToken     = fake("np", "m_", rnd36)
	twilioSID    = fake("S", "K", hex32)
	jwtToken     = fake(jwtHead, ".", b64url(`{"sub":"user-42","exp":1900000000}`), ".", rnd36)
	jwtIOSample  = fake(jwtHead, ".", b64url(`{"sub":"1234567890","name":"John Doe","iat":1516239022}`), ".", jwtIOSampleSignature)
	keyBody      = fake(b64Line, "\n", rnd64c, "\n", rnd64a[:44], "==")
	rsaKey       = fake("-----BEGIN ", "RSA PRIVATE KEY-----\n", keyBody, "\n-----END RSA PRIVATE KEY-----\n")
	encryptedKey = fake(`"-----BEGIN `, `ENCRYPTED PRIVATE KEY-----\n`, b64Line, `\n`, rnd64c, `\n-----END ENCRYPTED PRIVATE KEY-----"`)
	connRemote   = fake("postgres://", "svc:", "N7f%24kq9", "Lz2pW", "@prod-db.internal:5432/app")
	connLocal    = fake("postgres://", "admin:", "S3cret", "DbPass", "@localhost:5432/app")
	connCompose  = fake("amqp://", "app:", "S3cret", "MqPass", "@rabbitmq:5672/")
)

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// evalFile runs the secret detector the way the engine does, on one file.
func evalFile(t *testing.T, name, content string) []core.CheckResult {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	return e.evaluateEntropy(&core.FileInfo{Path: path, RelPath: name, Extension: strings.ToLower(filepath.Ext(name))})
}

func resultIDs(results []core.CheckResult) map[string]bool {
	ids := map[string]bool{}
	for _, r := range results {
		ids[r.ID] = true
	}
	return ids
}

// hitIDs returns the set of detected signature IDs for src read as code.
func hitIDs(src string) map[string]bool {
	ids := map[string]bool{}
	for _, h := range detectSecretHits(src, scanCode) {
		ids[h.id] = true
	}
	return ids
}

var severityWord = regexp.MustCompile(`(?i)^\s*(critical|high|medium|low|info)\b`)

// TestSecretSeverityPerID pins the severity and the advice of every id the
// detector can emit. Adding a signature without a case here fails the test.
func TestSecretSeverityPerID(t *testing.T) {
	cases := []struct {
		name, file, src string
		id, severity    string
		advice          string
	}{
		{"private key with a body", "keys.go", "var k = `" + rsaKey + "`\n", "SECRET-PRIVATE-KEY", "CRITICAL", advicePrivateKey},
		{"aws key id alone", "conf.py", "aws_key_id = '" + awsKeyID + "'\n", "SECRET-AWS-AKID", "HIGH", adviceAWSKeyID},
		{"aws key id with its secret key", "conf.py", "aws_access_key_id = '" + awsKeyID + "'\naws_secret_access_key = '" + aws40 + "'\n", "SECRET-AWS-AKID", "CRITICAL", adviceAWSKeyPair},
		{"github fine-grained pat", "a.js", "const t = '" + ghPAT + "';\n", "SECRET-GH-PAT", "CRITICAL", adviceVendorToken},
		{"github token", "a.js", "const t = '" + ghToken + "';\n", "SECRET-GH-TOKEN", "CRITICAL", adviceVendorToken},
		{"slack token", "a.js", "const t = '" + slackToken + "';\n", "SECRET-SLACK-TOKEN", "CRITICAL", adviceVendorToken},
		{"slack webhook", "a.js", "const u = '" + slackWebhook + "';\n", "SECRET-SLACK-WEBHOOK", "HIGH", adviceSlackWebhook},
		{"anthropic key", "a.py", "k = '" + anthropicKey + "'\n", "SECRET-ANTHROPIC", "CRITICAL", adviceVendorToken},
		{"openai key with marker", "a.py", "k = '" + openAIKey + "'\n", "SECRET-OPENAI", "CRITICAL", adviceVendorToken},
		{"openai project key", "a.py", "k = '" + openAIProj + "'\n", "SECRET-OPENAI", "CRITICAL", adviceVendorToken},
		{"stripe live key", "a.js", "const k = '" + stripeKey + "';\n", "SECRET-STRIPE", "CRITICAL", adviceVendorToken},
		{"sendgrid key", "a.js", "const k = '" + sendgridKey + "';\n", "SECRET-SENDGRID", "CRITICAL", adviceVendorToken},
		{"google api key", "a.js", "const k = '" + googleKey + "';\n", "SECRET-GOOGLE-API", "HIGH", adviceGoogleAPIKey},
		{"npm token", "a.js", "const k = '" + npmToken + "';\n", "SECRET-NPM", "CRITICAL", adviceVendorToken},
		{"twilio sid", "a.js", "const k = '" + twilioSID + "';\n", "SECRET-TWILIO", "HIGH", adviceTwilioSID},
		{"jwt", "a.ts", "export const t = '" + jwtToken + "';\n", "SECRET-JWT", "MEDIUM", adviceJWT},
		{"connection string to a remote host", "db.py", "dsn = '" + connRemote + "'\n", "SECRET-CONN-STRING", "HIGH", adviceConnRemote},
		{"connection string to localhost", "db.py", "dsn = '" + connLocal + "'\n", "SECRET-CONN-STRING", "MEDIUM", adviceConnLocal},
		{"connection string to a compose service", "db.py", "dsn = '" + connCompose + "'\n", "SECRET-CONN-STRING", "MEDIUM", adviceConnLocal},
		{"keyword assignment", "a.py", "client_secret = '" + rnd24 + "'\n", "SECRET-ASSIGN", "HIGH", adviceAssign},
		{"leak inherits a keyword hit", "main.go", "package main\n\nvar apiKey = \"" + rnd24 + "\"\n\nfunc f() { log.Println(\"key\", apiKey) }\n", "SECRET-LEAK-LOG", "HIGH", adviceLeakLog},
		{"leak inherits a vendor hit", "pay.js", "const k = '" + stripeKey + "';\nconsole.log('stripe', k);\n", "SECRET-LEAK-LOG", "CRITICAL", adviceLeakLog},
		{"leak inherits a local connection string", "db.py", "dsn = '" + connLocal + "'\nprint(dsn)\n", "SECRET-LEAK-LOG", "MEDIUM", adviceLeakLog},
	}

	covered := map[string]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			results := evalFile(t, c.file, c.src)
			var got *core.CheckResult
			for i := range results {
				if results[i].ID == c.id {
					got = &results[i]
				}
			}
			if got == nil {
				t.Fatalf("no %s finding; got %+v", c.id, results)
			}
			if got.Severity != c.severity {
				t.Errorf("%s severity = %s, want %s", c.id, got.Severity, c.severity)
			}
			if got.Suggestion != c.advice {
				t.Errorf("%s suggestion = %q, want %q", c.id, got.Suggestion, c.advice)
			}
			if got.Suggestion == "" || severityWord.MatchString(got.Suggestion) {
				t.Errorf("%s suggestion must be plain advice, not start with a severity: %q", c.id, got.Suggestion)
			}
		})
		covered[c.id] = true
	}
	for _, id := range SecretRuleIDs() {
		if !covered[id] {
			t.Errorf("no severity case for %s: add one when adding a signature", id)
		}
	}
}

func TestSecretAdviceNeverStartsWithASeverity(t *testing.T) {
	for _, advice := range []string{adviceVendorToken, advicePrivateKey, adviceAWSKeyID, adviceAWSKeyPair,
		adviceSlackWebhook, adviceGoogleAPIKey, adviceTwilioSID, adviceJWT, adviceConnRemote, adviceConnLocal,
		adviceAssign, adviceLeakLog} {
		if severityWord.MatchString(advice) {
			t.Errorf("advice starts with a severity word: %q", advice)
		}
	}
}

func TestDetectKnownSecretFormats(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		wantID string
	}{
		{"aws-akid", `const k = "` + awsKeyID + `"`, "SECRET-AWS-AKID"},
		{"github-token", `t := "` + ghToken + `"`, "SECRET-GH-TOKEN"},
		{"github-pat", `x = "` + ghPAT + `"`, "SECRET-GH-PAT"},
		{"slack-token", `t = "` + slackToken + `"`, "SECRET-SLACK-TOKEN"},
		{"slack-webhook", `url = "` + slackWebhook + `"`, "SECRET-SLACK-WEBHOOK"},
		{"stripe", `k = "` + stripeKey + `"`, "SECRET-STRIPE"},
		{"openai", `k = "` + openAIKey + `"`, "SECRET-OPENAI"},
		{"anthropic", `k = "` + anthropicKey + `"`, "SECRET-ANTHROPIC"},
		{"google", `k = "` + googleKey + `"`, "SECRET-GOOGLE-API"},
		{"sendgrid", `k = "` + sendgridKey + `"`, "SECRET-SENDGRID"},
		{"npm", `k = "` + npmToken + `"`, "SECRET-NPM"},
		{"jwt", `t = "` + jwtToken + `"`, "SECRET-JWT"},
		{"private-key", "key := `" + rsaKey + "`", "SECRET-PRIVATE-KEY"},
		{"conn-postgres", `dsn = "` + connRemote + `"`, "SECRET-CONN-STRING"},
		{"conn-mongo-srv", `uri = "` + fake("mongodb+srv://", "user:", "p4ssw0rd", "XYZ", "@cluster0.mongodb.net/test") + `"`, "SECRET-CONN-STRING"},
		{"conn-mysql", `dsn = "` + fake("mysql://", "root:", "hunter2", "pass", "@127.0.0.1:3306/db") + `"`, "SECRET-CONN-STRING"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ids := hitIDs(c.src)
			if !ids[c.wantID] {
				t.Errorf("expected %s, got IDs %v", c.wantID, ids)
			}
		})
	}
}

// Placeholders, templates, samples and names must stay silent.
func TestSecretPlaceholdersAreSilent(t *testing.T) {
	cases := []struct{ name, file, src string }{
		{"openai placeholder", "a.py", `OPENAI_API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxx"` + "\n"},
		{"css class with sk- prefix", "a.js", `const spinner = "sk-fading-circle-animation-wrapper";` + "\n"},
		{"css class in markup", "a.tsx", `export const S = () => <div className="sk-fading-circle-2x sk-circle12" />;` + "\n"},
		{"f-string connection string", "a.py", `DATABASE_URL = f"postgresql://{user}:{password}@{host}/db"` + "\n"},
		{"printf connection string", "a.py", `URI = "mongodb://%s:%s@%s:%s/" % (u, p, h, port)` + "\n"},
		{"python named format", "a.py", `URI = "postgres://%(user)s:%(pw)s@%(host)s/app" % cfg` + "\n"},
		{"env interpolation", "a.go", `url := "postgres://app:${DB_PASSWORD}@db:5432/app"` + "\n"},
		{"shell variable", "a.py", `url = "postgres://app:$DB_PASSWORD@db.internal:5432/app"` + "\n"},
		{"angle placeholder", "a.js", `const u = "postgres://user:<password>@db.internal:5432/app";` + "\n"},
		{"masked password", "a.js", `const u = "postgres://user:****@db.internal:5432/app";` + "\n"},
		{"xxx password", "a.js", `const u = "mysql://root:xxx@db.internal:3306/app";` + "\n"},
		{"changeme password", "a.js", `const u = "postgres://app:changeme@db.internal:5432/app";` + "\n"},
		{"literal word password", "a.js", `const u = "postgres://user:password@db.internal:5432/app";` + "\n"},
		{"documentation host", "a.js", `const u = "` + fake("postgres://", "admin:", "S3cret", "DbPass", "@db.example.com/app") + `";` + "\n"},
		{"k8s secret name", "a.py", `SECRET = "payments-api-db-credentials"` + "\n"},
		{"secret manager path", "a.py", `secret = "projects/my-proj/secrets/db-password/versions/latest"` + "\n"},
		{"secret mounted as a file", "a.py", `db_password = "/run/secrets/db_password_file"` + "\n"},
		{"env var name as a value", "a.py", `token = "GITHUB_TOKEN_FOR_CI"` + "\n"},
		{"ui copy", "a.ts", `const labels = { password: "Enter your password here" };` + "\n"},
		{"description keyed by a rule id", "owasp.go", `var m = map[string]string{"ENTROPY-SECRET": "A02:2021 – Cryptographic Failures"}` + "\n"},
		{"jwt.io sample token", "a.ts", `export const example = "` + jwtIOSample + `";` + "\n"},
		{"jwt.io sample signature", "a.ts", `export const example = "` + fake(jwtHead, ".", b64url(`{"sub":"42"}`), ".", jwtIOSampleSignature) + `";` + "\n"},
		{"aws documentation key", "a.py", `aws_key_id = "` + awsDocKeyID + `"` + "\n"},
		{"slack documentation webhook", "a.js", `const u = "` + fake("https://hooks.slack.com/services/", "T00000000/", "B00000000/", strings.Repeat("X", 24)) + `";` + "\n"},
		{"github token placeholder", "a.js", `const t = "` + fake("gh", "p_", strings.Repeat("x", 36)) + `";` + "\n"},
		{"private key header in parsing code", "pem.go", `if strings.HasPrefix(s, "` + fake("-----BEGIN ", "RSA PRIVATE KEY-----") + `") {` + "\n"},
		{"private key with a placeholder body", "a.py", "KEY = \"\"\"" + fake("-----BEGIN ", "PRIVATE KEY-----") + "\n<paste your key here>\n-----END PRIVATE KEY-----\"\"\"\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evalFile(t, c.file, c.src); len(got) != 0 {
				t.Errorf("false positive: %+v", got)
			}
		})
	}
}

// Cases the detector used to miss.
func TestSecretFormerMisses(t *testing.T) {
	cases := []struct{ name, file, src, wantID string }{
		{"go short assignment", "main.go", "package main\n\nfunc f() {\n\tapi_key := \"" + rnd24 + "\"\n\t_ = api_key\n}\n", "SECRET-ASSIGN"},
		{"keyword after underscore", "a.js", `const API_TOKEN = "` + rnd24 + `";` + "\n", "SECRET-ASSIGN"},
		{"keyword after a dot", "a.py", `self.api_key = "` + rnd24 + `"` + "\n", "SECRET-ASSIGN"},
		{"typed python setting", "settings.py", `api_key: str = "` + rnd24 + `"` + "\n", "SECRET-ASSIGN"},
		{"camel-case name with a symbol-heavy passphrase", "utils.go", "const JWTSecret = \"" + fake("A String Very ", "Strong!!@##$!@#$") + "\"\n", "SECRET-ASSIGN"},
		{"unquoted value in .env", ".env", "PORT=8080\nSESSION_SECRET=" + hex32 + "\n", "SECRET-ASSIGN"},
		{"unquoted value in .env.local", ".env.local", "export JWT_SECRET=" + rnd24 + "\n", "SECRET-ASSIGN"},
		{"unquoted value in .env.production", ".env.production", "API_TOKEN=" + rnd24 + "\n", "SECRET-ASSIGN"},
		{"sqlalchemy driver url", "db.py", `url = "` + fake("postgresql+asyncpg://", "app:", "N7fkq9", "Lz2pW", "@db.internal/app") + `"` + "\n", "SECRET-CONN-STRING"},
		{"redis without a user", "cache.py", `url = "` + fake("redis://", ":SuperSecret", "RedisPass", "@cache.internal:6379/0") + `"` + "\n", "SECRET-CONN-STRING"},
		{"encrypted private key in a string", "keys.js", "const k = " + encryptedKey + ";\n", "SECRET-PRIVATE-KEY"},
		{"pem file", "certs/server.pem", rsaKey, "SECRET-PRIVATE-KEY"},
		{"key file", "server.key", rsaKey, "SECRET-PRIVATE-KEY"},
		{"p8 file", "AuthKey_ABC123.p8", fake("-----BEGIN ", "PRIVATE KEY-----\n", keyBody, "\n-----END PRIVATE KEY-----\n"), "SECRET-PRIVATE-KEY"},
		{"openssh key file", "id_ed25519", fake("-----BEGIN ", "OPENSSH PRIVATE KEY-----\n", keyBody, "\n-----END OPENSSH PRIVATE KEY-----\n"), "SECRET-PRIVATE-KEY"},
		{"pgp key block in yaml", "keys.yaml", "key: |\n  " + fake("-----BEGIN ", "PGP PRIVATE KEY BLOCK-----\n  ", b64Line, "\n  ", rnd64c, "\n  -----END PGP PRIVATE KEY BLOCK-----\n"), "SECRET-PRIVATE-KEY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalFile(t, c.file, c.src)
			if !resultIDs(got)[c.wantID] {
				t.Errorf("expected %s, got %+v", c.wantID, got)
			}
		})
	}
}

func TestEnvTemplatesAreSkipped(t *testing.T) {
	content := fake("DATABASE_URL=", "mysql://root:", "S3cret", "DbPass", "@db.internal:3306/app\n", "SESSION_SECRET=", hex32, "\n")
	for _, name := range []string{".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", ".env.local.example"} {
		t.Run(name, func(t *testing.T) {
			if got := evalFile(t, name, content); len(got) != 0 {
				t.Errorf("%s is a template, not configuration: %+v", name, got)
			}
		})
	}
	if got := evalFile(t, ".env", content); len(got) < 2 {
		t.Errorf(".env must still be scanned, got %+v", got)
	}
}

func TestSecretScanKindFor(t *testing.T) {
	cases := map[string]secretScanKind{
		".env": scanEnvFile, ".env.local": scanEnvFile, "prod.env": scanEnvFile, ".envrc": scanEnvFile,
		"app.py": scanCode, "config.env.ts": scanCode,
		"settings.yaml": scanSignaturesOnly, "server.pem": scanSignaturesOnly, "id_rsa": scanSignaturesOnly,
		".env.example": 0, "example.env": 0, "README.md": 0, "app.envoy": 0, "id_rsa.pub": 0,
	}
	for name, want := range cases {
		got, ok := secretScanKindFor("/repo/"+name, filepath.Ext(name))
		if !ok {
			got = 0
		}
		if got != want {
			t.Errorf("secretScanKindFor(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestIsSecretName(t *testing.T) {
	for name, want := range map[string]bool{
		"api_key": true, "apiKey": true, "APIKey": true, "API_TOKEN": true, "self.api_key": true,
		"this.config.clientSecret": true, "dbPassword": true, "DB_PASS": true, "aws_secret_access_key": true,
		"SECRET_KEY": true, "password": true, "credentials": true, "privateKey": true, "x-api-key": true,
		"tokenizer": false, "SECRET_NAME": false, "passwordField": false, "maxTokens": false,
		"tokenType": false, "secretArn": false, "keyName": false, "monkey": false, "pass": false,
	} {
		if got := isSecretName(name); got != want {
			t.Errorf("isSecretName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLeakToLoggerNeedsTheVariableInALogCall(t *testing.T) {
	src := strings.Join([]string{
		"token := os.Getenv(\"TOKEN\")",
		"log.Printf(\"token loaded: %s\", token)",
		"api_key := \"" + rnd24 + "\"",
		"log.Println(\"key\", api_key)",
		"password := \"" + rnd20 + "Q!\"",
		"login(user, password)",
		"msg := fmt.Sprintf(\"%s\", password)",
	}, "\n") + "\n"
	got := evalFile(t, "s14.go", src)
	byLine := map[int]string{}
	for _, r := range got {
		byLine[r.Line] = r.ID
	}
	if byLine[3] != "SECRET-LEAK-LOG" {
		t.Errorf("api_key is logged on line 4, want SECRET-LEAK-LOG on line 3; got %+v", got)
	}
	if byLine[5] != "SECRET-ASSIGN" {
		t.Errorf("password goes to login() and Sprintf, which are not log sinks; want SECRET-ASSIGN on line 5, got %+v", got)
	}
	if len(got) != 2 {
		t.Errorf("got %d findings, want 2: %+v", len(got), got)
	}
}

func TestSecretLegacyInlineAliases(t *testing.T) {
	plain := "client_secret = '" + rnd24 + "'  # aitriage-ignore: ENTROPY-SECRET\n"
	if got := evalFile(t, "a.py", plain); len(got) != 0 {
		t.Errorf("legacy alias ENTROPY-SECRET must silence the line: %+v", got)
	}
	leak := "client_secret = '" + rnd24 + "'  # aitriage-ignore: ENTROPY-SECRET-LEAK\nprint(client_secret)\n"
	if got := evalFile(t, "a.py", leak); len(got) != 0 {
		t.Errorf("legacy alias ENTROPY-SECRET-LEAK must silence a leak: %+v", got)
	}
	underlying := "client_secret = '" + rnd24 + "'  # aitriage-ignore: SECRET-ASSIGN\nprint(client_secret)\n"
	if got := evalFile(t, "a.py", underlying); len(got) != 0 {
		t.Errorf("a directive for the underlying id must survive the leak escalation: %+v", got)
	}
}

func TestDetectGenericAssignments(t *testing.T) {
	cases := map[string]string{
		"api key blob": `apiKey = "` + fake("a1B2c3D4e5F6", "g7H8i9J0k1L2m3N4o5P6") + `"`,
		"strong pw":    `password = "` + fake("Kx9$mQ2v", "Lp8@nR4wZt") + `"`,
		"secret token": `client_secret: "` + fake("z9Y8x7W6v5U4", "t3S2r1Q0p9O8n7M6l5K4") + `"`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if !hitIDs(src)["SECRET-ASSIGN"] {
				t.Errorf("expected SECRET-ASSIGN for %q, got %+v", src, detectSecretHits(src, scanCode))
			}
		})
	}
}

func TestSecretLeakEvidenceIsRedacted(t *testing.T) {
	hits := detectSecretHits(`k = "`+awsKeyID+`"`, scanCode)
	if len(hits) == 0 {
		t.Fatal("expected a hit")
	}
	if strings.Contains(hits[0].evidence, awsKeyID) {
		t.Errorf("evidence must not contain the full secret: %q", hits[0].evidence)
	}
	if !strings.Contains(hits[0].evidence, "redacted") {
		t.Errorf("evidence should be marked redacted: %q", hits[0].evidence)
	}
}

func TestMultipleSecretsInOneFile(t *testing.T) {
	src := strings.Join([]string{
		`const aws = "` + awsKeyID + `"`,
		`const gh  = "` + ghToken + `"`,
		`const db  = "` + connRemote + `"`,
		`const oai = "` + openAIKey + `"`,
		`apiKey    = "` + fake("a1B2c3D4e5F6", "g7H8i9J0k1L2m3N4o5P6") + `"`,
	}, "\n")

	hits := detectSecretHits(src, scanCode)
	if len(hits) < 5 {
		t.Fatalf("expected all 5 secrets, got %d: %+v", len(hits), hits)
	}
	// Each must be on its own line (1..5) — proves we collect all, not just the first.
	lines := map[int]bool{}
	for _, h := range hits {
		lines[h.line] = true
	}
	for ln := 1; ln <= 5; ln++ {
		if !lines[ln] {
			t.Errorf("no secret detected on line %d; lines hit: %v", ln, lines)
		}
	}
}

func TestNoFalsePositives(t *testing.T) {
	negatives := []string{
		`apiKey = process.env.API_KEY`,
		`token = "${GITHUB_TOKEN}"`,
		`password = "example"`,
		`password = "changeme"`,
		`secret = "your_secret_here"`,
		`url = "https://api.example.com/v1/users"`,
		`name = "getUserProfileByIdAndTenant"`,
		`message = "the quick brown fox jumps over"`,
		`dbHost = "redis://cache.internal:6379/0"`, // host:port, no credentials
		`const greeting = "Hello, world! Welcome."`,
		`if password == "` + rnd24 + `" {`, // a comparison, not an assignment
	}
	for _, src := range negatives {
		t.Run(src, func(t *testing.T) {
			if hits := detectSecretHits(src, scanCode); len(hits) != 0 {
				t.Errorf("false positive on %q: %+v", src, hits)
			}
		})
	}
}
