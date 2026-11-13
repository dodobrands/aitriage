package deployaudit

import (
	"strings"
	"testing"
)

// composeStack is a local stack: a database whose password repeats its user
// name, a root password made of a default word, an application whose password
// is derived from the database user set in list form, and values that are not
// literals at all. Only the session and cache secrets look like live secrets.
const composeStack = `services:
  catalog-db:
    image: registry.example.test/library/mariadb:11
    environment:
      MARIADB_DATABASE: catalog
      MARIADB_USER: catalog
      MARIADB_PASSWORD: catalog
      MARIADB_ROOT_PASSWORD: Admin2024!
  ledger:
    image: ledger-service:dev
    environment:
      - LEDGER_DB_USER=ledger
  worker:
    image: catalog-worker:dev
    environment:
      WORKER_DB_PASSWORD: ledger_pass
      SESSION_SECRET: 8f2Kq9vLx3TzR7mW4pYc
      CACHE_PASSWORD: correct-horse-battery-staple
      SIGNING_SECRET: ${SIGNING_SECRET}
      BACKUP_PASSWORD: $BACKUP_PASSWORD
      SMTP_PASSWORD_FILE: /run/secrets/smtp_password
secrets:
  smtp_password:
    file: ./secrets/smtp_password.txt
`

// A committed password used to be a CRITICAL hardcoded secret whatever its
// value, so a local stack's default passwords outweighed every real problem
// in the score. Default and weak values are now a MEDIUM default credential;
// values that may be live secrets stay CRITICAL, and values Compose resolves
// when the stack starts are not reported.
func TestComposeReportsDefaultCredentialsApartFromSecrets(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"docker-compose.yml": composeStack})

	findings, err := AuditDeployFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]DeployFinding{}
	for _, f := range findings {
		key, _, _ := strings.Cut(f.Evidence, ":")
		got[key] = f
	}
	want := map[string]struct{ issue, severity string }{
		"MARIADB_PASSWORD":      {IssueComposeDefaultCredential, "MEDIUM"},
		"MARIADB_ROOT_PASSWORD": {IssueComposeDefaultCredential, "MEDIUM"},
		"WORKER_DB_PASSWORD":    {IssueComposeDefaultCredential, "MEDIUM"},
		"SESSION_SECRET":        {IssueComposeHardcodedSecret, "CRITICAL"},
		"CACHE_PASSWORD":        {IssueComposeHardcodedSecret, "CRITICAL"},
	}
	if len(got) != len(want) || len(findings) != len(want) {
		t.Fatalf("findings = %+v; want one for each of %v", findings, want)
	}
	for key, w := range want {
		f, ok := got[key]
		if !ok {
			t.Errorf("%s was not reported", key)
			continue
		}
		if f.Issue != w.issue || f.Severity != w.severity {
			t.Errorf("%s = %s %s; want %s %s", key, f.Issue, f.Severity, w.issue, w.severity)
		}
	}
	if advice := got["MARIADB_PASSWORD"].Advice; advice == got["SESSION_SECRET"].Advice || !strings.Contains(advice, "${MY_PASSWORD}") {
		t.Errorf("default credential advice = %q; want its own, pointing at the environment", advice)
	}
	// The evidence keeps the format the hardcoded secret always had: it is
	// part of a baseline fingerprint (see PreviousIssue).
	if ev := got["MARIADB_PASSWORD"].Evidence; ev != "MARIADB_PASSWORD: catalog" {
		t.Errorf("evidence = %q", ev)
	}
}

// randomUser is a user name generated like a password; the compose fixtures
// repeat it as the password.
const randomUser = "u8Kq9zX2mW7pL4vT"

func TestWeakCredentialCategories(t *testing.T) {
	context := map[string]bool{"catalog": true, "catalog-db": true, "mariadb": true, strings.ToLower(randomUser): true}
	weak := map[string]string{
		"postgres":             "documented default of an image",
		"Postgres!":            "default with a symbol appended",
		"password1":            "placeholder word with a counter",
		"Admin2024!":           "default account name with a year",
		"guest_password":       "default account name with a password word",
		"adminpass":            "default account name with a password word",
		"testpass123":          "placeholder word with a password word and digits",
		"P@ssw0rd":             "top of breached-password lists",
		"minioadmin":           "documented default of an image",
		"my-secret-pw":         "documented example of an image",
		"YourStrong@Passw0rd":  "documented example of an image, random-looking as it is",
		"example":              "placeholder",
		"changeme":             "placeholder",
		"examplepass":          "placeholder word with a password word",
		"your-db-password":     "placeholder word as a whole word",
		"your_password_here":   "placeholder word as a whole word",
		"<database password>":  "documentation placeholder",
		"change_me_please":     "placeholder words as whole words",
		"db-pass-xxxx":         "a run of x as a whole word",
		"secret-****":          "a run of * as a whole word",
		"xxxxxxxxxx":           "repetitive",
		"12345678":             "sequential",
		"87654321":             "sequential",
		"abcdefgh":             "sequential",
		"abcdefghijklmnopqrst": "sequential, random-looking as it is",
		"zzzzzzzz":             "repetitive",
		"123":                  "sequential",
		"catalog":              "the user and database name",
		"Catalog2024":          "the user name with a year",
		"catalog_password":     "the user name with a password word",
		"catalog-db":           "the service name",
		"mariadb_pass":         "the image name with a password word",
	}
	for value, why := range weak {
		if !isWeakCredential(value, context) {
			t.Errorf("isWeakCredential(%q) = false; want true (%s)", value, why)
		}
	}
	strong := map[string]string{
		"8f2Kq9vLx3TzR7mW4pYc":              "random",
		"correct-horse-battery-staple":      "a passphrase",
		"supersecret":                       "no default word on its own",
		"admin_8f2Kq9vLx3Tz":                "a default word with a random part",
		"catalog-8f2Kq9vLx3Tz":              "a name with a random part",
		"Tr0ub4dor&3":                       "chosen, not a default",
		"password_8f2Kq9vLx3Tz":             "a placeholder word with a random part",
		"q8#Kz!2":                           "short, but random: a short password is a credential",
		"Zx9!":                              "short, but random",
		"12":                                "too short to be a run",
		"aXxxxQ9zLm2Rt7VwPk3s":              "a run of x inside a random value",
		"hSampleq9zLm2Rt7VwPk3s8Fz":         "a placeholder word inside a random value",
		"NoFakeNews-Kq9zX2mW7pL4":           "a placeholder word inside a word",
		"exchangemeter":                     "\"changeme\" inside a word",
		"nofakenews":                        "\"fake\" inside a word",
		"resampled":                         "\"sample\" inside a word",
		"dummy-Kq9zX2mW7pL4vT8nR":           "a placeholder word next to a random part",
		"Kq9#zX2!mW7$pL4...vT8":             "an ellipsis inside a random value",
		"k8Fz***Qp2LmZ9xRtV7":               "stars inside a random value",
		"Your-Strong-Passphrase-Kq9zX2":     "a placeholder word in a random passphrase",
		"exchangemeter-orbit-velvet-quartz": "\"changeme\" inside a word",
		"correct-horse-battery-sample":      "a placeholder word in a passphrase random enough",
		randomUser:                          "a random user name repeated as the password",
		randomUser + "_pass":                "a random user name with a password word",
	}
	for value, why := range strong {
		if isWeakCredential(value, context) {
			t.Errorf("isWeakCredential(%q) = true; want false (%s): a value that may be a live secret must stay CRITICAL", value, why)
		}
	}
}

// The values above, through the audit of a Compose file: each stays a
// CRITICAL hardcoded secret, also when it repeats a random user name the file
// sets.
func TestComposeKeepsGeneratedValuesCritical(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"docker-compose.yml": `services:
  store-db:
    image: postgres:16
    environment:
      POSTGRES_USER: ` + randomUser + `
      POSTGRES_PASSWORD: ` + randomUser + `
      POSTGRES_DB: store
  store:
    image: store-api:dev
    environment:
      STORE_DB_PASSWORD: "dummy-Kq9zX2mW7pL4vT8nR"
      SESSION_SECRET: "exchangemeter-orbit-velvet-quartz"
      SIGNING_SECRET: "k8Fz***Qp2LmZ9xRtV7"
      CACHE_PASSWORD: "q8#Kz!2"
      ADMIN_PASSWORD: postgres
`})
	findings, err := AuditDeployFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]DeployFinding{}
	for _, f := range findings {
		key, _, _ := strings.Cut(f.Evidence, ":")
		got[key] = f
	}
	for _, key := range []string{"POSTGRES_PASSWORD", "STORE_DB_PASSWORD", "SESSION_SECRET", "SIGNING_SECRET", "CACHE_PASSWORD"} {
		if f := got[key]; f.Issue != IssueComposeHardcodedSecret || f.Severity != "CRITICAL" {
			t.Errorf("%s = %s %s; want a CRITICAL %s", key, f.Issue, f.Severity, IssueComposeHardcodedSecret)
		}
	}
	if f := got["ADMIN_PASSWORD"]; f.Issue != IssueComposeDefaultCredential || f.Severity != "MEDIUM" {
		t.Errorf("ADMIN_PASSWORD = %s %s; want the default credential at MEDIUM", f.Issue, f.Severity)
	}
}

func TestCredentialStem(t *testing.T) {
	for value, want := range map[string]string{
		"admin123":           "admin",
		"postgres!":          "postgres",
		"admin2024!":         "admin",
		"guestpass":          "guest",
		"inventory_password": "inventory",
		"service-pw":         "service",
		// At most six trailing digits and symbols are taken.
		"admin1234567": "admin1",
		// A password word alone is its own base.
		"password": "password",
	} {
		if got := credentialStem(value); got != want {
			t.Errorf("credentialStem(%q) = %q; want %q", value, got, want)
		}
	}
}

func TestComposeLiteral(t *testing.T) {
	cases := []struct {
		key, value string
		want       bool
	}{
		{"DB_PASSWORD", "", false},
		{"DB_PASSWORD", "${DB_PASSWORD}", false},
		{"DB_PASSWORD", "${DB_PASSWORD:-fallback}", false},
		{"DB_PASSWORD", "$DB_PASSWORD", false},
		// "$$" is a literal dollar sign: the value is committed.
		{"DB_PASSWORD", "$$DB_PASSWORD", true},
		{"DB_PASSWORD", "pa$word", true},
		{"DB_PASSWORD_FILE", "/run/secrets/db_password", false},
		// Without a path the image cannot read a file; keep reporting it.
		{"DB_PASSWORD_FILE", "hunter22", true},
		{"DB_PASSWORD", "/run/secrets/db_password", true},
	}
	for _, tc := range cases {
		if got := composeLiteral(tc.key, tc.value); got != tc.want {
			t.Errorf("composeLiteral(%q, %q) = %t; want %t", tc.key, tc.value, got, tc.want)
		}
	}
}

func TestComposeContextNames(t *testing.T) {
	for key, want := range map[string]bool{
		"MYSQL_USER": true, "POSTGRES_DB": true, "MONGO_INITDB_ROOT_USERNAME": true, "APP_DB_NAME": true,
		"MARIADB_DATABASE": true, "SERVICE_NAME": false, "DB_PASSWORD": false, "USER_AGENT": false,
	} {
		if got := namesAccount(key); got != want {
			t.Errorf("namesAccount(%q) = %t; want %t", key, got, want)
		}
	}
	for ref, want := range map[string]string{
		"postgres":    "postgres",
		"postgres:16": "postgres",
		"registry.example.test:5000/team/catalog-api:1.2@sha256:0123": "catalog-api",
		"${REGISTRY}/catalog-api:${TAG}":                              "catalog-api",
	} {
		if got := imageName(ref); got != want {
			t.Errorf("imageName(%q) = %q; want %q", ref, got, want)
		}
	}
}

// Ignore rules, inline directives, baselines and dismissals written for the
// id a default credential had before must keep covering it.
func TestPreviousIssue(t *testing.T) {
	if got := PreviousIssue(IssueComposeDefaultCredential); got != IssueComposeHardcodedSecret {
		t.Errorf("PreviousIssue(%s) = %q", IssueComposeDefaultCredential, got)
	}
	for _, issue := range []string{IssueComposeHardcodedSecret, "dockerfile_root_user", ""} {
		if got := PreviousIssue(issue); got != "" {
			t.Errorf("PreviousIssue(%q) = %q; want none", issue, got)
		}
	}
}
