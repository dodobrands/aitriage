package nfr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ruleByID(t *testing.T, id string) Rule {
	t.Helper()
	rules, err := getRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s is missing from the catalog", id)
	return Rule{}
}

// NFR severities feed the gate and the health score. Every rule must be
// pinned here; adding a rule without a severity case fails the test.
func TestNFRRuleSeverities(t *testing.T) {
	want := map[string]string{
		"NFR-API-001": "MEDIUM", // missing hardening, often enforced at the gateway
		"NFR-API-003": "MEDIUM",
		"NFR-ENV-001": "LOW", // documentation hygiene
		"NFR-ENV-002": "HIGH",
	}
	rules, err := getRules()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rules {
		seen[r.ID] = true
		sev, ok := want[r.ID]
		if !ok {
			t.Errorf("%s has no pinned severity: add it to this test", r.ID)
			continue
		}
		if r.Severity != sev {
			t.Errorf("%s severity = %q, want %q", r.ID, r.Severity, sev)
		}
		if r.Check == "file_contains" && r.compiledRegex == nil {
			t.Errorf("%s pattern does not compile", r.ID)
		}
		if r.AppliesPattern != "" && r.compiledAppliesPattern == nil {
			t.Errorf("%s applies_pattern does not compile", r.ID)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("rule %s is missing from the catalog", id)
		}
	}
}

func TestRateLimitPresencePattern(t *testing.T) {
	re := ruleByID(t, "NFR-API-001").compiledRegex
	for _, src := range []string{
		`const rateLimit = require("express-rate-limit")`,
		`app.use(limiter)`,
		`from slowapi import Limiter`,
		`import "golang.org/x/time/rate"`,
		`RATE_LIMIT_PER_MINUTE = 60`,
		`@throttle(10)`,
		`new RateLimiter({ points: 5 })`,
		`lmt := tollbooth.NewLimiter(1, nil)`,
	} {
		if !re.MatchString(src) {
			t.Errorf("rate limiting not recognised in %q", src)
		}
	}
	for _, src := range []string{
		`def generate_limit(n): return n`,
		`// we need an accurate limit here`,
		`const limits = { upload: 10 }`,
	} {
		if re.MatchString(src) {
			t.Errorf("%q is not rate limiting", src)
		}
	}
}

func TestAuthPresencePattern(t *testing.T) {
	re := ruleByID(t, "NFR-API-003").compiledRegex
	for _, src := range []string{
		`def me(user = Depends(get_current_user)):`,
		`def me(user = Depends(get_current_active_user)):`,
		`oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")`,
		`app.use(passport.initialize())`,
		`const jwt = require("jsonwebtoken")`,
		`claims, err := jwt.ParseWithClaims(raw, &c, key)`,
		`router.use(authMiddleware)`,
		`@UseGuards(JwtAuthGuard)`,
		`@login_required`,
		`import { auth } from "@clerk/nextjs/server"`,
		`req.headers.authorization`,
	} {
		if !re.MatchString(src) {
			t.Errorf("authentication not recognised in %q", src)
		}
	}
	for _, src := range []string{
		`__author__ = "Jane Doe"`,
		`# Copyright 2024 The Project Authors`,
		`const { useAuthor } = hooks`,
		`app.use(middleware.logger())`,
	} {
		if re.MatchString(src) {
			t.Errorf("%q is not authentication", src)
		}
	}
}

func TestRouteAppliesPatternNeedsAPath(t *testing.T) {
	re := ruleByID(t, "NFR-API-001").compiledAppliesPattern
	for _, src := range []string{`@app.get("/items")`, `router.post('/login', handler)`, "app.delete(`/x/${id}`, h)", `app = FastAPI()`, `http.HandleFunc("/", h)`} {
		if !re.MatchString(src) {
			t.Errorf("endpoint not recognised in %q", src)
		}
	}
	for _, src := range []string{`settings = app.get('config')`, `value = router.get(key)`} {
		if re.MatchString(src) {
			t.Errorf("%q is not an endpoint", src)
		}
	}
}

func TestEnvExampleAlternativesSatisfyNFRENV001(t *testing.T) {
	rule := ruleByID(t, "NFR-ENV-001")
	for _, name := range []string{".env.example", ".env.sample", ".env.template", "example.env", ".env.dist"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "main.py"), "import os\nTOKEN = os.getenv('TOKEN')\n")
			writeFile(t, filepath.Join(dir, name), "TOKEN=\n")
			triggered, _, err := evaluateRule(dir, rule)
			if err != nil {
				t.Fatal(err)
			}
			if triggered {
				t.Errorf("%s documents the variables, NFR-ENV-001 must not fire", name)
			}
		})
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.py"), "import os\nTOKEN = os.getenv('TOKEN')\n")
	if triggered, _, _ := evaluateRule(dir, rule); !triggered {
		t.Error("NFR-ENV-001 must fire when no template exists")
	}
}

func TestNFRENV002ChecksLocalAndProductionEnvFiles(t *testing.T) {
	rule := ruleByID(t, "NFR-ENV-002")
	for _, name := range []string{".env", ".env.local", ".env.production"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			initRepo(t, dir)
			writeFile(t, filepath.Join(dir, name), "API_KEY=secret\n")
			gitRun(t, dir, "add", name)
			triggered, detail, err := evaluateRule(dir, rule)
			if err != nil {
				t.Fatal(err)
			}
			if !triggered || detail != name {
				t.Errorf("tracked %s: triggered=%v detail=%q", name, triggered, detail)
			}
		})
	}

	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, filepath.Join(dir, ".gitignore"), ".env*\n")
	for _, name := range []string{".env", ".env.local", ".env.production"} {
		writeFile(t, filepath.Join(dir, name), "API_KEY=secret\n")
	}
	if triggered, detail, _ := evaluateRule(dir, rule); triggered {
		t.Errorf("ignored env files were reported: %q", detail)
	}
}

func TestNFRENV002MessageNamesTheExposedFile(t *testing.T) {
	dir := t.TempDir()
	initRepo(t, dir)
	writeFile(t, filepath.Join(dir, ".gitignore"), ".env\n")
	writeFile(t, filepath.Join(dir, ".env"), "A=1\n")
	writeFile(t, filepath.Join(dir, ".env.production"), "A=1\n")
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	findings, err := CheckNFR(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "NFR-ENV-002" {
			if !strings.HasSuffix(f.Message, "(.env.production)") {
				t.Errorf("message should name the exposed file only: %q", f.Message)
			}
			return
		}
	}
	t.Fatal("unignored .env.production was not reported")
}
