# AITriage Rules Library

**193 security rules** across **11 categories** — covering OWASP Top 10:2025, OWASP LLM Top 10:2025, and framework-specific patterns.

> The engine loads every `*.yaml` file in this directory tree (embedded at compile
> time) as its single source of truth. Regex and AST rules run in the AITriage
> engine; taint-mode rules (`mode: taint`) are compiled into a trusted config and
> executed by the bundled Semgrep during a full audit. Every `id` is unique
> across the catalog, ignoring case (`TestCatalogRuleIDsAreUnique`): baselines,
> suppressions, ignore lists and inline `aitriage-ignore` comments are keyed by
> it, and the engine keeps only the first rule it loads for an `id`.
>
> The per-category counts below are verified against the embedded catalog by a
> test (`TestREADMECountsMatchCatalog`), so they cannot silently drift. Every
> rule compiles, declares its severity, region filter and metadata
> (`TestCatalogRulesAreWellFormed`), and has fixtures that must and must not
> trigger it (`TestRuleFixtures`, see [`testdata/rules`](../testdata/rules/)).

---

## Coverage Matrix

| Category | Rules | Stacks / Languages |
|---|---|---|
| [Universal](./universal/) | 30 | All (JS, TS, Python, Go, C#) |
| [Python](./python/) | 16 | All Python frameworks |
| [Next.js / React](./nextjs/) | 21 | TypeScript, JavaScript, JSX/TSX |
| [FastAPI](./fastapi/) | 15 | Python |
| [Django](./django/) | 16 | Python |
| [Flask](./flask/) | 15 | Python |
| [Express.js](./express/) | 14 | TypeScript, JavaScript |
| [Go](./golang/) | 19 | Go |
| [ASP.NET Core](./aspnetcore/) | 14 | C# |
| [LLM / AI Security](./llm/) | 19 | All (OWASP LLM Top 10:2025) |
| [Docker / IaC](./docker/) | 14 | Dockerfile, YAML |
| **Secret detector** | Built-in | Vendor token formats and secret assignments in code, `.env`, config and key files (implemented in Go, documented in `universal/secrets.yaml`) |

### OWASP Mapping

Each rule names its category in `metadata.owasp`; this table lists examples.

| OWASP 2025 | Example rules |
|---|---|
| A01 Broken Access Control | `*-AUTH`, `ASP-AUTH-MISSING`, `NEXT-SERVER-ACTION-EXPOSED`, path traversal, SSRF and open redirect rules |
| A02 Security Misconfiguration | `DJANGO-DEBUG`, `FLASK-DEBUG`, `FAST-DEBUG`, CORS rules, `DOCKER-*`, security header policies |
| A03 Software Supply Chain Failures | `ENTR-02` (lockfile), `JS-UNSAFE-DESERIALIZE` |
| A04 Cryptographic Failures | `ENTR-WEAK-CRYPTO`, `PY-HASHLIB-WEAK`, `ASP-WEAK-CRYPTO`, TLS verification rules |
| A05 Injection | `*-SQLI`, `*-NOSQL`, command injection, `FAST-XSS`, `REACT-XSS`, `FLASK-SSTI` |
| A06 Insecure Design | rate-limit policies, `ENTR-INSECURE-RANDOM` |
| A07 Authentication Failures | hardcoded credential rules, `ENTR-JWT-NONE`, `PY-JWT-NOVERIFY`, `GO-JWT-UNVERIFIED` |
| A08 Software or Data Integrity Failures | `PY-PICKLE`, `FLASK-PICKLE`, `ASP-DESER`, `PY-YAML-LOAD` |
| A09 Security Logging and Alerting Failures | `ENTR-SENSITIVE-LOG`, `PY-LOGGING-SENSITIVE`, `ASP-LOGGING-SENSITIVE` |
| A10 Mishandling of Exceptional Conditions | `FAST-LAZY-EXC`, `GO-ERR-BLANK` |

| OWASP LLM 2025 | Rules |
|---|---|
| LLM01 Prompt Injection | `LLM-PROMPT-CONCAT`, `LLM-RAG-UNDELIMITED`, `ENTR-20`, `ENTR-AI-CONFIG-HIDDEN-UNICODE` |
| LLM02 Sensitive Information Disclosure | `LLM-SENSITIVE-IN-PROMPT` |
| LLM03 Supply Chain | `LLM-TRUST-REMOTE-CODE`, `LLM-UNSAFE-MODEL-LOAD`, `LLM-MODEL-UNPINNED` |
| LLM05 Improper Output Handling | `LLM-OUTPUT-EXEC`, `LLM-OUTPUT-SQL`, `LLM-OUTPUT-HTML`, `LLM-NO-OUTPUT-VALIDATION` |
| LLM06 Excessive Agency | `LLM-EXCESSIVE-AGENCY`, `LLM-TOOL-SHELL-EXEC`, `LLM-DANGEROUS-AGENT-TOOL` |
| LLM07 System Prompt Leakage | `LLM-SYSTEM-PROMPT-CLIENT` |
| LLM08 Vector and Embedding Weaknesses | `LLM-VECTOR-NO-TENANT-FILTER` |
| LLM10 Unbounded Consumption | `LLM-API-KEY-EXPOSED`, `LLM-NO-TIMEOUT`, `LLM-NO-TOKEN-LIMIT`, `LLM-AGENT-UNBOUNDED` |

LLM04 (data and model poisoning) and LLM09 (misinformation) have no static
signal in source code and are not covered.

---

## Rule Schema

Each rule is a YAML object with the following fields:

```yaml
- id: UNIQUE-ID            # e.g., DJANGO-DEBUG, LLM-OUTPUT-EXEC
  name: "Human-Readable Name"
  stack: universal          # Target stack: universal | nextjs | fastapi | django | flask | express | go | aspnetcore
  extensions: [".py"]      # Extensions, exact file names ("Dockerfile") or base-name globs ("Dockerfile.*")
  target: all               # Matching mode, see below
  regions: code             # Where a match may start: code | code_and_strings | comments | all
  exclude_tests: true       # Skip test files (optional)
  exclude_paths: ["seed"]   # Skip paths containing any of these fragments (optional)
  pattern: 'regex_pattern'  # Go RE2 regex; a tree-sitter query for target: ast
  condition: "..."          # Optional, see Conditions
  severity: HIGH            # Required: CRITICAL | HIGH | MEDIUM | LOW
  metadata:
    cwe: "CWE-89"           # Required for subcategory vuln
    owasp: "A05:2025"       # OWASP Top 10 2025 (Axx:2025) or LLM Top 10 2025 (LLMxx:2025); required for vuln
    confidence: high        # high | medium | low: how likely a match is a real issue
    subcategory: vuln       # vuln | audit (worth a look) | policy (a required control is absent) | quality (no security impact)
  suggestion: "Fix advice"  # Remediation shown with the finding
```

Findings carry the rule's CWE and OWASP category, and SARIF rule descriptors
get the `external/cwe/cwe-<n>` tag used by GitHub code scanning.

`subcategory: quality` marks a rule about code quality, maintainability or
hygiene that has no security impact in any project: `ENTR-04`,
`ENTR-AI-RESIDUE` and `ENTR-ZOMBIE-CODE` (comments), `ENTR-07` (TypeScript
type checks), `ENTR-12` (file length), `FAST-LAZY-EXC` (swallowed exception,
the same defect as Bandit `B110`) and `FAST-SYNC-ASYNC` (a blocking call in an
async function). Their findings carry the subcategory, and under the default
`quality_findings: report` they are triaged and reported but neither scored nor
gating; `quality_findings: block` restores gating. A quality rule must be `LOW`
and is listed with its reason in `catalog_strict_test.go`.

A rule runs only when its `stack` is `universal` or matches the detected (or
`--stack`) stack. Every built-in rule declares its severity in `severity:`
(`TestCatalogRulesDeclareSeverity`); the suggestion text carries no severity.

Severity follows one rubric: CRITICAL only when the pattern sees untrusted
input reaching a code, command or deserialization sink (or a live secret);
HIGH for likely exploitable issues the pattern identifies precisely; MEDIUM
for missing hardening or limited impact; LOW for hygiene. A rule that cannot
see where its input comes from is rated one level lower.

### Target Modes

| Mode | Description |
|---|---|
| `all` | Regex over the raw file; `regions` decides where a match may start |
| `docs` | Regex over comments and string literals only |
| `ast` | Tree-sitter query (Go, Python, JavaScript/JSX, TypeScript/TSX); inline `aitriage-ignore` applies |
| `filename` | With `condition: missing`: alert when no scanned file name matches the pattern |
| `condition` | Engine-specific check; currently `condition: large_file` (files over 1,500 lines) |
| `entropy-analysis` | Documentation-only entry for a check implemented in Go |

### Regions

The pattern always runs over the raw file, so it can span code and string
literals, and the reported line is the real one. The first match that starts
in an allowed region and is not silenced by an inline directive is reported.

| `regions` | A match may start in |
|---|---|
| `code` | Code only: not in a comment or a string literal |
| `code_and_strings` | Code or a string literal (SQL text, header values, config values, Dockerfile exec form) |
| `comments` | Comments only (AI-residue markers) |
| `all` | Anywhere (secrets, private keys, AI instruction files) |

Comment and string syntax comes from the file type; YAML, `.env`, TOML and INI
files use `#` comments. Custom and pack rules without `regions` keep the older
behaviour of their `target` (`code`: comments and strings removed).

### Conditions

| Condition | Description |
|---|---|
| `required_pattern` | Alert if files with the rule's extensions exist but none contains the pattern (in an allowed region) |
| `not_contains:A\|B` | Drop the file's match if any token appears outside comments (case-insensitive) |
| `contains:A\|B` | Keep the file's match only if a token appears outside comments |
| `missing` | With `target: filename`: alert if no file name matches the pattern |
| `missing_lockfile` | Alert if a project uses a package manager (its manifest is present) but has no lockfile for it; see `ecosystems` below |
| `large_file` | With `target: condition`: alert on files over 1,500 lines |

`pattern-not` is evaluated on its own over the file without comments: a file
that matches it produces no finding.

### Lockfile Ecosystems (`condition: missing_lockfile`)

```yaml
  ecosystems:
    - name: "npm"                          # Shown in the evidence
      manifests: ["package.json"]          # Any of them proves the project uses the ecosystem
      lockfiles: ["package-lock.json", "yarn.lock"]  # Any of them pins it
      workspace_root: true                 # Optional: a declared npm-family workspace root lockfile also counts
```

`workspace_root: true` currently supports npm/yarn/bun membership declared in `package.json` (`workspaces` array or `workspaces.packages`) and pnpm membership in `pnpm-workspace.yaml`. Patterns support `*`, `?`, character classes and `**`, with exclusions. Only a declared member can use the ancestor lockfile, and search stops at the scan root. Other ecosystems retain their per-project check; their workspace semantics need separate validation before enabling inheritance.

### Taint Mode (`mode: taint`)

A rule with `mode: taint` is a dataflow rule executed by the **bundled Semgrep**,
not by the regex/AST engine. It declares Semgrep `pattern-sources`,
`pattern-sinks` and optional `pattern-sanitizers` (verbatim Semgrep sub-syntax:
`pattern`, `patterns`, `pattern-either`, `pattern-inside`, `focus-metavariable`,
…). During a full audit these rules are compiled from the embedded catalog into a
trusted, owner-only config and run alongside Semgrep `auto`; taint flows through
local variables, f-strings, `.format()` and `%`-formatting automatically. Loading
or executing the mandatory taint rules is fail-closed — a full audit errors
rather than run without them. Example: `FAST-XSS` (reflected XSS in FastAPI).

---

## Writing Custom Rules

Add rules under the `rules:` key of `.aitriage.yaml` in your project root:

```yaml
rules:
  - id: MY-CUSTOM-RULE
    name: "Describe the vulnerability"
    stack: universal
    extensions: [".py", ".js"]
    target: code
    pattern: 'dangerous_function\('
    severity: HIGH
    suggestion: "Explain why this is dangerous and how to fix it."
```

Custom rules accept `id`, `name`, `stack`, `extensions`, `target`, `pattern`,
`condition`, `severity` and `suggestion`. Rule packs installed with
`aitriage rules install ./my-rules/` are copied to `~/.aitriage/packs/` and
loaded when the engine runs natively on that machine (for example
`aitriage scan`); a pack rule whose `id` already exists in the built-in catalog
is ignored. Custom and pack rules should set `severity:`. For compatibility,
a pack or custom rule without it may still start its suggestion with
`CRITICAL: `, `HIGH: `, `MEDIUM: ` or `LOW: `; with neither, the rule runs as
`LOW` and the engine logs a warning.

### Guidelines

1. **Be specific** — narrow patterns reduce false positives
2. **Use Go RE2 syntax** — no lookarounds or backreferences, and `(?m)` for
   `^`/`$` at line boundaries; `grep -P` accepts patterns RE2 rejects. A pack
   rule with an invalid pattern is matched as a literal string, with a warning
3. **Choose regions** — `code` for API calls, `code_and_strings` when the
   pattern targets literal text, `all` only for secrets and documents
4. **Set severity and metadata** — `severity:` plus CWE and OWASP 2025 in `metadata`
5. **Actionable fix** — always explain the remediation, not just the problem

---

## Contributing

1. Fork the repository
2. Add rules to the appropriate `rules/<category>/security.yaml`
3. Add bad and good fixtures under `testdata/rules/<RULE-ID>/` (see its README)
4. Update the counts above and run `go test ./rules/`
5. Verify with `aitriage scan <fixture> --stack <stack>`
6. Submit a PR with the rule and its test

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full workflow.
