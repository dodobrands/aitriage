# AITriage Rules Library

**199 security rules** across **11 categories** — covering OWASP Top 10:2025, OWASP LLM Top 10:2025, and framework-specific patterns.

> The engine loads every `*.yaml` file in this directory tree (embedded at compile
> time) as its single source of truth. Regex and AST rules run in the AITriage
> engine; taint-mode rules (`mode: taint`) are compiled into a trusted config and
> executed by the bundled Semgrep during a full audit. Every `id` is unique
> across the catalog, ignoring case (`TestCatalogRuleIDsAreUnique`): baselines,
> suppressions, ignore lists and inline `aitriage-ignore` comments are keyed by
> it, and the engine keeps only the first rule it loads for an `id`.
>
> The per-category counts below are verified against the embedded catalog by a
> test (`TestREADMECountsMatchCatalog`), so they cannot silently drift.

---

## Coverage Matrix

| Category | Rules | Stacks / Languages |
|---|---|---|
| [Universal](./universal/) | 31 | All (JS, TS, Python, Go, C#) |
| [Python](./python/) | 16 | All Python frameworks |
| [Next.js / React](./nextjs/) | 21 | TypeScript, JavaScript, JSX/TSX |
| [FastAPI](./fastapi/) | 20 | Python |
| [Django](./django/) | 16 | Python |
| [Flask](./flask/) | 15 | Python |
| [Express.js](./express/) | 14 | TypeScript, JavaScript |
| [Go](./golang/) | 19 | Go |
| [ASP.NET Core](./aspnetcore/) | 14 | C# |
| [LLM / AI Security](./llm/) | 19 | All (OWASP LLM Top 10:2025) |
| [Docker / IaC](./docker/) | 14 | Dockerfile, YAML |
| **Shannon Entropy** | Built-in | Go, Python, JS/TS and `.env` files (documented in `universal/secrets.yaml`) |

### OWASP Mapping

| OWASP 2025 | Rules |
|---|---|
| A01 Broken Access Control | `*-AUTH`, `*-AUTHZ`, `DJANGO-CSRF-EXEMPT`, `EXPRESS-AUTH` |
| A02 Security Misconfiguration | `DJANGO-DEBUG`, `DJANGO-HOSTS`, `FLASK-DEBUG`, `DOCKER-*` |
| A03 Supply Chain Failures | `ENTR-02` (lockfile), `ENTR-HALLUCINATION`, `LLM-API-KEY-EXPOSED` |
| A04 Cryptographic Failures | `ENTR-WEAK-CRYPTO`, `PY-HASHLIB-WEAK`, `GO-WEAK-TLS` |
| A05 Injection | `*-SQLI`, `*-NOSQL`, `*-CMD-INJECTION`, `PY-SUBPROCESS`, `FAST-XSS` |
| A07 Authentication Failures | `*-AUTH`, `JWT-HARDCODED`, `ENTR-JWT-NONE` |
| A08 Integrity Failures | `PY-PICKLE`, `ASP-DESER`, `FLASK-PICKLE` |
| A09 Logging Failures | `*-LOGGING`, `ENTR-SENSITIVE-LOG` |
| A10 Exceptional Conditions | `FAST-LAZY-EXC`, `GO-ERR-BLANK`, `REACT-HAPPY-PATH` |

| OWASP LLM 2025 | Rules |
|---|---|
| LLM01 Prompt Injection | `LLM-PROMPT-CONCAT` |
| LLM02 Sensitive Info Disclosure | `LLM-SENSITIVE-IN-PROMPT` |
| LLM03 Supply Chain | `LLM-API-KEY-EXPOSED` |
| LLM05 Insecure Output Handling | `LLM-OUTPUT-EXEC`, `LLM-OUTPUT-SQL`, `LLM-NO-OUTPUT-VALIDATION` |
| LLM06 Excessive Agency | `LLM-EXCESSIVE-AGENCY` |
| LLM07 System Prompt Leakage | `LLM-SYSTEM-PROMPT-CLIENT` |
| LLM10 Unbounded Consumption | `LLM-NO-TIMEOUT`, `LLM-NO-TOKEN-LIMIT` |

---

## Rule Schema

Each rule is a YAML object with the following fields:

```yaml
- id: UNIQUE-ID            # e.g., DJANGO-DEBUG, LLM-OUTPUT-EXEC
  name: "Human-Readable Name"
  stack: universal          # Target stack: universal | nextjs | fastapi | django | flask | express | go | aspnetcore
  extensions: [".py"]      # File extensions, or exact file names such as "Dockerfile"
  target: code              # Matching mode (default: code), see below
  exclude_tests: true       # Skip test files (optional)
  exclude_paths: ["seed"]   # Skip paths containing any of these fragments (optional)
  pattern: 'regex_pattern'  # Go RE2 regex; a tree-sitter query for target: ast
  condition: "..."          # Optional, see Conditions
  severity: HIGH            # Required: CRITICAL | HIGH | MEDIUM | LOW
  suggestion: "Fix advice"  # Remediation shown with the finding
```

A rule runs only when its `stack` is `universal` or matches the detected (or
`--stack`) stack. A built-in rule without a severity defaults to `LOW`.

### Target Modes

| Mode | Description |
|---|---|
| `code` | Default. Regex over the source with comments and string literals removed |
| `all` | Regex over the full file content |
| `docs` | Regex over comments and string literals only |
| `ast` | Tree-sitter query (Go, Python, JavaScript/JSX, TypeScript/TSX) |
| `filename` | With `condition: missing`: alert when no scanned file name matches the pattern |
| `condition` | Engine-specific check; currently `condition: large_file` (files over 1,500 lines) |
| `entropy-analysis` | Documentation-only entry for a check implemented in Go (Shannon entropy) |

`raw` and `lines_percentage` still appear in some catalog rules but have no
dedicated implementation: they are matched like `code` (like `all` under
`required_pattern`).

### Conditions

| Condition | Description |
|---|---|
| `required_pattern` | Alert if files with the rule's extensions exist but none contains the pattern (missing security control) |
| `not_contains:X` | Alert on a match only if the file does not also contain X (case-insensitive) |
| `missing` | With `target: filename`: alert if no file name matches the pattern |
| `missing_lockfile` | Alert if a project uses a package manager (its manifest is present) but has no lockfile for it; see `ecosystems` below |
| `large_file` | With `target: condition`: alert on files over 1,500 lines |

`contains:X` and `threshold:N` also appear in the catalog, but the engine does
not evaluate them yet: those rules match as if no condition were set.

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
2. **Use Go RE2 syntax** — no lookarounds or backreferences; `grep -P` accepts
   patterns RE2 rejects, and an invalid pattern silently degrades to a literal
   substring match (a `required_pattern` rule with one never fires)
3. **Map to OWASP** — reference the relevant OWASP category in the suggestion
4. **Set the severity** — `severity:` (CRITICAL / HIGH / MEDIUM / LOW)
5. **Actionable fix** — always explain the remediation, not just the problem

---

## Contributing

1. Fork the repository
2. Add rules to the appropriate `rules/<category>/security.yaml`
3. Add a test case (an engine test in `internal/engine/` or a fixture under `testdata/synthetic/`)
4. Update the counts above and run `go test ./rules/`
5. Verify with `aitriage scan <fixture> --stack <stack>`
6. Submit a PR with the rule and its test

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full workflow.
