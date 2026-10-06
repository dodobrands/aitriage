# AITriage Rules Library

**181 security rules** across **11 categories** — covering OWASP Top 10:2025, OWASP LLM Top 10:2025, and framework-specific patterns.

> The engine loads every `*.yaml` file in this directory tree (embedded at compile
> time) as its single source of truth. Regex and AST rules run in the AITriage
> engine; taint-mode rules (`mode: taint`) are compiled into a trusted config and
> executed by the bundled Semgrep during a full audit.
>
> The per-category counts below are verified against the embedded catalog by a
> test (`TestREADMECountsMatchCatalog`), so they cannot silently drift.

---

## Coverage Matrix

| Category | Rules | Stacks / Languages |
|---|---|---|
| [Universal](./universal/) | 32 | All (JS, TS, Python, Go, C#) |
| [Python](./python/) | 12 | All Python frameworks |
| [Next.js / React](./nextjs/) | 28 | TypeScript, JavaScript, JSX/TSX |
| [FastAPI](./fastapi/) | 20 | Python |
| [Django](./django/) | 16 | Python |
| [Flask](./flask/) | 14 | Python |
| [Express.js](./express/) | 14 | TypeScript, JavaScript |
| [Go](./golang/) | 14 | Go |
| [ASP.NET Core](./aspnetcore/) | 10 | C# |
| [LLM / AI Security](./llm/) | 10 | All (OWASP LLM Top 10:2025) |
| [Docker / IaC](./docker/) | 11 | Dockerfile, YAML |
| **Shannon Entropy** | Built-in | All (binary analysis) |

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
  extensions: [".py"]      # File extensions to scan
  target: all               # Matching mode: all | ast | raw | code | filename | lines_percentage | condition
  exclude_tests: true       # Skip test files (optional)
  pattern: 'regex_pattern'  # Go-compatible regex
  condition: "..."          # Optional: required_pattern | not_contains:X | contains:X | threshold:N
  suggestion: "Fix advice"  # Actionable remediation guidance
```

### Target Modes

| Mode | Description |
|---|---|
| `all` | Regex search across file content |
| `ast` | Tree-sitter AST query (Go, Python, JS/TS) |
| `raw` | Match against raw file bytes |
| `filename` | Match against filename |
| `condition` | Engine-specific condition (e.g., `large_file`) |

### Conditions

| Condition | Description |
|---|---|
| `required_pattern` | Alert if pattern is NOT found (missing security control) |
| `not_contains:X` | Alert if pattern matches but file doesn't contain X |
| `contains:X` | Alert only if file also contains X |
| `threshold:N` | Alert if matching lines exceed N% of total lines |
| `missing` | Alert if the expected file does not exist |
| `missing_lockfile` | Alert if a project uses a package manager (its manifest is present) but has no lockfile for it; see `ecosystems` below |

### Lockfile Ecosystems (`condition: missing_lockfile`)

```yaml
  ecosystems:
    - name: "npm"                          # Shown in the evidence
      manifests: ["package.json"]          # Any of them proves the project uses the ecosystem
      lockfiles: ["package-lock.json", "yarn.lock"]  # Any of them pins it
      workspace_root: true                 # Optional: a lockfile in an ancestor up to the scan root also counts
```

Set `workspace_root: true` only for package managers that pin a whole workspace with one lockfile at its root (npm/yarn/pnpm/bun workspaces, Cargo and uv workspaces, Mix umbrellas, Deno workspaces). Without it the lockfile must sit next to the manifest, as Go modules and NuGet projects require.

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

Add rules to `.aitriage.yaml` in your project root:

```yaml
custom_rules:
  - id: MY-CUSTOM-RULE
    name: "Describe the vulnerability"
    stack: universal
    extensions: [".py", ".js"]
    target: all
    pattern: 'dangerous_function\('
    suggestion: "Explain why this is dangerous and how to fix it."
```

### Guidelines

1. **Be specific** — narrow patterns reduce false positives
2. **Test the regex** — use `grep -P` to verify before committing
3. **Map to OWASP** — reference the relevant OWASP category in the suggestion
4. **Severity in suggestion** — prefix with CRITICAL / HIGH / MEDIUM / LOW
5. **Actionable fix** — always explain the remediation, not just the problem

---

## Contributing

1. Fork the repository
2. Add rules to the appropriate `rules/<stack>/security.yaml`
3. Test with `aitriage scan ./testdata`
4. Submit a PR with the rule and a test case
