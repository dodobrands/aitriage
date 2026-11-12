---
name: 🚀 New Detection Rule
about: Propose a new detection rule for the AITriage rules library
title: "[RULE] "
labels: enhancement, rule-proposal
assignees: ''

---

**Pattern Description**
What AI-generated code pattern, hallucination, or vulnerability should this rule catch?

**Proposed Stack** (one of the categories under `rules/`)
- [ ] Universal
- [ ] Python
- [ ] Next.js / React
- [ ] FastAPI
- [ ] Django
- [ ] Flask
- [ ] Express.js
- [ ] Go
- [ ] ASP.NET Core
- [ ] LLM / AI Security
- [ ] Docker / IaC

**Severity**
`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`

**Example Vulnerable Code:**
```ts
// Example code that should fail
```

**Proposed Rule:**
A YAML rule in the format described in `rules/README.md` (regex, tree-sitter AST query, or `mode: taint`).
```yaml
- id: MY-RULE-ID
```
