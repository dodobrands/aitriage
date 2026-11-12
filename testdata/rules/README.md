# Rule fixtures

Every built-in rule in `rules/` has fixtures here, checked by
`TestRuleFixtures` in `internal/engine/rule_fixtures_test.go`.

```
testdata/rules/<RULE-ID>/
  bad/<case>    # must make the rule report
  good/<case>   # similar, safe code; must stay silent
```

- A case is one file, or a directory with a small project (for rules that
  check a whole project, such as a missing control or lockfile).
- Keep the real file name the rule looks for (`Dockerfile`, `settings.py`,
  `package.json`); the rule's `extensions` decide which files it reads.
- In a bad file, put a comment containing `ruleid: <RULE-ID>` on the line
  above the code that should be reported. The test then checks the line.
- If a rule fires on its good case, that is a false positive: fix the rule's
  pattern, region or condition, not the case.
- Split credential-shaped values with `__JOIN__` (removed when the test copies
  the case), so the repository never contains a value that looks like a live
  secret.
- Avoid test-like names (`test_*.py`, `*_test.go`, `*.spec.ts`): the scanner
  does not attach test files to a project.

Run them with `go test ./internal/engine/ -run TestRuleFixtures`. The test
also fails when a rule has no bad or no good case.
