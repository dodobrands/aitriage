// Package surfaces holds the contract that AITriage's three surfaces — the CLI,
// the Web UI and the AI IDE tools — expose the same capabilities.
//
// They drifted apart because each was written separately and nothing objected.
// `aitriage baseline` shipped in the CLI alone for a year; the one pilot user
// who needed it worked entirely in the Web UI, could not reach it, and concluded
// the tool was unusable. The capability existed. For him it did not.
//
// This test is the objection. Adding a capability to one surface and not the
// others fails here, with the reason spelled out, instead of being discovered by
// a user months later.
package surfaces

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Surface is one of the three ways a person or an agent reaches AITriage.
type Surface string

const (
	CLI Surface = "CLI"
	Web Surface = "Web"
	IDE Surface = "AI IDE"
)

// capability is one thing AITriage can do, and how to prove each surface offers it.
//
// The proofs are deliberately crude — a string present in the source that
// registers the command, route or tool. A subtle check would be a second
// implementation to keep correct; this one fails loudly when a registration is
// removed or renamed, which is exactly when a surface starts drifting.
type capability struct {
	name string
	// why explains what a user loses when a surface lacks this. It is printed on
	// failure, so whoever broke it reads the consequence rather than a bare diff.
	why string
	// proof maps a surface to (file, substring that must appear).
	proof map[Surface][2]string
	// singleSurface records a deliberate exception, with the reason.
	singleSurface map[Surface]string
}

func capabilities() []capability {
	return []capability{
		{
			name: "Deterministic scan",
			why:  "without it a surface cannot answer the basic question the product exists for",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/scan.go", `Use:   "scan`},
				Web: {"internal/server/server.go", `"/api/scan"`},
				IDE: {"internal/agent/mcp/tools_scan.go", `"aitriage_scan"`},
			},
		},
		{
			name: "Baseline",
			why:  "a team adopting AITriage on an existing codebase has no other way to stop the gate judging years of accumulated debt",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/baseline.go", `Use:   "baseline"`},
				Web: {"internal/server/server.go", `"/api/baseline"`},
				IDE: {"internal/agent/mcp/tools_baseline.go", `"aitriage_baseline"`},
			},
		},
		{
			name: "Dismiss a finding",
			why:  "a false positive nobody can mark keeps blocking, and a decision one surface cannot see is not a decision",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/ignore.go", `Use:   "ignore"`},
				Web: {"internal/server/server.go", `"/api/suppressions"`},
				IDE: {"internal/agent/mcp/tools_suppress.go", `"aitriage_suppress"`},
			},
		},
		{
			name: "Generate a report artifact",
			why:  "a surface that finds problems but cannot produce the document a reviewer asks for is a dead end",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/scan.go", "sarif"},
				Web: {"internal/server/server.go", `"/api/reports/generate"`},
				IDE: {"internal/agent/mcp/tools_report.go", `"aitriage_report"`},
			},
		},
		{
			name: "SBOM",
			why:  "supply-chain questions are asked of whichever surface the person happens to be using",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/sbom.go", `Use:   "sbom`},
				Web: {"internal/report/artifacts/artifacts.go", "FormatCycloneDX"},
				IDE: {"internal/agent/mcp/tools_report.go", "cyclonedx"},
			},
		},
		{
			name: "Inspect rule packs",
			why:  "\"what did this scan actually cover?\" decides whether a clean result means anything",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/rules_cmd.go", `Use:   "rules"`},
				Web: {"internal/server/server.go", `"/api/rules"`},
				IDE: {"internal/agent/mcp/tools_rules.go", `"aitriage_rules"`},
			},
		},
		{
			name: "Targeted checks (NFR, deploy, entropy)",
			why:  "a quick check before a commit is skipped entirely if it costs a full audit",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/preaudit.go", `Use:   "preaudit"`},
				Web: {"internal/server/checks_handler.go", `case "nfr"`},
				IDE: {"internal/agent/mcp/tools_nfr.go", `"aitriage_nfr_check"`},
			},
		},
		{
			name: "Diff against the previous scan",
			why:  "\"what changed since last time?\" is the only useful question on a repository that already carries a backlog",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/watch.go", `Use:   "watch`},
				Web: {"internal/server/server.go", `"/api/diff"`},
				IDE: {"internal/agent/mcp/tools_history.go", `"aitriage_diff"`},
			},
		},
		{
			name: "Install IDE connectors",
			why:  "writing an IDE's configuration file belongs to the person at that machine",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/install_clients.go", "install-"},
			},
			singleSurface: map[Surface]string{
				CLI: "Configuring an editor from a browser or from a tool call is meaningless: the person installing is at the terminal.",
			},
		},
		{
			name: "Install a rule pack",
			why:  "a pack is third-party rule content written to disk",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/rules_cmd.go", "runRulesInstall"},
			},
			singleSurface: map[Surface]string{
				CLI: "Fetching and writing rule content is a decision for the person at the keyboard, not for a web request or a tool call. Reading the installed set is available everywhere.",
			},
		},
		{
			name: "Set up the container runtime",
			why:  "it installs and verifies Docker images for the machine",
			proof: map[Surface][2]string{
				CLI: {"cmd/aitriage/setup.go", `Use:   "setup"`},
			},
			singleSurface: map[Surface]string{
				CLI: "The Web UI runs inside the runtime this command prepares; it cannot bootstrap itself.",
			},
		},
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// This package sits at internal/surfaces, two levels below the root.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

func sourceContains(t *testing.T, root, relPath, needle string) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, relPath))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), needle)
}

// TestEveryCapabilityReachesEverySurface is the parity contract itself.
func TestEveryCapabilityReachesEverySurface(t *testing.T) {
	root := repoRoot(t)

	for _, cap := range capabilities() {
		t.Run(cap.name, func(t *testing.T) {
			for _, surface := range []Surface{CLI, Web, IDE} {
				proof, declared := cap.proof[surface]

				if !declared {
					if reason, deliberate := cap.singleSurface[expectedOnly(cap)]; deliberate && len(cap.proof) == 1 {
						t.Logf("%s: not offered on %s by design — %s", cap.name, surface, reason)
						continue
					}
					t.Errorf("%q is missing from %s.\n  Why it matters: %s.\n"+
						"  Add it to that surface, or record it in singleSurface with the reason.",
						cap.name, surface, cap.why)
					continue
				}

				if !sourceContains(t, root, proof[0], proof[1]) {
					t.Errorf("%q no longer appears to be registered on %s:\n"+
						"  expected %q in %s\n  Why it matters: %s.",
						cap.name, surface, proof[1], proof[0], cap.why)
				}
			}
		})
	}
}

// expectedOnly returns the single surface a deliberately-limited capability
// lives on.
func expectedOnly(c capability) Surface {
	for surface := range c.proof {
		return surface
	}
	return ""
}

// TestDeliberateExceptionsCarryAReason keeps the exception list honest: it is
// there to record decisions, not to silence the test.
func TestDeliberateExceptionsCarryAReason(t *testing.T) {
	for _, cap := range capabilities() {
		if len(cap.proof) >= 3 {
			if len(cap.singleSurface) > 0 {
				t.Errorf("%q is available everywhere but still lists an exception; remove the stale entry", cap.name)
			}
			continue
		}
		if len(cap.singleSurface) == 0 {
			t.Errorf("%q is offered on only %d surface(s) with no recorded reason.\n"+
				"  Either add the missing surfaces, or say why it belongs to one.", cap.name, len(cap.proof))
			continue
		}
		for surface, reason := range cap.singleSurface {
			if len(strings.TrimSpace(reason)) < 40 {
				t.Errorf("%q on %s: the reason is too thin to be a decision — %q", cap.name, surface, reason)
			}
		}
	}
}

// TestSharedStoresAreProjectFiles guards the mechanism that makes parity real.
//
// Baselines and dismissals are shared between surfaces only because they live in
// project files. Moving either into a server database would silently break
// parity for the CLI, which has no database at all.
func TestSharedStoresAreProjectFiles(t *testing.T) {
	root := repoRoot(t)

	for _, store := range []struct{ file, constant string }{
		{"internal/engine/baseline/baseline.go", `BaselineFile = ".aitriage-baseline.json"`},
		{"internal/engine/suppression/suppression.go", `File = ".aitriage-suppressions.json"`},
	} {
		if !sourceContains(t, root, store.file, store.constant) {
			t.Errorf("the shared store in %s changed.\n"+
				"  A project file is what lets the CLI, the Web UI and an IDE agent see the same decisions.\n"+
				"  A database would be reachable by the server only.", store.file)
		}
	}
}

// TestNoSurfaceInventsItsOwnFingerprint checks that every surface identifies a
// finding the same way. If they diverged, a dismissal recorded in one place
// would not match the same finding seen from another.
func TestNoSurfaceInventsItsOwnFingerprint(t *testing.T) {
	root := repoRoot(t)

	fingerprintDefinition := regexp.MustCompile(`func\s+FingerprintItem\(`)
	data, err := os.ReadFile(filepath.Join(root, "internal/engine/baseline/items.go"))
	if err != nil {
		t.Fatalf("read baseline items: %v", err)
	}
	if !fingerprintDefinition.Match(data) {
		t.Fatal("the shared fingerprint is gone; each surface would start identifying findings its own way")
	}

	// Consumers must go through the shared package — either its fingerprint or
	// the Accepts/Suppresses calls built on it — and must never hash their own
	// fields. A second hashing scheme is how two surfaces stop agreeing on what
	// counts as "the same finding".
	for _, consumer := range []string{
		"internal/engine/suppression/suppression.go",
		"internal/engine/orchestrator/baseline.go",
	} {
		usesShared := sourceContains(t, root, consumer, "FingerprintItem(") ||
			sourceContains(t, root, consumer, "baseline.From") ||
			sourceContains(t, root, consumer, ".Accepts(") ||
			sourceContains(t, root, consumer, ".Suppresses(")
		if !usesShared {
			t.Errorf("%s no longer identifies findings through the shared baseline package", consumer)
		}
		if sourceContains(t, root, consumer, "sha256.Sum") {
			t.Errorf("%s hashes findings itself; identity belongs to one place or the surfaces will disagree", consumer)
		}
	}
}
