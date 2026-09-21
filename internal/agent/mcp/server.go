package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"
)

type Server struct {
	version string
	srv     *mcp.Server
	profile Profile
	guard   *PathGuard
}

// NewServer builds a server with the full profile and no path confinement.
// Backward-compatible entry point (e.g. Claude Desktop via `serve`).
func NewServer(version string) *Server {
	s, err := NewServerWithConfig(version, Config{Profile: ProfileFull})
	if err != nil {
		// The full profile builds no guard, so this cannot fail; panic guards
		// against a future regression rather than a runtime condition.
		panic(fmt.Sprintf("NewServer: %v", err))
	}
	return s
}

// NewServerWithConfig builds a server with an explicit profile and optional
// scan-root confinement.
func NewServerWithConfig(version string, cfg Config) (*Server, error) {
	if cfg.Profile == "" {
		cfg.Profile = ProfileFull
	}
	var guard *PathGuard
	if strings.TrimSpace(cfg.ScanRoot) != "" {
		g, err := NewPathGuard(cfg.ScanRoot)
		if err != nil {
			return nil, err
		}
		guard = g
	}

	s := &Server{version: version, profile: cfg.Profile, guard: guard}
	s.srv = mcp.NewServer(&mcp.Implementation{
		Name:    "aitriage",
		Version: version,
	}, &mcp.ServerOptions{Instructions: serverInstructions(guard != nil)})
	s.registerTools()
	s.registerResources()
	return s, nil
}

// serverInstructions tells a connected agent how to run a real security review.
// It steers agents away from treating the raw aitriage_scan tool as a verdict
// and toward the full deferred pipeline, which the agent answers with its own
// model session.
func serverInstructions(runWorkflow bool) string {
	if !runWorkflow {
		return "AITriage exposes deterministic security-scan tools. `aitriage_scan` is a RAW pre-scan (no triage, not a final verdict)."
	}
	return strings.Join([]string{
		"AITriage runs the SAME full AI security-triage pipeline as its CI/CD `aitriage agent` (identical scanners, SecureCoder prompts, cache, canonical artifacts and gate). YOU (the host agent) only power the model requests with your own active session — no separate API key. Do NOT invent your own analysis or prompts.",
		"",
		"Two user commands map to one intent each:",
		"• \"Проверь проект через AITriage\" / \"audit\" → intent=audit (read-only, never edits source).",
		"• \"Проверь и исправь подтверждённые уязвимости\" / \"audit and fix\" → intent=audit_and_fix.",
		"Set intent ONLY from the user's actual words. A red gate, or the existence of summary.md/fixspec.md, is NOT permission to fix. Never self-escalate audit to fix.",
		"",
		"For any review START with `aitriage_run_start` (pass intent) — NOT `aitriage_scan` (raw, untriaged pre-scan, never a verdict). If the user names a project/subproject inside the configured repository root, pass that relative path to `aitriage_run_start`. Do not ask the user to edit MCP configuration.",
		"If a full run fails, report that failure. NEVER fall back to `aitriage_scan` and present raw findings as the requested security review.",
		"Workflow:",
		"1. `aitriage_run_start` returns a run_id and either a pending request (exact SecureCoder prompt) or the final result.",
		"2. Answer each pending request with YOUR model, exactly as given; submit via `aitriage_run_submit` with the SAME request_id. Report token usage only if your session actually provides it.",
		"3. Repeat until the run finalizes: four CI-parity artifacts (triage-findings.json, summary.md, report.md, fixspec.md) + aitriage.sarif + gate, all under aitriage-reports/<run-id>/.",
		"4. Show the user the gate and canonical finding IDs. For intent=audit, STOP here (zero source changes).",
		"5. Fix authorization has two paths. With intent=audit_and_fix, AITriage records approval before returning fix_context. After a completed audit, when the user later chooses findings to fix, your FIRST action MUST be `aitriage_run_approve` with the exact selected canonical TP IDs — BEFORE planning a patch, editing any file, running a formatter, or generating code. Proceed only after it returns status=fixing and fix_context. If approval rejects project drift, start a new audit; never approve retroactively.",
		"6. OPEN the returned summary_path and follow its AI Remediation Prompt / Operating Contract (Phase 0–3) verbatim. Implement fixes ONLY for the approved TP IDs; never touch False Positives or Needs-Manual-Review findings. Run the tests the contract specifies.",
		"7. Then call `aitriage_run_verify`. Verification requires at least one project change made AFTER the recorded approval. Answer its requests; it re-runs the same pipeline and reports, per approved TP, resolved/still_present, plus the overall gate separately.",
		"Use `aitriage_run_status`/`aitriage_run_continue` to resume after any interruption — they return the same fix_context so you never need to hunt for files or recall earlier chat.",
	}, "\n")
}

func (s *Server) Run(ctx context.Context, transport string, port int) error {
	switch transport {
	case "stdio":
		return s.srv.Run(ctx, &mcp.StdioTransport{})
	case "sse":
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		handler := mcp.NewSSEHandler(func(r *http.Request) *mcp.Server {
			return s.srv
		}, nil)
		mux := http.NewServeMux()

		securedHandler := corsMiddleware(rateLimitMiddleware(handler))
		mux.Handle("/sse", securedHandler)
		mux.Handle("/", securedHandler)
		httpSrv := &http.Server{Addr: addr, Handler: mux}

		fmt.Printf("  AITriage MCP Server (SSE)\n")
		fmt.Printf("  ─────────────────────────────────────\n")
		fmt.Printf("  Listening on http://%s\n", addr)
		fmt.Printf("  Add to your AI client:\n")
		fmt.Printf("    URL: http://localhost:%d/sse\n", port)
		fmt.Printf("  ─────────────────────────────────────\n\n")

		go func() {
			<-ctx.Done()
			httpSrv.Shutdown(context.Background()) //nolint:errcheck
		}()
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("SSE server error: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown transport: %s (supported: stdio, sse)", transport)
	}
}

func (s *Server) registerTools() {
	registerScanTool(s.srv, s.guard)
	registerSecretsTool(s.srv, s.guard)
	registerEntropyCheckTool(s.srv, s.guard)
	registerArchitectureTool(s.srv, s.guard)
	registerFixPlanTool(s.srv, s.guard)
	registerScannersListTool(s.srv)
	registerExternalTools(s.srv, s.guard, s.profile == ProfileSafe)
	registerSecureCoderTools(s.srv, s.guard, s.profile.allowsMutation())
	registerBaselineTool(s.srv, s.guard, s.profile.allowsMutation())
	registerReportTool(s.srv, s.guard)
	registerSuppressTool(s.srv, s.guard, s.profile.allowsMutation())
	registerRulesTool(s.srv)
	registerDeployTool(s.srv, s.guard)
	registerNFRTool(s.srv, s.guard)
	registerDiagramTool(s.srv, s.guard)
	registerHistoryTool(s.srv, s.guard)
	// Full deferred AI-triage workflow (host agent answers the model requests).
	// Requires a confined scan root, so it registers only when a guard is set.
	registerRunTools(s.srv, s.guard, s.version)
}

func (s *Server) registerResources() {
	registerPlaybookResource(s.srv)
	registerGuidelinesResource(s.srv)
}

// ── Middleware ───────────────────────────────────────────────────────────────

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

var globalLimiter = rate.NewLimiter(rate.Limit(10), 20)

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !globalLimiter.Allow() {
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
