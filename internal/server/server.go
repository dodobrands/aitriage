package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/agent/architect"
	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/prompts"
	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/engine"
	"github.com/dodobrands/aitriage/internal/engine/baseline"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/engine/orchestrator"
	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/report/healthcheck"
	"github.com/dodobrands/aitriage/internal/scanner/deps"
	"github.com/dodobrands/aitriage/internal/scanner/external"
	"github.com/dodobrands/aitriage/internal/server/handlers"
	"github.com/dodobrands/aitriage/internal/server/middleware"
	"github.com/dodobrands/aitriage/internal/server/repositories"
)

// llmUnavailableMessage is the single user-facing explanation for every AI
// surface that cannot run without a configured provider. It names all supported
// keys instead of one, because any of them unlocks the feature.
const llmUnavailableMessage = "AI features are offline: no LLM provider is configured. " +
	"Set GEMINI_API_KEY, ANTHROPIC_API_KEY or OPENAI_API_KEY (or configure llm.api_key in .aitriage.yaml) and restart AITriage. " +
	"Scanning and report generation work without it."

type Server struct {
	hostPrefix         string
	llmClient          llm.Client
	lastResult         *llm.RichScanResult
	userRepo           *repositories.UserRepository
	productRepo        *repositories.ProductRepository
	engagementRepo     *repositories.EngagementRepository
	findingRepo        *repositories.FindingRepository
	auditRepo          *repositories.AuditRepository
	notifRepo          *repositories.NotificationRepository
	metricsRepo        *repositories.MetricsRepository
	apiKeyRepo         *repositories.APIKeyRepository
	topologyRepo       *repositories.TopologyRepository
	configRepo         *repositories.ConfigRepository
	reportRepo         *repositories.ReportRepository
	chatRepo           *repositories.ChatRepository
	ignoreRepo         *repositories.IgnoreRepository
	runwayRepo         *repositories.RunwayRepository
	runwayArtifactRepo *repositories.RunwayArtifactRepository
	db                 *sql.DB
	engine             *engine.Engine
}

func NewServer(hostPrefix string, db *sql.DB) *Server {
	userRepo := repositories.NewUserRepository(db)
	productRepo := repositories.NewProductRepository(db)
	eng, err := engine.NewEngine(nil)
	if err != nil {
		slog.Error("CRITICAL: Failed to initialize security engine", "error", err)
	} else {
		slog.Info("Security engine initialized", "rules_count", len(eng.Rules))
	}

	// Eagerly initialize LLM client from env vars so chat works without a scan.
	var llmCl llm.Client
	cfg := config.LoadConfig(".")
	if cfg.LLM.APIKey != "" {
		client, llmErr := llm.NewClient(llm.Config{
			Provider: cfg.LLM.Provider,
			Model:    cfg.LLM.Model,
			APIKey:   cfg.LLM.APIKey,
			BaseURL:  cfg.LLM.BaseURL,
			Timeout:  cfg.LLM.Timeout,
		})
		if llmErr == nil {
			llmCl = client
			slog.Info("LLM client initialized at startup", "provider", cfg.LLM.Provider)
		} else {
			slog.Warn("LLM client init failed", "error", llmErr)
		}
	}

	return &Server{
		hostPrefix:         hostPrefix,
		llmClient:          llmCl,
		userRepo:           userRepo,
		productRepo:        productRepo,
		engagementRepo:     repositories.NewEngagementRepository(db),
		findingRepo:        repositories.NewFindingRepository(db),
		auditRepo:          repositories.NewAuditRepository(db),
		notifRepo:          repositories.NewNotificationRepository(db),
		metricsRepo:        repositories.NewMetricsRepository(db),
		apiKeyRepo:         repositories.NewAPIKeyRepository(db),
		topologyRepo:       repositories.NewTopologyRepository(db),
		configRepo:         repositories.NewConfigRepository(db),
		reportRepo:         repositories.NewReportRepository(db),
		chatRepo:           repositories.NewChatRepository(db),
		ignoreRepo:         repositories.NewIgnoreRepository(db),
		runwayRepo:         repositories.NewRunwayRepository(db),
		runwayArtifactRepo: repositories.NewRunwayArtifactRepository(db),
		db:                 db,
		engine:             eng,
	}
}

// resolveProjectPath maps a Web/API path into the single project root mounted
// at hostPrefix. In container mode the root is /workspace; callers may use
// relative paths, /workspace paths, or the legacy UI aliases /project and
// /host. Every result is symlink-resolved and confined to that root.
//
// An empty hostPrefix keeps the historical native/development behavior. The
// production container always supplies a hostPrefix and therefore fails closed
// on traversal and symlink escapes instead of exposing the container filesystem.
func (s *Server) resolveProjectPath(input string) (string, error) {
	if s.hostPrefix == "" {
		return input, nil
	}

	root, err := filepath.Abs(s.hostPrefix)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("project root is unavailable")
	}

	raw := strings.TrimSpace(input)
	slashRaw := strings.ReplaceAll(raw, `\`, "/")
	var candidate string
	switch {
	case raw == "", raw == ".", raw == "/", raw == "/project", raw == "/host":
		candidate = root
	case filepath.IsAbs(raw):
		absolute, resolveErr := filepath.EvalSymlinks(raw)
		if resolveErr == nil && (absolute == root || strings.HasPrefix(absolute, root+string(os.PathSeparator))) {
			candidate = absolute
		} else if filepath.VolumeName(raw) != "" {
			// A native Windows absolute path (drive or UNC) is never a UI alias.
			// Do not reinterpret an outside host path as project-relative.
			return "", fmt.Errorf("path %q escapes the opened project", input)
		} else {
			// Older Web clients use /project/... or /host/... and breadcrumb
			// paths rooted at /. Interpret every other absolute path as project-
			// relative; it can never address /etc or another container directory.
			rel := projectAliasRelativePath(slashRaw)
			candidate = filepath.Join(root, filepath.FromSlash(rel))
		}
	case strings.HasPrefix(slashRaw, "/"):
		// On Windows, filepath.IsAbs("/project/...") is false. These are still
		// container/Web aliases and must be interpreted independently of GOOS.
		rel := projectAliasRelativePath(slashRaw)
		candidate = filepath.Join(root, filepath.FromSlash(rel))
	default:
		candidate = filepath.Join(root, raw)
	}

	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("path %q does not exist inside the opened project", input)
	}
	if resolved != root && !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes the opened project", input)
	}
	return resolved, nil
}

func projectAliasRelativePath(value string) string {
	rel := strings.TrimLeft(pathpkg.Clean(value), "/")
	rel = strings.TrimPrefix(rel, "project/")
	rel = strings.TrimPrefix(rel, "host/")
	if rel == "project" || rel == "host" || rel == "." {
		return ""
	}
	return rel
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		if !allowedLocalWebOrigin(origin) {
			http.Error(w, "cross-origin access is not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	}

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/api/scan", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleScan)))
	mux.Handle("/api/browser", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleBrowser)))
	mux.Handle("/api/triage", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleTriage)))
	mux.Handle("/api/chat", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleChat)))
	mux.Handle("/api/rules", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleRules)))

	// Product Management
	productHandler := handlers.NewProductHandler(s.productRepo)
	mux.Handle("/api/products", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			productHandler.HandleListProducts(w, r)
		case "POST":
			productHandler.HandleCreateProduct(w, r)
		case "PUT":
			productHandler.HandleUpdateProduct(w, r)
		case "DELETE":
			productHandler.HandleDeleteProduct(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/products/types", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(productHandler.HandleListProductTypes)))
	mux.Handle("/api/products/members", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(productHandler.HandleAddProductMember)))

	// Engagement Tracking
	engagementHandler := handlers.NewEngagementHandler(s.engagementRepo)
	mux.Handle("/api/engagements", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			engagementHandler.HandleListEngagements(w, r)
		case "POST":
			engagementHandler.HandleCreateEngagement(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})))

	// Findings Management
	findingHandler := handlers.NewFindingHandler(s.findingRepo)
	mux.Handle("/api/findings", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			findingHandler.HandleListFindings(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/findings/", middleware.PermissionMiddleware("admin", "manager", "developer")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/ai-triage") {
			if r.Method == "POST" {
				s.handleAITriage(w, r)
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		} else if strings.HasSuffix(r.URL.Path, "/agent-prompt") {
			if r.Method == http.MethodGet || r.Method == http.MethodPost {
				s.handleFindingAgentPrompt(w, r)
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		} else if strings.HasSuffix(r.URL.Path, "/verify") {
			if r.Method == http.MethodPost {
				s.handleFindingVerification(w, r)
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		} else if r.Method == "PUT" {
			findingHandler.HandleUpdateFinding(w, r)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})))

	// User Management (Admin)
	authHandler := handlers.NewAuthHandler(s.userRepo)
	adminUsersHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			authHandler.HandleListUsers(w, r)
		case "POST":
			authHandler.HandleCreateUser(w, r)
		case "DELETE":
			authHandler.HandleDeleteUser(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// System Configuration (Admin)
	configHandler := handlers.NewConfigHandler(s.configRepo)
	mux.Handle("/api/admin/config", middleware.PermissionMiddleware("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			configHandler.HandleGetConfig(w, r)
		case "POST", "PUT":
			configHandler.HandleUpdateConfig(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})))

	mux.Handle("/api/admin/users", middleware.PermissionMiddleware("admin")(adminUsersHandler))

	mux.HandleFunc("/api/login", authHandler.HandleLogin)
	mux.Handle("/api/me", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(authHandler.HandleMe)))

	// Notifications
	notifHandler := handlers.NewNotificationHandler(s.notifRepo)
	mux.Handle("/api/notifications", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(notifHandler.HandleListNotifications)))
	mux.Handle("/api/notifications/", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(notifHandler.HandleMarkAsRead)))

	// Audit
	auditHandler := handlers.NewAuditHandler(s.auditRepo)
	mux.Handle("/api/audit", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(auditHandler.HandleListAuditLogs)))

	// Metrics
	metricsHandler := handlers.NewMetricsHandler(s.metricsRepo)
	mux.Handle("/api/metrics", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(metricsHandler.HandleGetDashboardMetrics)))

	// Reports
	reportHandler := handlers.NewReportHandler(s.findingRepo, s.engagementRepo, s.productRepo, s.reportRepo)
	mux.Handle("/api/reports/executive", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(reportHandler.HandleExecutiveReport)))
	mux.Handle("/api/reports/engagement/", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(reportHandler.HandleEngagementReport)))
	mux.Handle("/api/reports/history", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(reportHandler.HandleListReportHistory)))
	mux.Handle("/api/reports/generate", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(reportHandler.HandleGenerateReport)))
	mux.Handle("/api/reports/download/", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(reportHandler.HandleDownloadReport)))
	mux.Handle("/api/baseline", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleBaseline)))

	mux.Handle("/api/analyze", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleAnalyze)))
	mux.Handle("/api/pipeline", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handlePipeline)))
	mux.Handle("/api/file", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleFile)))

	topologyHandler := handlers.NewTopologyHandler(s.topologyRepo)
	mux.Handle("/api/topology", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(topologyHandler.HandleGetTopology)))

	apiKeyHandler := handlers.NewAPIKeyHandler(s.apiKeyRepo)
	mux.Handle("/api/admin/keys", middleware.PermissionMiddleware("admin")(http.HandlerFunc(apiKeyHandler.HandleListKeys)))
	mux.Handle("/api/admin/keys/create", middleware.PermissionMiddleware("admin")(http.HandlerFunc(apiKeyHandler.HandleCreateKey)))
	mux.Handle("/api/admin/keys/", middleware.PermissionMiddleware("admin")(http.HandlerFunc(apiKeyHandler.HandleRevokeKey)))

	mux.Handle("/api/admin/clear-cache", middleware.PermissionMiddleware("admin")(http.HandlerFunc(s.handleClearCache)))
	mux.Handle("/api/admin/purge", middleware.PermissionMiddleware("admin")(http.HandlerFunc(s.handlePurgeDatabase)))
	mux.Handle("/api/admin/rebuild", middleware.PermissionMiddleware("admin")(http.HandlerFunc(s.handleRebuild)))

	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/prompts", s.handlePrompts)
	mux.Handle("/api/ai-summary", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleSummary)))

	mux.Handle("/api/chat/sessions", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleChatSessions)))
	mux.Handle("/api/chat/sessions/", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleChatSession)))
	mux.Handle("/api/chat/messages", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleChatMessages)))

	// SecureCoder-Compatible API
	mux.HandleFunc("/api/securecoder/config", s.handleSecureCoderConfig)
	mux.Handle("/api/securecoder/scan", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleSecureCoderScan)))
	mux.Handle("/api/securecoder/scan-directory", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleSecureCoderScanDirectory)))
	mux.Handle("/api/securecoder/ignore", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleSecureCoderIgnore)))
	mux.Handle("/api/securecoder/ignored", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleSecureCoderIgnored)))
	mux.Handle("/api/securecoder/fix_completed", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleSecureCoderFixCompleted)))
	mux.Handle("/api/securecoder/dependency/scan", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleSecureCoderDepScan)))
	mux.Handle("/api/securecoder/wiz/status", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleWizStatus)))
	mux.Handle("/api/securecoder/wiz/login", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleWizLogin)))
	mux.Handle("/api/securecoder/wiz/login/poll", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleWizLoginPoll)))
	mux.Handle("/api/securecoder/wiz/logout", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleWizLogout)))
	mux.Handle("/api/securecoder/ignore-file", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleSecureCoderIgnoreFile)))

	mux.Handle("/api/runway", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleRunway)))
	mux.Handle("/api/runway/all", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleRunwayAll)))
	mux.Handle("GET /api/runway/artifacts/{id}", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleRunwayArtifactManifest)))
	mux.Handle("GET /api/runway/handoff/{id}", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleRunwayHandoff)))
	mux.Handle("GET /api/runway/artifacts/{id}/{kind}", middleware.PermissionMiddleware("admin", "manager", "viewer")(http.HandlerFunc(s.handleRunwayArtifactDownload)))
	mux.Handle("/api/runway/export/", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleRunwayExport)))
	mux.Handle("/api/runway/", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleRunwaySession)))
	mux.Handle("/api/runway/start/", middleware.PermissionMiddleware("admin", "manager")(http.HandlerFunc(s.handleRunwayStart)))

	// UI
	mux.HandleFunc("/", handleUI)

	handler := middleware.SecurityHeadersMiddleware(
		middleware.RateLimitMiddleware(
			mux,
		),
	)

	handler.ServeHTTP(w, r)
}

func allowedLocalWebOrigin(raw string) bool {
	origin, err := url.Parse(raw)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") {
		return false
	}
	host := origin.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ── API Handlers ─────────────────────────────────────────────────────────────

type scanRequest struct {
	Path     string `json:"path"`
	Stack    string `json:"stack,omitempty"`
	External bool   `json:"external,omitempty"`
	// ProbeNetwork opts into scanning listening ports on the host running
	// AITriage. It is off by default because it describes the environment, not
	// the audited repository.
	ProbeNetwork bool `json:"probe_network,omitempty"`
	// UseBaseline reports only findings absent from the accepted baseline, so a
	// legacy codebase can be gated on regressions instead of on its whole history.
	UseBaseline bool `json:"use_baseline,omitempty"`
}

type findingDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Suggestion  string `json:"suggestion"`
	OWASP       string `json:"owasp,omitempty"`
	AuditStatus string `json:"audit_status"`
	Stack       string `json:"stack"`
}

type scanResponse struct {
	Ok              bool                        `json:"ok"`
	ScanID          string                      `json:"scan_id"`
	Findings        []findingDTO                `json:"findings"`
	Dependencies    []deps.Dependency           `json:"dependencies"`
	Stacks          []string                    `json:"stacks"`
	SecurityScore   int                         `json:"security_score"`
	SecurityGrade   string                      `json:"security_grade"`
	HealthCheck     healthcheck.Result          `json:"health_check"`
	ScannerCoverage string                      `json:"scanner_coverage"`
	Scanners        []external.ScannerExecution `json:"scanners,omitempty"`
	ManifestPath    string                      `json:"manifest_path,omitempty"`
	// BaselinedFindings counts findings suppressed by an accepted baseline. It is
	// always reported so a reduced result can never look like a clean project.
	BaselinedFindings int    `json:"baselined_findings"`
	Duration          string `json:"duration"`
	Error             string `json:"error,omitempty"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		jsonError(w, "path is required", http.StatusBadRequest)
		return
	}

	containerPath, err := s.resolveProjectPath(req.Path)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	slog.Info("Scan requested", "path", req.Path, "full", containerPath)
	start := time.Now()
	ctx := r.Context()

	containerFull := os.Getenv("AITRIAGE_RUNTIME") == "container"
	opts := orchestrator.Options{
		ProjectPath: containerPath,
		ForceStack:  req.Stack,
		RunExternal: req.External || containerFull,
		// Port probing is opt-in. It inspects the machine AITriage runs on, not
		// the code being audited, so it must never happen because someone asked
		// for a source scan.
		ProbeHost: requestedProbeHost(req.ProbeNetwork),
	}

	rich := orchestrator.RunAllScanners(ctx, opts)

	// A baseline hides findings the team has already accepted. It is applied
	// here, before scoring and persistence, so the score, the gate verdict and
	// the stored findings all describe the same set: what is new.
	baselinedCount := 0
	if req.UseBaseline {
		accepted, loadErr := baseline.Load(containerPath)
		if loadErr != nil {
			jsonError(w, fmt.Sprintf("failed to read baseline: %v", loadErr), http.StatusInternalServerError)
			return
		}
		if accepted != nil {
			filtered := baseline.Filter(rich.Report.Results, accepted)
			baselinedCount = len(filtered.Baseline)
			rich.Report.Results = filtered.New
			orchestrator.RecomputeHealthCheck(&rich)
		}
	}

	s.lastResult = &rich
	scannerCoverage := "core"
	if opts.RunExternal {
		scannerCoverage = "partial"
	}
	if containerFull {
		if missing := rich.MissingRequiredScanners(); len(missing) > 0 {
			jsonError(w, "full audit aborted: required scanner execution(s) did not complete: "+strings.Join(missing, ", "), http.StatusServiceUnavailable)
			return
		}
		scannerCoverage = "full"
	}
	scanID := fmt.Sprintf("scan-%s-%d", time.Now().UTC().Format("20060102T150405"), time.Now().UnixNano())
	manifestPath := ""
	if reportsDir := strings.TrimSpace(os.Getenv("AITRIAGE_REPORTS_DIR")); reportsDir != "" {
		manifestPath, err = writeWebScanManifest(reportsDir, webScanManifest{
			SchemaVersion:   1,
			ScanID:          scanID,
			RequestedPath:   req.Path,
			ScannerCoverage: scannerCoverage,
			Scanners:        rich.ScannerExecutions,
			SecurityScore:   rich.Report.SecurityScore,
			SecurityGrade:   rich.Report.SecurityGrade,
			CreatedAt:       time.Now().UTC(),
		})
		if err != nil {
			jsonError(w, "full audit completed but its scanner manifest could not be persisted: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Initialize LLM if config is available
	if rich.Report.Config != nil && s.llmClient == nil {
		client, err := llm.NewClient(llm.Config{
			Provider: rich.Report.Config.LLM.Provider,
			Model:    rich.Report.Config.LLM.Model,
			APIKey:   rich.Report.Config.LLM.APIKey,
			BaseURL:  rich.Report.Config.LLM.BaseURL,
			Timeout:  rich.Report.Config.LLM.Timeout,
		})
		if err == nil {
			s.llmClient = client
		}
	}

	// ── Persist to DB ────────────────────────────────────────────────
	// 1. Auto-create or find product
	productID, err := s.productRepo.FindOrCreateByPath(ctx, req.Path)
	if err != nil {
		slog.Error("Failed to find/create product for scan", "path", req.Path, "error", err)
	}

	// 2. Create engagement
	scanPath := req.Path
	engagementName := fmt.Sprintf("Web Audit — %s", filepath.Base(req.Path))
	engagement := &models.Engagement{
		ProductID:      productID,
		Name:           engagementName,
		ScanPath:       &scanPath,
		EngagementType: "interactive",
		Status:         "in_progress",
	}
	if err := s.engagementRepo.Create(ctx, engagement); err != nil {
		slog.Error("Failed to create engagement", "error", err)
	}
	engagementID := engagement.ID

	// 3. Convert findings and bulk-insert — ALL scanner types
	var findings []findingDTO
	var dbFindings []models.Finding

	// 3a. Core SAST findings
	for _, result := range rich.Report.Results {
		findings = append(findings, findingDTO{
			ID:          result.ID,
			Name:        result.Name,
			Severity:    result.Severity,
			File:        result.File,
			Line:        result.Line,
			Suggestion:  result.Suggestion,
			OWASP:       result.OWASPMapping,
			AuditStatus: string(result.AuditStatus),
			Stack:       result.Framework,
		})

		filePath := result.File
		lineNum := result.Line
		description := result.Suggestion
		dbFindings = append(dbFindings, models.Finding{
			EngagementID:  engagementID,
			ProductID:     &productID,
			RuleID:        result.ID,
			Title:         result.Name,
			Severity:      strings.ToUpper(result.Severity),
			FilePath:      &filePath,
			LineNumber:    &lineNum,
			Description:   &description,
			FixSuggestion: &result.Suggestion,
			Status:        "open",
			KanbanColumn:  "backlog",
			Stack:         result.Framework,
		})
	}

	// 3b. External scanner findings (Semgrep, Trivy, Bandit, Gitleaks)
	for _, ext := range rich.External {
		sev := strings.ToUpper(ext.Severity)
		if sev == "" {
			sev = "MEDIUM"
		}
		filePath := ext.File
		lineNum := ext.Line
		desc := ext.Message
		suggestion := ext.Message
		name := fmt.Sprintf("[%s] %s", ext.Source, ext.RuleID)
		if ext.RuleID == "" {
			name = fmt.Sprintf("[%s] %s", ext.Source, ext.Message)
		}

		findings = append(findings, findingDTO{
			ID:         ext.RuleID,
			Name:       name,
			Severity:   strings.ToLower(sev),
			File:       ext.File,
			Line:       ext.Line,
			Suggestion: ext.Message,
			Stack:      ext.Source,
		})
		dbFindings = append(dbFindings, models.Finding{
			EngagementID:  engagementID,
			ProductID:     &productID,
			RuleID:        ext.RuleID,
			Title:         name,
			Severity:      sev,
			FilePath:      &filePath,
			LineNumber:    &lineNum,
			Description:   &desc,
			FixSuggestion: &suggestion,
			Status:        "open",
			KanbanColumn:  "backlog",
			Stack:         ext.Source,
		})
	}

	// 3c. NFR (Non-Functional Requirement) findings
	for _, n := range rich.NFR {
		sev := strings.ToUpper(n.Severity)
		if sev == "" {
			sev = "LOW"
		}
		desc := n.Message
		zeroLine := 0
		findings = append(findings, findingDTO{
			ID:         n.RuleID,
			Name:       n.Name,
			Severity:   strings.ToLower(sev),
			Suggestion: n.Message,
			Stack:      "nfr",
		})
		dbFindings = append(dbFindings, models.Finding{
			EngagementID:  engagementID,
			ProductID:     &productID,
			RuleID:        n.RuleID,
			Title:         n.Name,
			Severity:      sev,
			LineNumber:    &zeroLine,
			Description:   &desc,
			FixSuggestion: &desc,
			Status:        "open",
			KanbanColumn:  "backlog",
			Stack:         "nfr",
		})
	}

	// 3d. Deploy / IaC findings
	for _, d := range rich.Deploy {
		sev := strings.ToUpper(d.Severity)
		if sev == "" {
			sev = "MEDIUM"
		}
		filePath := d.File
		lineNum := d.Line
		desc := d.Issue
		advice := d.Advice
		findings = append(findings, findingDTO{
			ID:         fmt.Sprintf("deploy-%s-%d", filepath.Base(d.File), d.Line),
			Name:       d.Issue,
			Severity:   strings.ToLower(sev),
			File:       d.File,
			Line:       d.Line,
			Suggestion: d.Advice,
			Stack:      "deploy",
		})
		dbFindings = append(dbFindings, models.Finding{
			EngagementID:  engagementID,
			ProductID:     &productID,
			RuleID:        fmt.Sprintf("deploy-%s-%d", filepath.Base(d.File), d.Line),
			Title:         d.Issue,
			Severity:      sev,
			FilePath:      &filePath,
			LineNumber:    &lineNum,
			Description:   &desc,
			FixSuggestion: &advice,
			Status:        "open",
			KanbanColumn:  "backlog",
			Stack:         "deploy",
		})
	}

	// 3e. Network probe findings
	for _, n := range rich.Network {
		sev := strings.ToUpper(n.Severity)
		if sev == "" {
			sev = "HIGH"
		}
		desc := n.Message
		host := n.Target
		zeroLine := 0
		name := fmt.Sprintf("Open port %d (%s) on %s", n.Port, n.Service, n.Target)
		findings = append(findings, findingDTO{
			ID:         fmt.Sprintf("net-%s-%d", n.Target, n.Port),
			Name:       name,
			Severity:   strings.ToLower(sev),
			Suggestion: n.Message,
			Stack:      "network",
		})
		dbFindings = append(dbFindings, models.Finding{
			EngagementID:  engagementID,
			ProductID:     &productID,
			RuleID:        fmt.Sprintf("net-%s-%d", n.Target, n.Port),
			Title:         name,
			Severity:      sev,
			FilePath:      &host,
			LineNumber:    &zeroLine,
			Description:   &desc,
			FixSuggestion: &desc,
			Status:        "open",
			KanbanColumn:  "backlog",
			Stack:         "network",
		})
	}

	// 3f. Git history leaks
	for _, hl := range rich.HistoryLeaks {
		filePath := hl.FilePath
		zeroLine := 0
		desc := fmt.Sprintf("Pattern '%s' found in commit %s by %s: %s", hl.Pattern, hl.CommitHash, hl.Author, hl.LinePreview)
		findings = append(findings, findingDTO{
			ID:         fmt.Sprintf("gitleak-%s", hl.CommitHash[:8]),
			Name:       fmt.Sprintf("Secret leak: %s in %s", hl.Pattern, hl.FilePath),
			Severity:   "high",
			File:       hl.FilePath,
			Suggestion: desc,
			Stack:      "git-history",
		})
		dbFindings = append(dbFindings, models.Finding{
			EngagementID:  engagementID,
			ProductID:     &productID,
			RuleID:        fmt.Sprintf("gitleak-%s", hl.CommitHash[:8]),
			Title:         fmt.Sprintf("Secret leak: %s in %s", hl.Pattern, hl.FilePath),
			Severity:      "HIGH",
			FilePath:      &filePath,
			LineNumber:    &zeroLine,
			Description:   &desc,
			FixSuggestion: &desc,
			Status:        "open",
			KanbanColumn:  "backlog",
			Stack:         "git-history",
		})
	}

	if len(dbFindings) > 0 {
		if err := s.findingRepo.BulkCreate(ctx, dbFindings); err != nil {
			slog.Error("Failed to bulk-insert findings", "count", len(dbFindings), "error", err)
		} else {
			slog.Info("Findings persisted to database", "count", len(dbFindings), "engagement_id", engagementID)
		}
	}

	// ── Populate Topology ───────────────────────────────────────────
	_ = s.topologyRepo.Clear()

	appNodeID := fmt.Sprintf("app-%d", productID)
	appRisk := rich.Report.SecurityGrade
	switch appRisk {
	case "F", "D":
		appRisk = "CRITICAL"
	case "C":
		appRisk = "MEDIUM"
	default:
		appRisk = "LOW"
	}

	components := architect.DetectComponents(containerPath)
	mainAppName := filepath.Base(req.Path)

	for _, c := range components {
		if c.Type == "app" {
			mainAppName = fmt.Sprintf("%s (%s)", c.Name, filepath.Base(req.Path))
			break
		}
	}

	_ = s.topologyRepo.Upsert(repositories.TopologyNode{
		ID:     appNodeID,
		Name:   mainAppName,
		Type:   "APPLICATION",
		Status: "ONLINE",
		Risk:   appRisk,
	})

	for _, c := range components {
		if c.Type == "app" {
			continue
		}

		nodeType := "SYSTEM_NODE"
		switch c.Type {
		case "db":
			nodeType = "DATABASE"
		case "cache":
			nodeType = "CACHE"
		case "proxy":
			nodeType = "PROXY"
		case "storage":
			nodeType = "STORAGE"
		case "message_broker":
			nodeType = "MESSAGE_BROKER"
		}

		compRisk := "LOW"
		maxSeverityVal := 0
		severityMap := map[string]int{
			"LOW":      0,
			"INFO":     0,
			"MEDIUM":   1,
			"HIGH":     2,
			"CRITICAL": 3,
		}

		for _, f := range dbFindings {
			fTitle := strings.ToLower(f.Title)
			fDesc := ""
			if f.Description != nil {
				fDesc = strings.ToLower(*f.Description)
			}
			compNameLower := strings.ToLower(c.Name)
			if strings.Contains(fTitle, compNameLower) || strings.Contains(fDesc, compNameLower) {
				sevUpper := strings.ToUpper(f.Severity)
				val := severityMap[sevUpper]
				if val > maxSeverityVal {
					maxSeverityVal = val
					compRisk = sevUpper
				}
			}
		}

		compNodeID := fmt.Sprintf("infra-%d-%s", productID, strings.ToLower(strings.ReplaceAll(c.Name, " ", "-")))
		_ = s.topologyRepo.Upsert(repositories.TopologyNode{
			ID:     compNodeID,
			Name:   c.Name,
			Type:   nodeType,
			Status: "ONLINE",
			Risk:   compRisk,
		})
		_ = s.topologyRepo.UpsertLink(repositories.TopologyLink{Source: appNodeID, Target: compNodeID})
	}

	// 4. Mark engagement completed
	if err := s.engagementRepo.UpdateStatus(ctx, engagementID, "completed"); err != nil {
		slog.Error("Failed to update engagement status", "error", err)
	}

	var stacks []string
	for _, st := range rich.Report.Stacks {
		stacks = append(stacks, string(st))
	}

	duration := time.Since(start).String()
	slog.Info("Scan completed", "path", req.Path, "findings", len(findings), "duration", duration, "product_id", productID, "engagement_id", engagementID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scanResponse{
		Ok:                true,
		ScanID:            scanID,
		BaselinedFindings: baselinedCount,
		Findings:          findings,
		Dependencies:      rich.Report.Dependencies,
		Stacks:            stacks,
		SecurityScore:     rich.Report.SecurityScore,
		SecurityGrade:     rich.Report.SecurityGrade,
		HealthCheck:       rich.Report.HealthCheck,
		ScannerCoverage:   scannerCoverage,
		Scanners:          rich.ScannerExecutions,
		ManifestPath:      manifestPath,
		Duration:          duration,
	})
}

type webScanManifest struct {
	SchemaVersion   int                         `json:"schema_version"`
	ScanID          string                      `json:"scan_id"`
	RequestedPath   string                      `json:"requested_path"`
	ScannerCoverage string                      `json:"scanner_coverage"`
	Scanners        []external.ScannerExecution `json:"scanners"`
	SecurityScore   int                         `json:"security_score"`
	SecurityGrade   string                      `json:"security_grade"`
	CreatedAt       time.Time                   `json:"created_at"`
}

func writeWebScanManifest(reportsDir string, manifest webScanManifest) (string, error) {
	base, err := filepath.Abs(reportsDir)
	if err != nil {
		return "", fmt.Errorf("resolve reports directory: %w", err)
	}
	runDir := filepath.Join(base, "web-scans", manifest.ScanID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return "", fmt.Errorf("create web scan directory: %w", err)
	}
	if err := os.Chmod(runDir, 0o700); err != nil {
		return "", fmt.Errorf("secure web scan directory: %w", err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode scanner manifest: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(runDir, ".manifest-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create scanner manifest: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer cleanup()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	target := filepath.Join(runDir, "manifest.json")
	if err := os.Rename(tmpName, target); err != nil {
		return "", fmt.Errorf("publish scanner manifest: %w", err)
	}
	return filepath.ToSlash(filepath.Join("aitriage-reports", "web-scans", manifest.ScanID, "manifest.json")), nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	err := s.db.PingContext(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "database connection failed"})
		return
	}

	tools := map[string]bool{
		"semgrep":  external.IsInstalled("semgrep"),
		"bandit":   external.IsInstalled("bandit"),
		"gitleaks": external.IsInstalled("gitleaks"),
		"trivy":    external.IsInstalled("trivy"),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    true,
		"tools": tools,
		// Scanning, scoring, the gate verdict and every report format work
		// without a provider. Only triage and the written narrative need one, so
		// the UI can say which half of the product is available rather than
		// letting a user discover it by pressing a button that fails.
		"ai_available": s.llmClient != nil,
	})
}

// handlePrompts serves unified prompt templates from prompts.WebPromptTemplates.
// This is the single source of truth for ALL frontends (Web UI, Command Center, AI Triage Framework).
func (s *Server) handlePrompts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"templates": prompts.WebPromptTemplates,
	})
}

type browserEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Path  string `json:"path"`
}

func (s *Server) handleBrowser(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "."
	}

	fullPath, err := s.resolveProjectPath(path)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		slog.Error("Browser error", "path", fullPath, "err", err)
		if os.IsPermission(err) {
			jsonError(w, "Permission denied for this directory", http.StatusForbidden)
		} else if os.IsNotExist(err) {
			jsonError(w, "Directory not found", http.StatusNotFound)
		} else {
			jsonError(w, "Internal system error accessing directory", http.StatusInternalServerError)
		}
		return
	}

	var res []browserEntry
	for _, e := range entries {
		res = append(res, browserEntry{
			Name:  e.Name(),
			IsDir: e.IsDir(),
			Path:  filepath.Join(path, e.Name()),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"path":    path,
		"entries": res,
	})
}

// ── Admin Maintenance Endpoints ─────────────────────────────────────────────────────────────

func (s *Server) handleClearCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	slog.Warn("Admin requested to clear findings cache")
	queries := []deleteQuery{
		{"finding_notes", "DELETE FROM finding_notes"},
		{"findings", "DELETE FROM findings"},
		{"engagements", "DELETE FROM engagements"},
		{"topology_links", "DELETE FROM topology_links"},
		{"topology_nodes", "DELETE FROM topology_nodes"},
	}
	if err := s.deleteRows(r.Context(), queries); err != nil {
		slog.Error("Failed to clear findings cache", "error", err)
		jsonError(w, "failed to clear cache", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) handlePurgeDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	slog.Warn("Admin requested to PURGE ALL DATA")

	queries := []deleteQuery{
		{"finding_notes", "DELETE FROM finding_notes"},
		{"findings", "DELETE FROM findings"},
		{"engagements", "DELETE FROM engagements"},
		{"product_members", "DELETE FROM product_members"},
		{"products", "DELETE FROM products"},
		{"product_types", "DELETE FROM product_types"},
		{"topology_links", "DELETE FROM topology_links"},
		{"topology_nodes", "DELETE FROM topology_nodes"},
		{"reports", "DELETE FROM reports"},
		{"chat_messages", "DELETE FROM chat_messages"},
		{"chat_sessions", "DELETE FROM chat_sessions"},
		{"audit_log", "DELETE FROM audit_log"},
		{"notifications", "DELETE FROM notifications"},
		{"runway_sessions", "DELETE FROM runway_sessions"},
	}
	if err := s.deleteRows(r.Context(), queries); err != nil {
		slog.Error("Failed to purge database", "error", err)
		jsonError(w, "failed to purge database", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

type deleteQuery struct {
	table string
	query string
}

func (s *Server) deleteRows(ctx context.Context, queries []deleteQuery) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, item := range queries {
		if _, err := tx.ExecContext(ctx, item.query); err != nil {
			return fmt.Errorf("delete %s: %w", item.table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete transaction: %w", err)
	}
	return nil
}

func (s *Server) handleRebuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// A process inside a managed, immutable image cannot rebuild itself. The old
	// implementation only exited, leaving `aitriage web` stopped while claiming
	// a rebuild had started. Fail explicitly and keep the current audit alive.
	jsonError(w, "This Web instance is managed by the AITriage CLI and cannot rebuild itself. Update the CLI/image with `aitriage setup --repair`, then restart `aitriage web`.", http.StatusConflict)
}

func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project string `json:"project"`
		ID      string `json:"id"`
		File    string `json:"file"`
		Action  string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid triage request", http.StatusBadRequest)
		return
	}

	fullProject, err := s.resolveProjectPath(req.Project)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	auditStore := core.NewAuditStore(fullProject)
	status := core.AuditStatusOpen
	switch req.Action {
	case "IGNORE":
		status = core.AuditStatusIgnored
	case "FIX", "TRIAGE":
		status = core.AuditStatusTriage
	}

	err = auditStore.SetStatus(req.ID, req.File, status, "Triage via Web UI")
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func findingIDFromActionPath(path, suffix string) (int64, error) {
	raw := strings.TrimPrefix(path, "/api/findings/")
	raw = strings.TrimSuffix(raw, suffix)
	raw = strings.Trim(raw, "/")
	if raw == "" {
		return 0, fmt.Errorf("missing finding id")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid finding id")
	}
	return id, nil
}

func (s *Server) handleFindingAgentPrompt(w http.ResponseWriter, r *http.Request) {
	findingID, err := findingIDFromActionPath(r.URL.Path, "/agent-prompt")
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	finding, err := s.findingRepo.GetByID(ctx, findingID)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to get finding: %v", err), http.StatusNotFound)
		return
	}

	prompt, sourceAvailable := s.buildAgentPrompt(ctx, finding)
	if r.Method == http.MethodPost {
		if err := s.findingRepo.MarkAgentPromptGenerated(ctx, findingID, prompt); err != nil {
			jsonError(w, fmt.Sprintf("failed to update finding status: %v", err), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":               true,
		"prompt":           prompt,
		"status":           "sent_to_agent",
		"source_available": sourceAvailable,
	})
}

func (s *Server) handleFindingVerification(w http.ResponseWriter, r *http.Request) {
	findingID, err := findingIDFromActionPath(r.URL.Path, "/verify")
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req struct {
		External *bool `json:"external,omitempty"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	ctx := r.Context()
	finding, err := s.findingRepo.GetByID(ctx, findingID)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to get finding: %v", err), http.StatusNotFound)
		return
	}

	scanPath, err := s.resolveFindingScanPath(ctx, finding)
	if err != nil {
		summary := fmt.Sprintf("Verification could not start: %v", err)
		_ = s.findingRepo.MarkVerificationResult(ctx, findingID, false, summary)
		jsonError(w, summary, http.StatusBadRequest)
		return
	}

	if err := s.findingRepo.MarkPendingVerification(ctx, findingID); err != nil {
		jsonError(w, fmt.Sprintf("failed to update finding status: %v", err), http.StatusInternalServerError)
		return
	}

	runExternal := shouldRunExternalForFinding(finding)
	if req.External != nil {
		runExternal = *req.External
	}

	slog.Info("Finding verification started", "finding_id", findingID, "scan_path", scanPath, "external", runExternal)
	rich := orchestrator.RunAllScanners(ctx, orchestrator.Options{
		ProjectPath: scanPath,
		RunExternal: runExternal,
	})

	stillPresent, matchedBy := findingStillPresent(finding, scanPath, &rich)
	var status string
	var summary string
	if stillPresent {
		status = "not_fixed"
		summary = fmt.Sprintf("Verification failed: AITriage still detects this finding (%s). The vulnerability is back in work.", matchedBy)
	} else {
		status = "fixed"
		summary = "Verification passed: AITriage did not detect this finding in the repeated scan."
	}

	if err := s.findingRepo.MarkVerificationResult(ctx, findingID, !stillPresent, summary); err != nil {
		jsonError(w, fmt.Sprintf("failed to save verification result: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"status":     status,
		"fixed":      !stillPresent,
		"summary":    summary,
		"matched_by": matchedBy,
		"scan_path":  scanPath,
		"external":   runExternal,
		"findings":   len(rich.Report.Results) + len(rich.External) + len(rich.NFR) + len(rich.Deploy) + len(rich.Network) + len(rich.HistoryLeaks),
	})
}

func (s *Server) resolveFindingScanPath(ctx context.Context, finding *models.Finding) (string, error) {
	if engagement, err := s.engagementRepo.GetByID(ctx, finding.EngagementID); err == nil && engagement != nil && engagement.ScanPath != nil && *engagement.ScanPath != "" {
		return s.resolveProjectPath(*engagement.ScanPath)
	}

	if finding.ProductID != nil {
		if product, err := s.productRepo.GetByID(ctx, *finding.ProductID); err == nil && product != nil && product.RepoURL != nil && *product.RepoURL != "" {
			return s.resolveProjectPath(*product.RepoURL)
		}
	}

	filePath := stringValue(finding.FilePath)
	if filePath == "" {
		return "", fmt.Errorf("finding has no scan path or file path")
	}
	if filepath.IsAbs(filePath) {
		return s.resolveProjectPath(filepath.Dir(filePath))
	}
	return "", fmt.Errorf("finding has only relative file path %q and no engagement scan path", filePath)
}

func (s *Server) toContainerPath(path string) string {
	resolved, err := s.resolveProjectPath(path)
	if err != nil {
		return ""
	}
	return resolved
}

func shouldRunExternalForFinding(finding *models.Finding) bool {
	switch strings.ToLower(finding.Stack) {
	case "semgrep", "bandit", "trivy", "gitleaks", "git-history":
		return true
	default:
		return false
	}
}

func findingStillPresent(finding *models.Finding, scanPath string, rich *llm.RichScanResult) (bool, string) {
	originalFile := stringValue(finding.FilePath)
	originalLine := intValue(finding.LineNumber)
	title := strings.TrimSpace(strings.ToLower(finding.Title))

	for _, result := range rich.Report.Results {
		if result.ID == finding.RuleID && sameFindingLocation(result.File, originalFile, scanPath) {
			return true, fmt.Sprintf("core rule %s at %s:%d", result.ID, result.File, result.Line)
		}
		if title != "" && strings.EqualFold(result.Name, finding.Title) && sameFindingLocation(result.File, originalFile, scanPath) {
			return true, fmt.Sprintf("core title match at %s:%d", result.File, result.Line)
		}
	}

	for _, ext := range rich.External {
		if ext.RuleID == finding.RuleID && sameFindingLocation(ext.File, originalFile, scanPath) {
			return true, fmt.Sprintf("%s rule %s at %s:%d", ext.Source, ext.RuleID, ext.File, ext.Line)
		}
		if title != "" && strings.Contains(strings.ToLower(ext.Message), title) && sameFindingLocation(ext.File, originalFile, scanPath) {
			return true, fmt.Sprintf("%s message match at %s:%d", ext.Source, ext.File, ext.Line)
		}
	}

	for _, nfr := range rich.NFR {
		if nfr.RuleID == finding.RuleID || strings.EqualFold(nfr.Name, finding.Title) {
			return true, fmt.Sprintf("nfr rule %s", nfr.RuleID)
		}
	}

	for _, deploy := range rich.Deploy {
		deployID := fmt.Sprintf("deploy-%s-%d", filepath.Base(deploy.File), deploy.Line)
		if deployID == finding.RuleID || (strings.EqualFold(deploy.Issue, finding.Title) && sameFindingLocation(deploy.File, originalFile, scanPath)) {
			return true, fmt.Sprintf("deploy finding at %s:%d", deploy.File, deploy.Line)
		}
	}

	for _, network := range rich.Network {
		networkID := fmt.Sprintf("net-%s-%d", network.Target, network.Port)
		if networkID == finding.RuleID || strings.Contains(strings.ToLower(finding.Title), strings.ToLower(network.Target)) {
			return true, fmt.Sprintf("network finding %s:%d", network.Target, network.Port)
		}
	}

	for _, leak := range rich.HistoryLeaks {
		if strings.HasPrefix(finding.RuleID, "gitleak-") && sameFindingLocation(leak.FilePath, originalFile, scanPath) {
			return true, fmt.Sprintf("git history leak in %s", leak.FilePath)
		}
	}

	_ = originalLine
	return false, ""
}

func sameFindingLocation(candidate, original, scanPath string) bool {
	if original == "" {
		return true
	}

	candidates := normalizedPathForms(candidate, scanPath)
	originals := normalizedPathForms(original, scanPath)
	for _, c := range candidates {
		for _, o := range originals {
			if c == o || strings.HasSuffix(c, "/"+o) || strings.HasSuffix(o, "/"+c) {
				return true
			}
		}
	}
	return false
}

func normalizedPathForms(pathValue, scanPath string) []string {
	if pathValue == "" {
		return nil
	}
	forms := []string{normalizePath(pathValue)}
	if scanPath != "" && filepath.IsAbs(pathValue) {
		if rel, err := filepath.Rel(scanPath, pathValue); err == nil {
			forms = append(forms, normalizePath(rel))
		}
	}
	if scanPath != "" && !filepath.IsAbs(pathValue) {
		forms = append(forms, normalizePath(filepath.Join(scanPath, pathValue)))
	}
	return forms
}

func normalizePath(pathValue string) string {
	cleaned := filepath.Clean(pathValue)
	cleaned = filepath.ToSlash(cleaned)
	cleaned = strings.TrimPrefix(cleaned, "./")
	return strings.Trim(cleaned, "/")
}

func (s *Server) buildAgentPrompt(ctx context.Context, finding *models.Finding) (string, bool) {
	projectName := "unknown"
	projectStack := ""
	productCriticality := ""
	if finding.ProductID != nil {
		if product, err := s.productRepo.GetByID(ctx, *finding.ProductID); err == nil && product != nil {
			projectName = product.Name
			if product.TechStack != nil {
				projectStack = *product.TechStack
			}
			productCriticality = product.BusinessCriticality
		}
	}

	engagementName := ""
	scanPath := ""
	if engagement, err := s.engagementRepo.GetByID(ctx, finding.EngagementID); err == nil && engagement != nil {
		engagementName = engagement.Name
		if engagement.ScanPath != nil {
			scanPath = *engagement.ScanPath
		}
	}

	filePath := stringValue(finding.FilePath)
	lineNumber := intValue(finding.LineNumber)
	fullFindingPath := filePath
	if scanPath != "" && filePath != "" && !filepath.IsAbs(filePath) {
		fullFindingPath = filepath.Join(scanPath, filePath)
	}
	scanPathLocal, scanPathRuntime := s.promptLocalAndRuntimePath(scanPath)
	findingPathLocal, findingPathRuntime := s.promptLocalAndRuntimePath(fullFindingPath)
	repoRelativePath := repositoryRelativePath(scanPath, fullFindingPath, filePath)
	repoLocation := formatPromptLocation(repoRelativePath, lineNumber)
	locationLocal := formatPromptLocation(findingPathLocal, lineNumber)
	locationRuntime := formatPromptLocation(findingPathRuntime, lineNumber)
	runtimeScanPathLine := runtimePathLine("AITriage container scan path", scanPathRuntime, scanPathLocal)
	runtimeLocationLine := runtimePathLine("AITriage container location", locationRuntime, locationLocal)
	hostLocationLine := hostPathLine("Host location (detected)", locationLocal, repoLocation, locationRuntime)
	sourceContext, sourceAvailable := s.readFindingSourceContext(scanPath, filePath, repoRelativePath, lineNumber, 4)

	description := redactPromptText(fallbackString(finding.Description, "No description provided."))
	recommendation := redactPromptText(fallbackString(finding.FixSuggestion, ""))
	recommendationSection := ""
	if strings.TrimSpace(recommendation) != "" && !strings.EqualFold(strings.TrimSpace(description), strings.TrimSpace(recommendation)) {
		recommendationSection = fmt.Sprintf("\n## Existing Recommendation\n%s\n", recommendation)
	}

	return fmt.Sprintf(`AITriage generated this AGENT PROMPT from a stored finding. It is not an LLM answer.

## Mission
Fix exactly this finding with the smallest correct code/config change, then prove it with project tests and AITriage VERIFY FIX.

## Target
- Project: %s
- Engagement: %s
- Scan root: %s
%s
- Product criticality: %s
- Product tech stack: %s

## Finding Evidence
- AITriage finding ID: %d
- Rule ID: %s
- Title: %s
- Severity: %s
- Scanner / stack: %s
- Repository-relative location: %s
%s
%s
- CWE: %s
- CVE: %s

## Issue
%s
%s
## Remediation Guidance
%s

## Source Excerpt (redacted)
%s

## Required Workflow
1. Inspect the local repository before editing.
2. Fix the root cause at the trust boundary; avoid unrelated refactors.
3. Add or update focused regression coverage when the project has a suitable test layer.
4. Run the relevant tests/build commands for the touched project.
5. Run AITriage VERIFY FIX. Success means AITriage no longer reports rule '%s' for this finding location.
6. Report files changed, root cause, fix summary, verification results, and remaining risk.

## Important Constraints
- Do not mark this fixed only because code changed; the scanner must stop detecting this finding.
- Do not paste or commit secrets. If a real secret was exposed, rotate/revoke it outside the code change and mention that in the report.
- If the finding cannot be fixed safely with available context, explain the blocker and the exact missing information.
`, projectName, engagementName, scanPathLocal, runtimeScanPathLine, productCriticality, projectStack,
		finding.ID, finding.RuleID, finding.Title, finding.Severity, finding.Stack, repoLocation, hostLocationLine, runtimeLocationLine,
		stringValue(finding.CWEID), stringValue(finding.CVEID), description, recommendationSection,
		findingPromptGuidance(finding), sourceContext, finding.RuleID), sourceAvailable
}

func repositoryRelativePath(scanPath, fullFindingPath, originalFilePath string) string {
	if originalFilePath != "" && !portableAbsolutePath(originalFilePath) {
		return filepath.ToSlash(originalFilePath)
	}
	if scanPath != "" && fullFindingPath != "" {
		scanSlash := strings.ReplaceAll(scanPath, `\`, "/")
		findingSlash := strings.ReplaceAll(fullFindingPath, `\`, "/")
		if strings.HasPrefix(scanSlash, "/") && strings.HasPrefix(findingSlash, "/") {
			scanSlash = strings.TrimSuffix(pathpkg.Clean(scanSlash), "/")
			findingSlash = pathpkg.Clean(findingSlash)
			if prefix := scanSlash + "/"; strings.HasPrefix(findingSlash, prefix) {
				return strings.TrimPrefix(findingSlash, prefix)
			}
		}
		if rel, err := filepath.Rel(scanPath, fullFindingPath); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(fullFindingPath)
}

func portableAbsolutePath(value string) bool {
	return filepath.IsAbs(value) || strings.HasPrefix(strings.ReplaceAll(value, `\`, "/"), "/")
}

func (s *Server) promptLocalAndRuntimePath(pathValue string) (string, string) {
	if pathValue == "" {
		return "", ""
	}
	if s.hostPrefix == "" || !strings.HasPrefix(pathValue, s.hostPrefix) {
		return pathValue, ""
	}

	if mountInfo, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		if localPath, ok := localPathForHostPrefix(s.hostPrefix, pathValue, string(mountInfo)); ok {
			return localPath, pathValue
		}
	}

	rel := strings.TrimPrefix(pathValue, s.hostPrefix)
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "/")
	if rel == "" {
		return "host mount root (the directory mounted to " + s.hostPrefix + ")", pathValue
	}
	return filepath.ToSlash(filepath.Join("host mount root", rel)), pathValue
}

func runtimePathLine(label, runtimePath, localPath string) string {
	if runtimePath == "" || runtimePath == localPath {
		return ""
	}
	return fmt.Sprintf("- %s: %s (runtime only; do not use this as the host edit path)", label, runtimePath)
}

func hostPathLine(label, hostPath, repoPath, runtimePath string) string {
	if hostPath == "" || hostPath == repoPath || hostPath == runtimePath || strings.HasPrefix(hostPath, "host mount root") {
		return ""
	}
	return fmt.Sprintf("- %s: %s", label, hostPath)
}

func formatPromptLocation(pathValue string, lineNumber int) string {
	if lineNumber <= 0 || pathValue == "" {
		return pathValue
	}
	return fmt.Sprintf("%s:%d", pathValue, lineNumber)
}

func localPathForHostPrefix(hostPrefix, pathValue, mountInfo string) (string, bool) {
	hostRoot, ok := hostRootForPrefix(hostPrefix, mountInfo)
	if !ok {
		return "", false
	}
	rel := strings.TrimPrefix(pathValue, hostPrefix)
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "/")
	if rel == "" {
		return hostRoot, true
	}
	return filepath.ToSlash(filepath.Join(hostRoot, rel)), true
}

func hostRootForPrefix(hostPrefix, mountInfo string) (string, bool) {
	for _, line := range strings.Split(mountInfo, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			continue
		}
		pre := strings.Fields(parts[0])
		post := strings.Fields(parts[1])
		if len(pre) < 5 || len(post) < 2 {
			continue
		}
		root := pre[3]
		mountPoint := pre[4]
		source := post[1]
		if mountPoint != hostPrefix {
			continue
		}
		if strings.HasPrefix(source, "/run/host_mark/") {
			hostBase := "/" + strings.TrimPrefix(source, "/run/host_mark/")
			return filepath.ToSlash(filepath.Join(hostBase, strings.TrimPrefix(root, "/"))), true
		}
		if filepath.IsAbs(source) {
			return filepath.ToSlash(filepath.Join(source, strings.TrimPrefix(root, "/"))), true
		}
	}
	return "", false
}

func findingPromptGuidance(finding *models.Finding) string {
	haystack := strings.ToLower(strings.Join([]string{
		finding.RuleID,
		finding.Title,
		finding.Stack,
		stringValue(finding.Description),
		stringValue(finding.FixSuggestion),
	}, " "))

	switch {
	case strings.Contains(haystack, "gitleaks") ||
		strings.Contains(haystack, "secret") ||
		strings.Contains(haystack, "password") ||
		strings.Contains(haystack, "token") ||
		strings.Contains(haystack, "jwt"):
		return `- Remove the exposed credential/token from tracked source, generated reports, fixtures, or docs.
- Replace it with a safe placeholder, environment variable reference, or test-only dummy value that scanners do not classify as a secret.
- If the secret could be real, rotate/revoke it outside the repository and include that in the final report.`
	case strings.Contains(haystack, "flask") && strings.Contains(haystack, "debug"):
		return `- Ensure production startup never enables Flask debug mode.
- Gate debug mode behind an explicit local-development configuration that defaults to false.
- Prefer environment/config parsing over hardcoded debug=True.`
	case strings.Contains(haystack, "ssti") || strings.Contains(haystack, "template injection"):
		return `- Do not render user-controlled strings as templates.
- Use static templates and pass user input only as escaped data.
- Add a regression case with template syntax in user input.`
	case strings.Contains(haystack, "async") && (strings.Contains(haystack, "blocking") || strings.Contains(haystack, "sync")):
		return `- Remove blocking synchronous database work from the async request path.
- Use the project's async database/session API, or move blocking work to a controlled worker boundary.
- Add a test or deterministic check that exercises the async handler.`
	default:
		return `- Trace untrusted input to the vulnerable sink named by the finding.
- Fix the boundary condition rather than suppressing the scanner result.
- Keep the patch minimal and prove the scanner result disappears.`
	}
}

var (
	promptJWTRegex         = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}`)
	promptKnownSecretRegex = regexp.MustCompile(`(?i)\b(?:AKIA[0-9A-Z]{16}|gh[ps]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9\-_]{20,}|sk_live_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
	promptNamedSecretRegex = regexp.MustCompile("(?i)((?:password|passwd|token|secret|api[_-]?key|jwt)[^\\n:=]{0,40}\\s*[:=]\\s*)[`\"']?[^`\"'\\s]{8,}([`\"']?)")
)

func redactPromptText(text string) string {
	text = promptJWTRegex.ReplaceAllString(text, "[REDACTED_JWT]")
	text = promptKnownSecretRegex.ReplaceAllString(text, "[REDACTED_SECRET]")
	text = promptNamedSecretRegex.ReplaceAllString(text, "${1}[REDACTED]")
	return text
}

func sanitizePromptSourceLine(line string) string {
	line = redactPromptText(line)
	return strings.ReplaceAll(line, "```", "'''")
}

func (s *Server) readFindingSourceContext(scanPath, filePath, displayFilePath string, lineNumber, radius int) (string, bool) {
	if filePath == "" {
		return "Source context unavailable: finding has no file path.", false
	}
	if displayFilePath == "" {
		displayFilePath = filePath
	}

	fullPath := filePath
	if scanPath != "" && !filepath.IsAbs(filePath) {
		fullPath = filepath.Join(scanPath, filePath)
	}
	resolvedPath, err := s.resolveProjectPath(fullPath)
	if err != nil {
		return fmt.Sprintf("Source context unavailable: %v.", err), false
	}
	fullPath = resolvedPath

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Sprintf("Source context unavailable: could not read %s (%v).", fullPath, err), false
	}

	lines := strings.Split(string(data), "\n")
	if lineNumber <= 0 || lineNumber > len(lines) {
		limit := len(lines)
		if limit > 160 {
			limit = 160
		}
		if limit > 12 {
			limit = 12
		}
		for i := 0; i < limit; i++ {
			lines[i] = sanitizePromptSourceLine(lines[i])
		}
		return fmt.Sprintf("File: %s\n```text\n%s\n```", displayFilePath, strings.Join(lines[:limit], "\n")), true
	}

	lineIdx := lineNumber - 1
	start := lineIdx - radius
	if start < 0 {
		start = 0
	}
	end := lineIdx + radius + 1
	if end > len(lines) {
		end = len(lines)
	}

	var snippet []string
	for i := start; i < end; i++ {
		prefix := "   "
		if i == lineIdx {
			prefix = ">> "
		}
		snippet = append(snippet, fmt.Sprintf("%s%d: %s", prefix, i+1, sanitizePromptSourceLine(lines[i])))
	}
	return fmt.Sprintf("File: %s\n```text\n%s\n```", displayFilePath, strings.Join(snippet, "\n")), true
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func intValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func fallbackString(value *string, fallback string) string {
	if value == nil || strings.TrimSpace(*value) == "" {
		return fallback
	}
	return *value
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if s.llmClient == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": llmUnavailableMessage,
		})
		return
	}

	var req struct {
		Messages []llm.Message `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid chat request", http.StatusBadRequest)
		return
	}

	// Build security context from findings database
	ctx := r.Context()
	var systemCtx strings.Builder

	// Use the unified SecureCoderFramework from templates.go (same as CI/CD pipeline)
	systemCtx.WriteString(prompts.SecureCoderFramework)
	systemCtx.WriteString("\n\nYou also serve as an interactive Security Consultant with access to scan results.\n")
	systemCtx.WriteString("Answer in the user's language, but keep technical labels, file paths, commands, and code in their original form.\n\n")

	// Get product (project) list
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, COALESCE(repo_url,'') FROM products ORDER BY name`)
	if err == nil {
		defer func() { _ = rows.Close() }()
		systemCtx.WriteString("## Scanned Projects\n")
		for rows.Next() {
			var id int64
			var name, repoURL string
			_ = rows.Scan(&id, &name, &repoURL)
			var crit, high, med, low int
			_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END),0) FROM findings WHERE product_id=?`, id).Scan(&crit, &high, &med, &low)
			systemCtx.WriteString(fmt.Sprintf("- **%s** (path: %s): %d critical, %d high, %d medium, %d low\n", name, repoURL, crit, high, med, low))
		}
		systemCtx.WriteString("\n")
	}

	// Get top critical/high findings (up to 30 for context)
	frows, err := s.db.QueryContext(ctx, `
		SELECT f.title, f.severity, COALESCE(f.file_path,''), COALESCE(f.line_number,0), COALESCE(f.description,''), COALESCE(p.name,'unknown')
		FROM findings f LEFT JOIN products p ON f.product_id = p.id
		WHERE f.severity IN ('critical','high') AND f.status NOT IN ('triage','false_positive','risk_accepted')
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 END, f.id
		LIMIT 30
	`)
	if err == nil {
		defer func() { _ = frows.Close() }()
		systemCtx.WriteString("## Top Critical & High Findings\n")
		for frows.Next() {
			var title, severity, filePath, desc, project string
			var lineNum int
			_ = frows.Scan(&title, &severity, &filePath, &lineNum, &desc, &project)
			loc := filePath
			if lineNum > 0 {
				loc = fmt.Sprintf("%s:%d", filePath, lineNum)
			}
			systemCtx.WriteString(fmt.Sprintf("- [%s][%s] **%s** at `%s`\n", strings.ToUpper(severity), project, title, loc))
			if desc != "" && len(desc) < 200 {
				systemCtx.WriteString(fmt.Sprintf("  %s\n", desc))
			}
		}
		systemCtx.WriteString("\n")
	}

	// Get overall stats
	var totalFindings, openFindings int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&totalFindings)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE status NOT IN ('triage','false_positive','risk_accepted')`).Scan(&openFindings)
	systemCtx.WriteString(fmt.Sprintf("## Stats: %d total findings, %d open/active.\n\n", totalFindings, openFindings))

	// Response mode instructions
	systemCtx.WriteString("## Response Modes\n")
	systemCtx.WriteString("AI_IDE_PROMPT_MODE: Use this when the user asks for a prompt, AI IDE, Cursor, Windsurf, Copilot, repository-wide fix, or something they will copy into an IDE. Return a ready-to-copy prompt, preferably in one fenced text block. The prompt must include: role, objective, scan context, prioritized findings with file:line, SecureCoder constraints, implementation rules, verification commands/tests, and required final report format. Do not wrap it in a chatty explanation.\n")
	systemCtx.WriteString("EXPLANATION_MODE: For questions that are not asking for an IDE prompt, answer with short sections: Priority, Why it matters, Fix, Verify. Include code only when it is directly useful.\n")
	systemCtx.WriteString("REMEDIATION_MODE: When asked to fix one finding, provide root cause, minimal patch strategy, before/after guidance, exploit/blocked verification, and a regression test.\n\n")
	systemCtx.WriteString("## AI IDE Prompt Requirements\n")
	systemCtx.WriteString("When generating prompts for another coding agent, instruct it to inspect the repository before editing, make minimal targeted changes, preserve public APIs unless security requires otherwise, avoid unrelated refactors, update/add focused tests, run the relevant verification commands, and report files changed plus remaining risks.\n")

	// Prepend system message with context
	messages := make([]llm.Message, 0, len(req.Messages)+1)
	messages = append(messages, llm.Message{Role: "system", Content: systemCtx.String()})
	for _, msg := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		if role == "system" {
			continue
		}
		if role != "user" && role != "assistant" {
			continue
		}
		messages = append(messages, llm.Message{Role: role, Content: msg.Content})
	}

	reply, _, err := s.llmClient.Chat(ctx, messages)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"content": reply,
	})
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if s.llmClient == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": "AI Consultant is offline.",
		})
		return
	}

	var req struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid analysis request", http.StatusBadRequest)
		return
	}

	var fTitle, fDesc, fCode, fFile, fSeverity string
	var fLine int
	findingID, err := strconv.ParseInt(req.ID, 10, 64)
	if err == nil {
		finding, err := s.findingRepo.GetByID(r.Context(), findingID)
		if err == nil && finding != nil {
			fTitle = finding.Title
			fSeverity = finding.Severity
			if finding.Description != nil {
				fDesc = *finding.Description
			}
			if finding.CodeSnippet != nil {
				fCode = *finding.CodeSnippet
			}
			if finding.FilePath != nil {
				fFile = *finding.FilePath
			}
			if finding.LineNumber != nil {
				fLine = *finding.LineNumber
			}
		}
	}

	prompt := fmt.Sprintf(`Please analyze this security finding:
Title: %s
Severity: %s
File: %s:%d
Description: %s
Code Snippet:
%s

Your task is to:
1. Determine if this finding is a True Positive (valid vulnerability) or a False Positive. Explain your reasoning in detail.
2. Provide a detailed, context-aware remediation plan if it is a True Positive, with clear fixed code examples.
3. Suggest a verification plan to check if the fix is correct.`, fTitle, fSeverity, fFile, fLine, fDesc, fCode)

	messages := []llm.Message{
		{
			Role:    "system",
			Content: prompts.SecureCoderFramework + "\n\nYou are performing a detailed single-finding analysis. Determine if this is a True Positive, False Positive, or Needs Human Review. Provide exploitability assessment, impact analysis, and if True Positive — a remediation plan with fixed code examples.",
		},
		{Role: "user", Content: prompt},
	}

	analysis, _, err := s.llmClient.Chat(r.Context(), messages)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"analysis": analysis,
	})
}

func (s *Server) handleAITriage(w http.ResponseWriter, r *http.Request) {
	if s.llmClient == nil {
		jsonError(w, llmUnavailableMessage, http.StatusServiceUnavailable)
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/findings/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		jsonError(w, "missing finding id", http.StatusBadRequest)
		return
	}
	findingID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		jsonError(w, "invalid finding id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	finding, err := s.findingRepo.GetByID(ctx, findingID)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to get finding: %v", err), http.StatusNotFound)
		return
	}

	slog.Info("AI Triage started", "finding_id", findingID, "title", finding.Title, "severity", finding.Severity)

	// 1. Resolve code file context
	var fileContent string
	var fullPath string
	if finding.FilePath != nil && *finding.FilePath != "" {
		eng, err := s.engagementRepo.GetByID(ctx, finding.EngagementID)
		if err == nil && eng != nil && eng.ScanPath != nil && *eng.ScanPath != "" {
			fullPath = filepath.Join(*eng.ScanPath, *finding.FilePath)
		} else {
			prod, err := s.productRepo.GetByID(ctx, *finding.ProductID)
			if err == nil && prod != nil && prod.RepoURL != nil && *prod.RepoURL != "" {
				fullPath = filepath.Join(*prod.RepoURL, *finding.FilePath)
			} else {
				fullPath = *finding.FilePath
			}
		}
		if resolved, resolveErr := s.resolveProjectPath(fullPath); resolveErr == nil {
			fullPath = resolved
		} else {
			slog.Warn("AI Triage: rejected source path", "path", fullPath, "error", resolveErr)
			fullPath = ""
		}

		data, err := os.ReadFile(fullPath)
		if err != nil {
			slog.Warn("AI Triage: could not read source file", "path", fullPath, "error", err)
		} else {
			lines := strings.Split(string(data), "\n")
			if finding.LineNumber != nil && *finding.LineNumber > 0 {
				lineIdx := *finding.LineNumber - 1
				start := lineIdx - 40
				if start < 0 {
					start = 0
				}
				end := lineIdx + 40
				if end > len(lines) {
					end = len(lines)
				}
				var snippet []string
				for i := start; i < end; i++ {
					prefix := "   "
					if i == lineIdx {
						prefix = ">> "
					}
					snippet = append(snippet, fmt.Sprintf("%s%d: %s", prefix, i+1, lines[i]))
				}
				fileContent = strings.Join(snippet, "\n")
			} else {
				// Limit to first 200 lines if no specific line
				if len(lines) > 200 {
					fileContent = strings.Join(lines[:200], "\n") + "\n... (truncated)"
				} else {
					fileContent = string(data)
				}
			}
		}
	}

	// 2. Collect ALL available finding metadata for rich context
	fTitle := finding.Title
	fSeverity := finding.Severity
	fRuleID := finding.RuleID
	fStack := finding.Stack

	// Fetch project (product) and engagement for full context
	var productName, productTechStack, productPlatform, productCriticality string
	var engagementName, scanPath string
	if finding.ProductID != nil {
		prod, err := s.productRepo.GetByID(ctx, *finding.ProductID)
		if err == nil && prod != nil {
			productName = prod.Name
			if prod.TechStack != nil {
				productTechStack = *prod.TechStack
			}
			if prod.Platform != nil {
				productPlatform = *prod.Platform
			}
			productCriticality = prod.BusinessCriticality
		}
	}
	eng, err := s.engagementRepo.GetByID(ctx, finding.EngagementID)
	if err == nil && eng != nil {
		engagementName = eng.Name
		if eng.ScanPath != nil {
			scanPath = *eng.ScanPath
		}
	}

	// Build a comprehensive context block
	fFile := ""
	if finding.FilePath != nil {
		fFile = *finding.FilePath
	}
	fLine := 0
	if finding.LineNumber != nil {
		fLine = *finding.LineNumber
	}
	fDesc := ""
	if finding.Description != nil {
		fDesc = *finding.Description
	}
	fCode := ""
	if finding.CodeSnippet != nil {
		fCode = *finding.CodeSnippet
	}
	fFixSuggestion := ""
	if finding.FixSuggestion != nil {
		fFixSuggestion = *finding.FixSuggestion
	}
	fImpact := ""
	if finding.Impact != nil {
		fImpact = *finding.Impact
	}
	fCWE := ""
	if finding.CWEID != nil {
		fCWE = *finding.CWEID
	}
	fCVE := ""
	if finding.CVEID != nil {
		fCVE = *finding.CVEID
	}

	var contextParts []string
	if productName != "" {
		contextParts = append(contextParts, fmt.Sprintf("Project: %s", productName))
	}
	if productTechStack != "" {
		contextParts = append(contextParts, fmt.Sprintf("Tech Stack: %s", productTechStack))
	}
	if productPlatform != "" {
		contextParts = append(contextParts, fmt.Sprintf("Platform: %s", productPlatform))
	}
	if productCriticality != "" {
		contextParts = append(contextParts, fmt.Sprintf("Business Criticality: %s", productCriticality))
	}
	if engagementName != "" {
		contextParts = append(contextParts, fmt.Sprintf("Engagement: %s", engagementName))
	}
	if scanPath != "" {
		contextParts = append(contextParts, fmt.Sprintf("Scan Path: %s", scanPath))
	}
	contextParts = append(contextParts, fmt.Sprintf("Title: %s", fTitle))
	contextParts = append(contextParts, fmt.Sprintf("Severity: %s", fSeverity))
	contextParts = append(contextParts, fmt.Sprintf("Scanner / Stack: %s", fStack))
	contextParts = append(contextParts, fmt.Sprintf("Rule ID: %s", fRuleID))
	if fFile != "" {
		contextParts = append(contextParts, fmt.Sprintf("File Path: %s", fFile))
	}
	if fLine > 0 {
		contextParts = append(contextParts, fmt.Sprintf("Line Number: %d", fLine))
	}
	if fCWE != "" {
		contextParts = append(contextParts, fmt.Sprintf("CWE: %s", fCWE))
	}
	if fCVE != "" {
		contextParts = append(contextParts, fmt.Sprintf("CVE: %s", fCVE))
	}
	if fDesc != "" {
		contextParts = append(contextParts, fmt.Sprintf("Description: %s", fDesc))
	}
	if fFixSuggestion != "" {
		contextParts = append(contextParts, fmt.Sprintf("Remediation / Fix Suggestion: %s", fFixSuggestion))
	}
	if fImpact != "" {
		contextParts = append(contextParts, fmt.Sprintf("Impact: %s", fImpact))
	}
	if fCode != "" {
		contextParts = append(contextParts, fmt.Sprintf("Code Snippet from Scanner:\n```\n%s\n```", fCode))
	}

	findingContext := strings.Join(contextParts, "\n")

	var codeContextBlock string
	if fileContent != "" {
		codeContextBlock = fmt.Sprintf("Source Code Context (from %s around line %d):\n```\n%s\n```", fFile, fLine, fileContent)
	} else {
		codeContextBlock = "Source Code Context: Not available (file could not be read). Perform triage based on the finding details, vulnerability type, project context, and your security expertise."
	}

	prompt := fmt.Sprintf(`## Vulnerability Finding
%s

## %s

## Triage Methodology

Evaluate this finding using the following criteria (based on SecureCoder threat model analysis):

### 1. Reachability Analysis
- Is the flagged code reachable from an **untrusted entry point** (HTTP handler, CLI arg, file input, user-controlled data)?
- Or is it only reachable from trusted internal code paths?

### 2. Trust Boundary & Auth Context
- Does the project's **authentication/authorization** context mitigate the risk?
- Are there **implicit trust assumptions** (e.g., "only internal services call this") that make exploitation unlikely?
- Does the data cross **trust boundaries** (frontend→backend, user→admin)?

### 3. Exploitability Assessment
- Is the vulnerability **actually exploitable** given the deployment context (web app, CLI tool, internal service)?
- Are there existing **mitigations** in place (input validation, sanitization, parameterized queries, CSP headers, rate limiting)?
- Would an attacker realistically be able to trigger this code path with malicious input?

### 4. Vulnerability-Specific Checks
For common vulnerability types, check:
- **Path Traversal**: Does the code normalize or reject "../" sequences? Is the resolved path validated?
- **XSS**: Is user input escaped/sanitized before DOM insertion? Are Content-Security-Policy headers set?
- **SQL Injection**: Are parameterized queries/prepared statements used? Or is there string concatenation?
- **SSRF**: Are target URLs validated and restricted? Are internal IP ranges blocked?
- **Hardcoded Secrets**: Is this a real secret or a placeholder/test value? Is it in a test/example file?
- **Missing Rate Limiting**: Is this an authentication endpoint or public-facing API that needs rate limiting?
- **Insecure Deserialization**: Are safe deserialization methods used? Are types restricted?

### 5. Classification

| Disposition | Criteria |
|---|---|
| **True Positive** | Code IS reachable from untrusted input, vulnerability IS exploitable, no sufficient mitigations exist |
| **False Positive** | Code is NOT reachable from untrusted input, OR mitigations already exist, OR scanner pattern match is incorrect, OR this is intended functionality |
| **Needs Review** | Insufficient context to determine reachability or exploitability; requires manual security engineer review |

## Response Format
Return ONLY a valid JSON object with no other text:
{
  "status": "true_positive" | "false_positive" | "needs_review",
  "summary": "Specific explanation (1-3 sentences): state WHY — which exact code is vulnerable/protected, which entry points are involved, which mitigations exist or are missing"
}`, findingContext, codeContextBlock)

	slog.Info("AI Triage prompt built", "finding_id", findingID, "has_code_context", fileContent != "", "prompt_len", len(prompt))

	// Use the unified TriageSystemPrompt from templates.go (same as CI/CD pipeline)
	messages := []llm.Message{
		{
			Role:    "system",
			Content: prompts.TriageSystemPrompt + "\n\nCRITICAL: You output ONLY valid JSON. No markdown, no explanations, just the JSON object.",
		},
		{Role: "user", Content: prompt},
	}

	reply, _, err := s.llmClient.Chat(ctx, messages)
	if err != nil {
		slog.Error("AI Triage LLM error", "finding_id", findingID, "error", err)
		jsonError(w, fmt.Sprintf("LLM chat error: %v", err), http.StatusInternalServerError)
		return
	}

	slog.Info("AI Triage LLM response received", "finding_id", findingID, "reply_len", len(reply))

	// Parse JSON response — handle ```json blocks and bare JSON
	cleaned := reply
	if idx := strings.Index(cleaned, "```json"); idx != -1 {
		cleaned = cleaned[idx+7:]
		if endIdx := strings.Index(cleaned, "```"); endIdx != -1 {
			cleaned = cleaned[:endIdx]
		}
	} else if idx := strings.Index(cleaned, "```"); idx != -1 {
		cleaned = cleaned[idx+3:]
		if endIdx := strings.Index(cleaned, "```"); endIdx != -1 {
			cleaned = cleaned[:endIdx]
		}
	}
	// Also try to extract JSON from { to }
	cleaned = strings.TrimSpace(cleaned)
	if !strings.HasPrefix(cleaned, "{") {
		if braceIdx := strings.Index(cleaned, "{"); braceIdx != -1 {
			cleaned = cleaned[braceIdx:]
		}
	}
	if lastBrace := strings.LastIndex(cleaned, "}"); lastBrace != -1 {
		cleaned = cleaned[:lastBrace+1]
	}

	var triageRes struct {
		Status  string `json:"status"`
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal([]byte(cleaned), &triageRes); err != nil {
		slog.Warn("AI Triage JSON parse failed, using fallback", "finding_id", findingID, "error", err, "raw", reply[:min(len(reply), 200)])
		triageRes.Status = "needs_review"
		// Extract something useful from the raw reply
		triageRes.Summary = "AI analysis could not return a structured response. Manual review required. AI response: " + reply
		if len(triageRes.Summary) > 500 {
			triageRes.Summary = triageRes.Summary[:500] + "..."
		}
	}

	// Validate status
	switch triageRes.Status {
	case "true_positive", "false_positive", "needs_review":
		// valid
	default:
		slog.Warn("AI Triage returned unknown status, defaulting to needs_review", "finding_id", findingID, "status", triageRes.Status)
		triageRes.Status = "needs_review"
	}

	slog.Info("AI Triage completed", "finding_id", findingID, "status", triageRes.Status)

	// 3. Update database
	err = s.findingRepo.UpdateAITriage(ctx, findingID, triageRes.Status, triageRes.Summary)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to update finding AI triage: %v", err), http.StatusInternalServerError)
		return
	}

	// If False Positive, automatically update the finding status
	switch triageRes.Status {
	case "false_positive":
		_ = s.findingRepo.UpdateStatus(ctx, findingID, "false_positive")
		_, _ = s.db.ExecContext(ctx, "UPDATE findings SET is_false_positive = 1, fp_reason = ? WHERE id = ?", triageRes.Summary, findingID)
	case "true_positive":
		_ = s.findingRepo.UpdateStatus(ctx, findingID, "triage")
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"status":  triageRes.Status,
		"summary": triageRes.Summary,
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rules := make([]engine.Rule, 0)
	if s.engine != nil {
		rules = s.engine.Rules
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    true,
		"rules": rules,
	})
}

func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		jsonError(w, "path is required", http.StatusBadRequest)
		return
	}

	fullPath, err := s.resolveProjectPath(path)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	content, err := os.ReadFile(fullPath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"content": string(content),
	})
}

func (s *Server) Listen(addr string) error {
	slog.Info("AITriage Web UI started", "url", "http://"+addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	return server.ListenAndServe()
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type aiSummaryCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Other    int
}

func (c aiSummaryCounts) total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Other
}

type aiSummaryFinding struct {
	RuleID          string
	Title           string
	Severity        string
	File            string
	Line            int
	Description     string
	FixSuggestion   string
	Status          string
	Stack           string
	AITriageStatus  string
	AITriageSummary string
	IsFalsePositive bool
}

type aiSummaryEvidence struct {
	ProductID           int
	ProductName         string
	RepoPath            string
	ScanPath            string
	TechStack           string
	Platform            string
	BusinessCriticality string
	Lifecycle           string
	ProjectShape        []string
	LocalAuditExcerpt   string
	ActiveCounts        aiSummaryCounts
	SuppressedCounts    aiSummaryCounts
	Findings            []aiSummaryFinding
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	productID, useProduct := parseOptionalInt(r.URL.Query().Get("product_id"))
	lang := normalizedSummaryLang(r.URL.Query().Get("lang"))
	generate := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("generate")), "true")

	// Default (page load): return the previously generated summary from storage
	// without spending an LLM call, so it survives refreshes. Only regenerate
	// when the user explicitly asks (the "Generate" button sends generate=true).
	if !generate && useProduct {
		if stored, at, ok := s.loadStoredAISummary(r.Context(), productID, lang); ok {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"summary":      stored,
				"generated_at": at,
				"generated":    true,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "summary": "", "generated": false})
		return
	}

	evidence, err := s.loadAISummaryEvidence(r.Context(), productID, useProduct)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to build summary evidence: %v", err), http.StatusInternalServerError)
		return
	}

	var summary string
	if s.llmClient != nil && (evidence.ActiveCounts.total() > 0 || evidence.SuppressedCounts.total() > 0) {
		messages := []llm.Message{
			{Role: "system", Content: buildAISummarySystemPrompt(lang)},
			{Role: "user", Content: buildAISummaryUserPrompt(evidence, lang)},
		}
		reply, _, err := s.llmClient.Chat(r.Context(), messages)
		if err == nil && strings.TrimSpace(reply) != "" {
			summary = strings.TrimSpace(reply)
		}
	}

	if summary == "" {
		summary = buildAISummaryFallback(evidence, lang)
	}

	// Persist so the generated text survives page refreshes.
	if useProduct {
		s.storeAISummary(r.Context(), productID, lang, summary)
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"summary":   summary,
		"generated": true,
	})
}

// loadStoredAISummary returns the persisted AI summary for a product+lang.
func (s *Server) loadStoredAISummary(ctx context.Context, productID int, lang string) (string, string, bool) {
	var summary, generatedAt string
	err := s.db.QueryRowContext(ctx,
		"SELECT summary, generated_at FROM ai_summaries WHERE product_id = ? AND lang = ?",
		productID, lang).Scan(&summary, &generatedAt)
	if err != nil || strings.TrimSpace(summary) == "" {
		return "", "", false
	}
	return summary, generatedAt, true
}

// storeAISummary upserts the generated AI summary so it persists across reloads.
func (s *Server) storeAISummary(ctx context.Context, productID int, lang, summary string) {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ai_summaries (product_id, lang, summary, generated_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(product_id, lang) DO UPDATE SET summary = excluded.summary, generated_at = CURRENT_TIMESTAMP`,
		productID, lang, summary)
	if err != nil {
		slog.Error("Failed to persist AI summary", "product_id", productID, "lang", lang, "error", err)
	}
}

func parseOptionalInt(value string) (int, bool) {
	if strings.TrimSpace(value) == "" {
		return 0, false
	}
	n, err := strconv.Atoi(value)
	return n, err == nil
}

func normalizedSummaryLang(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "en":
		return "en"
	default:
		return "ru"
	}
}

func (s *Server) loadAISummaryEvidence(ctx context.Context, productID int, useProduct bool) (aiSummaryEvidence, error) {
	evidence := aiSummaryEvidence{ProductID: productID}

	if useProduct {
		err := s.db.QueryRowContext(ctx, `
			SELECT name, COALESCE(repo_url,''), COALESCE(tech_stack,''), COALESCE(platform,''),
			       COALESCE(business_criticality,''), COALESCE(lifecycle,'')
			FROM products
			WHERE id = ?
		`, productID).Scan(
			&evidence.ProductName,
			&evidence.RepoPath,
			&evidence.TechStack,
			&evidence.Platform,
			&evidence.BusinessCriticality,
			&evidence.Lifecycle,
		)
		if err != nil {
			if err == sql.ErrNoRows {
				return evidence, fmt.Errorf("product %d not found", productID)
			}
			return evidence, err
		}

		_ = s.db.QueryRowContext(ctx, `
			SELECT COALESCE(scan_path,'')
			FROM engagements
			WHERE product_id = ?
			ORDER BY started_at DESC, id DESC
			LIMIT 1
		`, productID).Scan(&evidence.ScanPath)
	} else {
		evidence.ProductName = "All scanned projects"
	}

	projectPath := firstNonEmpty(evidence.ScanPath, evidence.RepoPath)
	evidence.ProjectShape = s.projectShapeEvidence(projectPath)
	evidence.LocalAuditExcerpt = s.localAuditExcerpt(projectPath)

	countsQuery := `
		SELECT COALESCE(severity,''), COALESCE(status,''), COALESCE(is_false_positive,0)
		FROM findings`
	countsArgs := []any{}
	if useProduct {
		countsQuery += ` WHERE product_id = ?`
		countsArgs = append(countsArgs, productID)
	}
	rows, err := s.db.QueryContext(ctx, countsQuery, countsArgs...)
	if err != nil {
		return evidence, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var severity, status string
		var isFalsePositive bool
		if err := rows.Scan(&severity, &status, &isFalsePositive); err != nil {
			return evidence, err
		}
		if isActiveSummaryStatus(status, isFalsePositive) {
			incrementSummaryCount(&evidence.ActiveCounts, severity)
		} else {
			incrementSummaryCount(&evidence.SuppressedCounts, severity)
		}
	}
	if err := rows.Err(); err != nil {
		return evidence, err
	}

	findingsQuery := `
		SELECT COALESCE(rule_id,''), title, COALESCE(severity,''), COALESCE(file_path,''), COALESCE(line_number,0),
		       COALESCE(description,''), COALESCE(fix_suggestion,''), COALESCE(status,''), COALESCE(stack,''),
		       COALESCE(ai_triage_status,''), COALESCE(ai_triage_summary,''), COALESCE(is_false_positive,0)
		FROM findings`
	findingsArgs := []any{}
	if useProduct {
		findingsQuery += ` WHERE product_id = ?`
		findingsArgs = append(findingsArgs, productID)
	}
	findingsQuery += `
		ORDER BY
			CASE
				WHEN status NOT IN ('resolved', 'closed', 'risk_accepted', 'false_positive') AND COALESCE(is_false_positive,0) = 0 THEN 0
				ELSE 1
			END,
			CASE UPPER(severity)
				WHEN 'CRITICAL' THEN 0
				WHEN 'HIGH' THEN 1
				WHEN 'MEDIUM' THEN 2
				WHEN 'LOW' THEN 3
				ELSE 4
			END,
			id
		LIMIT 40`

	findingRows, err := s.db.QueryContext(ctx, findingsQuery, findingsArgs...)
	if err != nil {
		return evidence, err
	}
	defer func() { _ = findingRows.Close() }()

	for findingRows.Next() {
		var f aiSummaryFinding
		if err := findingRows.Scan(
			&f.RuleID,
			&f.Title,
			&f.Severity,
			&f.File,
			&f.Line,
			&f.Description,
			&f.FixSuggestion,
			&f.Status,
			&f.Stack,
			&f.AITriageStatus,
			&f.AITriageSummary,
			&f.IsFalsePositive,
		); err != nil {
			return evidence, err
		}
		evidence.Findings = append(evidence.Findings, f)
	}
	if err := findingRows.Err(); err != nil {
		return evidence, err
	}

	return evidence, nil
}

func isActiveSummaryStatus(status string, isFalsePositive bool) bool {
	if isFalsePositive {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "resolved", "closed", "risk_accepted", "accepted_risk", "false_positive":
		return false
	default:
		return true
	}
}

func incrementSummaryCount(counts *aiSummaryCounts, severity string) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		counts.Critical++
	case "HIGH":
		counts.High++
	case "MEDIUM":
		counts.Medium++
	case "LOW":
		counts.Low++
	default:
		counts.Other++
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Server) projectShapeEvidence(projectPath string) []string {
	if strings.TrimSpace(projectPath) == "" {
		return []string{"No project filesystem path is recorded in products or engagements."}
	}

	fullPath := s.toContainerPath(projectPath)
	info, err := os.Stat(fullPath)
	if err != nil || !info.IsDir() {
		return []string{fmt.Sprintf("Project path is not readable from the server runtime: %s", projectPath)}
	}

	fileMarkers := []string{
		"package.json",
		"vite.config.ts",
		"vite.config.js",
		"src/main.tsx",
		"src/main.jsx",
		"src/App.tsx",
		"src/App.jsx",
		"server.ts",
		"server.js",
		"src/server.ts",
		"src/server.js",
		"pages/api",
		"app/api",
		"go.mod",
		"requirements.txt",
	}
	var present []string
	for _, marker := range fileMarkers {
		if _, err := os.Stat(filepath.Join(fullPath, marker)); err == nil {
			present = append(present, marker)
		}
	}

	lines := []string{}
	if len(present) > 0 {
		lines = append(lines, "Detected project markers: "+strings.Join(present, ", "))
	} else {
		lines = append(lines, "No common application markers detected at project root.")
	}

	packagePath := filepath.Join(fullPath, "package.json")
	if data, err := os.ReadFile(packagePath); err == nil {
		var pkg struct {
			Name            string            `json:"name"`
			Scripts         map[string]string `json:"scripts"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal(data, &pkg); err == nil {
			if pkg.Name != "" {
				lines = append(lines, "package.json name: "+pkg.Name)
			}
			if len(pkg.Scripts) > 0 {
				lines = append(lines, "package.json scripts: "+summaryMapKeys(pkg.Scripts, 8))
			}

			allDeps := make(map[string]string)
			for k, v := range pkg.Dependencies {
				allDeps[k] = v
			}
			for k, v := range pkg.DevDependencies {
				allDeps[k] = v
			}
			frontendMarkers := intersectDependencyNames(allDeps, []string{"react", "react-dom", "vite", "@vitejs/plugin-react", "tailwindcss"})
			backendMarkers := intersectDependencyNames(allDeps, []string{"express", "fastify", "koa", "hono", "next", "@remix-run/node", "@nestjs/core"})
			if len(frontendMarkers) > 0 {
				lines = append(lines, "Frontend dependency markers: "+strings.Join(frontendMarkers, ", "))
			}
			if len(backendMarkers) > 0 {
				lines = append(lines, "Backend dependency markers: "+strings.Join(backendMarkers, ", "))
			} else {
				lines = append(lines, "Backend dependency markers: none among express, fastify, koa, hono, next, remix, nest.")
			}
		}
	}

	serverRouteMarkers := []string{"server.ts", "server.js", "src/server.ts", "src/server.js", "pages/api", "app/api"}
	var routeMarkers []string
	for _, marker := range serverRouteMarkers {
		if _, err := os.Stat(filepath.Join(fullPath, marker)); err == nil {
			routeMarkers = append(routeMarkers, marker)
		}
	}
	if len(routeMarkers) == 0 {
		lines = append(lines, "Server/API route file markers: none among server.ts, server.js, src/server.ts, src/server.js, pages/api, app/api.")
	} else {
		lines = append(lines, "Server/API route file markers: "+strings.Join(routeMarkers, ", "))
	}

	return lines
}

func (s *Server) localAuditExcerpt(projectPath string) string {
	if strings.TrimSpace(projectPath) == "" {
		return ""
	}
	fullPath := s.toContainerPath(projectPath)
	data, err := os.ReadFile(filepath.Join(fullPath, "SECURITY_TRIAGE_REPORT.md"))
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(data))
	if len(text) > 3000 {
		text = text[:3000] + "\n... (truncated)"
	}
	return text
}

func summaryMapKeys(values map[string]string, limit int) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
		keys = append(keys, "...")
	}
	return strings.Join(keys, ", ")
}

func intersectDependencyNames(deps map[string]string, candidates []string) []string {
	var result []string
	for _, candidate := range candidates {
		if _, ok := deps[candidate]; ok {
			result = append(result, candidate)
		}
	}
	return result
}

func buildAISummarySystemPrompt(lang string) string {
	language := "Russian"
	if lang == "en" {
		language = "English"
	}
	return fmt.Sprintf(`You are AITriage SecureCoder writing a short security posture summary for a scanned project.

Use SecureCoder methodology: actual repository evidence first, threat model second, scanner finding interpretation third.

Hard rules:
- Respond in %s.
- Do not use emoji.
- Do not invent project type, backend services, API endpoints, forms, authentication, rate limits, database access, secrets, or deployment exposure.
- Do not infer backend/API/auth/rate-limit risk unless the evidence explicitly shows request handlers, API routes, forms, auth/session code, database access, or network services.
- Scanner titles are hypotheses, not proof. If evidence only contains a scanner title, say it needs confirmation.
- Treat statuses false_positive, risk_accepted, resolved, and closed as non-active. Mention them only as suppressed/context evidence.
- Cite concrete rule IDs and file paths when making a claim.
- If a finding is project-level with no file, explain the missing affected file as a verification gap instead of pretending the whole project is exploitable.

Output exactly four short paragraphs with bold labels, no markdown headings:
1. Project overview grounded in evidence.
2. Security status.
3. Main priority.
4. Quick win.`, language)
}

func buildAISummaryUserPrompt(e aiSummaryEvidence, lang string) string {
	var sb strings.Builder
	sb.WriteString("## Summary Evidence\n\n")
	sb.WriteString(fmt.Sprintf("Requested language: %s\n", lang))
	sb.WriteString(fmt.Sprintf("Product: %s\n", firstNonEmpty(e.ProductName, "unknown")))
	if e.RepoPath != "" {
		sb.WriteString(fmt.Sprintf("Repo path: %s\n", e.RepoPath))
	}
	if e.ScanPath != "" {
		sb.WriteString(fmt.Sprintf("Latest scan path: %s\n", e.ScanPath))
	}
	if e.TechStack != "" {
		sb.WriteString(fmt.Sprintf("Recorded tech stack: %s\n", e.TechStack))
	}
	if e.Platform != "" {
		sb.WriteString(fmt.Sprintf("Platform: %s\n", e.Platform))
	}
	if e.BusinessCriticality != "" {
		sb.WriteString(fmt.Sprintf("Business criticality: %s\n", e.BusinessCriticality))
	}
	if e.Lifecycle != "" {
		sb.WriteString(fmt.Sprintf("Lifecycle: %s\n", e.Lifecycle))
	}

	sb.WriteString("\n## Project Filesystem Evidence\n")
	for _, line := range e.ProjectShape {
		sb.WriteString("- " + line + "\n")
	}

	sb.WriteString("\n## Finding Counts\n")
	sb.WriteString(fmt.Sprintf("- Active findings: %d (critical=%d, high=%d, medium=%d, low=%d, other=%d)\n",
		e.ActiveCounts.total(), e.ActiveCounts.Critical, e.ActiveCounts.High, e.ActiveCounts.Medium, e.ActiveCounts.Low, e.ActiveCounts.Other))
	sb.WriteString(fmt.Sprintf("- Non-active/suppressed findings: %d (critical=%d, high=%d, medium=%d, low=%d, other=%d)\n",
		e.SuppressedCounts.total(), e.SuppressedCounts.Critical, e.SuppressedCounts.High, e.SuppressedCounts.Medium, e.SuppressedCounts.Low, e.SuppressedCounts.Other))

	sb.WriteString("\n## Findings Evidence\n")
	if len(e.Findings) == 0 {
		sb.WriteString("- No findings recorded for this scope.\n")
	} else {
		for _, f := range e.Findings {
			active := "non-active"
			if isActiveSummaryStatus(f.Status, f.IsFalsePositive) {
				active = "active"
			}
			loc := formatPromptLocation(firstNonEmpty(f.File, "project-level/no-file"), f.Line)
			sb.WriteString(fmt.Sprintf("- [%s][%s][%s] %s at `%s`; status=%s; stack=%s",
				active, strings.ToUpper(f.Severity), firstNonEmpty(f.RuleID, "no-rule-id"), f.Title, loc, firstNonEmpty(f.Status, "open"), firstNonEmpty(f.Stack, "unknown")))
			if f.AITriageStatus != "" {
				sb.WriteString("; ai_triage=" + f.AITriageStatus)
			}
			sb.WriteString("\n")
			if strings.TrimSpace(f.Description) != "" {
				sb.WriteString("  Description: " + truncateForPrompt(f.Description, 260) + "\n")
			}
			if strings.TrimSpace(f.FixSuggestion) != "" {
				sb.WriteString("  Fix suggestion: " + truncateForPrompt(f.FixSuggestion, 220) + "\n")
			}
			if strings.TrimSpace(f.AITriageSummary) != "" {
				sb.WriteString("  AI triage summary: " + truncateForPrompt(f.AITriageSummary, 220) + "\n")
			}
		}
	}

	if e.LocalAuditExcerpt != "" {
		sb.WriteString("\n## Existing Local Security Triage Report Excerpt\n")
		sb.WriteString(e.LocalAuditExcerpt)
		sb.WriteString("\n")
	}

	sb.WriteString("\n## Required Behavior\n")
	sb.WriteString("- Prefer the existing local security triage report when it contradicts raw scanner titles.\n")
	sb.WriteString("- If the project evidence looks frontend/static, do not state that API/auth/rate limiting is exploitable unless actual API/request handling evidence is listed above.\n")
	sb.WriteString("- Main priority must be a confirmed active issue or an explicit verification step, not a guessed backend remediation.\n")
	sb.WriteString("- Quick win must be tied to evidence in files or recorded findings.\n")

	return sb.String()
}

func truncateForPrompt(value string, limit int) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\n", " ")
	if len(value) <= limit {
		return value
	}
	if limit < 4 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}

func buildAISummaryFallback(e aiSummaryEvidence, lang string) string {
	product := firstNonEmpty(e.ProductName, "project")
	active := e.ActiveCounts.total()
	suppressed := e.SuppressedCounts.total()

	var top *aiSummaryFinding
	for i := range e.Findings {
		if isActiveSummaryStatus(e.Findings[i].Status, e.Findings[i].IsFalsePositive) {
			top = &e.Findings[i]
			break
		}
	}

	if lang == "en" {
		if active == 0 {
			return fmt.Sprintf("**Project overview:** `%s` has no active findings in the current AITriage database scope.\n\n**Security status:** No active vulnerability is confirmed from recorded evidence. %d non-active or suppressed findings remain as audit context.\n\n**Main priority:** Verify the deployed host applies the recorded hardening controls before calling production fully clean.\n\n**Quick win:** Keep suppressed scanner findings documented with rationale so auth/rate-limit style checks do not reappear as unverified critical blockers.", product, suppressed)
		}
		if top != nil {
			return fmt.Sprintf("**Project overview:** `%s` has %d active findings in the current AITriage database scope.\n\n**Security status:** Active findings require review: critical=%d, high=%d, medium=%d, low=%d.\n\n**Main priority:** Confirm and address `%s` (`%s`) at `%s`; treat scanner-only or project-level findings as verification work until an affected entry point is proven.\n\n**Quick win:** Start with the cited file/rule evidence and suppress or reclassify findings that do not apply to the actual project surface.", product, active, e.ActiveCounts.Critical, e.ActiveCounts.High, e.ActiveCounts.Medium, e.ActiveCounts.Low, top.Title, firstNonEmpty(top.RuleID, "no-rule-id"), formatPromptLocation(firstNonEmpty(top.File, "project-level/no-file"), top.Line))
		}
		return fmt.Sprintf("**Project overview:** `%s` has %d active findings in the current AITriage database scope.\n\n**Security status:** Active findings require review, but no detailed finding evidence was available to this summary endpoint.\n\n**Main priority:** Re-run or refresh the scan evidence before remediation.\n\n**Quick win:** Ensure every active finding has rule ID, file path, status, and rationale.", product, active)
	}

	if active == 0 {
		return fmt.Sprintf("**Project overview:** `%s` has no active findings in the current AITriage database scope.\n\n**Security status:** Based on recorded evidence, no active vulnerability is confirmed. %d inactive or suppressed findings remain as audit context.\n\n**Top priority:** Verify the actual production host and hardening controls before making a final assessment.\n\n**Quick win:** Store rationale for suppressed scanner findings so auth/rate-limit checks don't resurface as unconfirmed critical blockers.", product, suppressed)
	}
	if top != nil {
		return fmt.Sprintf("**Project overview:** `%s` has %d active findings in the current AITriage database scope.\n\n**Security status:** Active findings require verification: critical=%d, high=%d, medium=%d, low=%d.\n\n**Top priority:** Confirm and triage `%s` (`%s`) in `%s`; treat scanner-only or project-level findings as verification tasks until a specific affected entry point is proven.\n\n**Quick win:** Start with the indicated file/rule evidence and suppress or reclassify findings that don't apply to the project's actual attack surface.", product, active, e.ActiveCounts.Critical, e.ActiveCounts.High, e.ActiveCounts.Medium, e.ActiveCounts.Low, top.Title, firstNonEmpty(top.RuleID, "no-rule-id"), formatPromptLocation(firstNonEmpty(top.File, "project-level/no-file"), top.Line))
	}
	return fmt.Sprintf("**Project overview:** `%s` has %d active findings in the current AITriage database scope.\n\n**Security status:** Findings require verification, but detailed evidence is unavailable from the summary endpoint.\n\n**Top priority:** Update scan evidence before remediation.\n\n**Quick win:** Ensure every active finding has a rule ID, file path, status, and rationale.", product, active)
}

func (s *Server) handleChatSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "GET":
		// List all sessions (user_id=1 for now since auth may be disabled)
		sessions, err := s.chatRepo.ListSessions(r.Context(), 1)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if sessions == nil {
			sessions = []repositories.ChatSession{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "sessions": sessions})
	case "POST":
		var req struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req.Title = "New Chat"
		}
		if req.Title == "" {
			req.Title = "New Chat"
		}
		id, err := s.chatRepo.CreateSession(r.Context(), 1, req.Title)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleChatSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Extract session ID from URL: /api/chat/sessions/123
	parts := strings.Split(strings.TrimRight(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		jsonError(w, "missing session id", http.StatusBadRequest)
		return
	}
	idStr := parts[len(parts)-1]
	var sessionID int
	if _, err := fmt.Sscanf(idStr, "%d", &sessionID); err != nil {
		jsonError(w, "invalid session id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "DELETE":
		if err := s.chatRepo.DeleteSession(r.Context(), sessionID); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	case "PUT":
		var req struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Title == "" {
			jsonError(w, "title is required", http.StatusBadRequest)
			return
		}
		if err := s.chatRepo.UpdateSessionTitle(r.Context(), sessionID, req.Title); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleChatMessages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "GET":
		sessionIDStr := r.URL.Query().Get("session_id")
		var sessionID int
		if _, err := fmt.Sscanf(sessionIDStr, "%d", &sessionID); err != nil {
			jsonError(w, "session_id is required", http.StatusBadRequest)
			return
		}
		msgs, err := s.chatRepo.GetMessages(r.Context(), sessionID)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if msgs == nil {
			msgs = []repositories.ChatMessage{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "messages": msgs})
	case "POST":
		var req struct {
			SessionID int    `json:"session_id"`
			Role      string `json:"role"`
			Content   string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request", http.StatusBadRequest)
			return
		}
		id, err := s.chatRepo.AddMessage(r.Context(), req.SessionID, req.Role, req.Content)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRunway(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case "GET":
		pidStr := r.URL.Query().Get("product_id")
		if pidStr == "" {
			// List all active sessions
			// For now just return empty
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "session": nil})
			return
		}
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil {
			jsonError(w, "invalid product_id", http.StatusBadRequest)
			return
		}
		session, err := s.runwayRepo.GetActiveByProductID(ctx, pid)
		if err != nil {
			// No active session
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "session": nil})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "session": session})

	case "POST":
		var req struct {
			ProductID int64 `json:"product_id"`
			AutoMode  bool  `json:"auto_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req.ProductID == 0 {
			jsonError(w, "product_id is required", http.StatusBadRequest)
			return
		}
		session := &models.RunwaySession{
			ProductID: req.ProductID,
			Status:    "in_progress",
			AutoMode:  req.AutoMode,
		}
		if err := s.runwayRepo.Create(ctx, session); err != nil {
			jsonError(w, fmt.Sprintf("failed to create session: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "session": session})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRunwaySession(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/runway/")
	if idStr == "" {
		jsonError(w, "missing session id", http.StatusBadRequest)
		return
	}

	// Handle /api/runway/history?product_id=X
	if idStr == "history" {
		pidStr := r.URL.Query().Get("product_id")
		if pidStr == "" {
			jsonError(w, "product_id is required", http.StatusBadRequest)
			return
		}
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil {
			jsonError(w, "invalid product_id", http.StatusBadRequest)
			return
		}
		sessions, err := s.runwayRepo.ListByProductID(r.Context(), pid)
		if err != nil {
			jsonError(w, fmt.Sprintf("failed to list sessions: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "sessions": sessions})
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, "invalid session id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	switch r.Method {
	case "GET":
		session, err := s.runwayRepo.GetByID(ctx, id)
		if err != nil {
			jsonError(w, fmt.Sprintf("session not found: %v", err), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "session": session})

	case "PUT":
		session, err := s.runwayRepo.GetByID(ctx, id)
		if err != nil {
			jsonError(w, fmt.Sprintf("session not found: %v", err), http.StatusNotFound)
			return
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if val, ok := body["product_id"]; ok {
			if fval, ok := val.(float64); ok {
				session.ProductID = int64(fval)
			}
		}
		if val, ok := body["status"]; ok {
			if sval, ok := val.(string); ok {
				session.Status = sval
			}
		}
		if val, ok := body["current_step"]; ok {
			if fval, ok := val.(float64); ok {
				session.CurrentStep = int(fval)
			}
		}
		if val, ok := body["progress_message"]; ok {
			if sval, ok := val.(string); ok {
				session.ProgressMessage = &sval
			} else if val == nil {
				session.ProgressMessage = nil
			}
		}
		if val, ok := body["auto_mode"]; ok {
			if bval, ok := val.(bool); ok {
				session.AutoMode = bval
			}
		}
		if val, ok := body["threat_model"]; ok {
			if sval, ok := val.(string); ok {
				session.ThreatModel = &sval
			} else if val == nil {
				session.ThreatModel = nil
			}
		}
		if val, ok := body["security_plan"]; ok {
			if sval, ok := val.(string); ok {
				session.SecurityPlan = &sval
			} else if val == nil {
				session.SecurityPlan = nil
			}
		}
		if val, ok := body["remediation"]; ok {
			if sval, ok := val.(string); ok {
				session.Remediation = &sval
			} else if val == nil {
				session.Remediation = nil
			}
		}
		if val, ok := body["poc"]; ok {
			if sval, ok := val.(string); ok {
				session.PoC = &sval
			} else if val == nil {
				session.PoC = nil
			}
		}
		if val, ok := body["audit_report"]; ok {
			if sval, ok := val.(string); ok {
				session.AuditReport = &sval
			} else if val == nil {
				session.AuditReport = nil
			}
		}
		if val, ok := body["scan_count_before"]; ok {
			if fval, ok := val.(float64); ok {
				session.ScanCountBefore = int(fval)
			}
		}
		if val, ok := body["scan_count_after"]; ok {
			if fval, ok := val.(float64); ok {
				session.ScanCountAfter = int(fval)
			}
		}
		if val, ok := body["error_message"]; ok {
			if sval, ok := val.(string); ok {
				session.ErrorMessage = &sval
			} else if val == nil {
				session.ErrorMessage = nil
			}
		}

		if err := s.runwayRepo.Update(ctx, session); err != nil {
			jsonError(w, fmt.Sprintf("failed to update session: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "session": session})

	case "DELETE":
		if err := s.runwayRepo.Delete(ctx, id); err != nil {
			jsonError(w, fmt.Sprintf("failed to delete session: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRunwayAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sessions, err := s.runwayRepo.ListAll(r.Context())
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to list sessions: %v", err), http.StatusInternalServerError)
		return
	}

	// Enrich with product names
	type enrichedSession struct {
		models.RunwaySession
		ProductName string `json:"product_name"`
	}
	var result []enrichedSession
	for _, sess := range sessions {
		name := "Unknown"
		prod, err := s.productRepo.GetByID(r.Context(), sess.ProductID)
		if err == nil && prod != nil {
			name = prod.Name
		}
		result = append(result, enrichedSession{RunwaySession: sess, ProductName: name})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "sessions": result})
}

func (s *Server) handleRunwayExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/runway/export/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, "invalid session id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	session, err := s.runwayRepo.GetByID(ctx, id)
	if err != nil {
		jsonError(w, fmt.Sprintf("session not found: %v", err), http.StatusNotFound)
		return
	}

	product, err := s.productRepo.GetByID(ctx, session.ProductID)
	if err != nil || product == nil {
		jsonError(w, "product not found", http.StatusNotFound)
		return
	}

	// Build markdown content
	var md strings.Builder
	// Machine marker (invisible in rendered Markdown) so a later scan skips this
	// report instead of flagging its embedded examples as new vulnerabilities.
	md.WriteString(core.AITriageArtifactMarker + "\n")
	md.WriteString("# 🛡️ AITriage Security Audit Report\n\n")
	md.WriteString(fmt.Sprintf("**Project**: %s\n", product.Name))
	md.WriteString(fmt.Sprintf("**Date**: %s\n", session.CreatedAt.Format("2006-01-02 15:04")))
	md.WriteString(fmt.Sprintf("**Session ID**: %d\n", session.ID))
	md.WriteString(fmt.Sprintf("**Status**: %s\n", session.Status))
	md.WriteString(fmt.Sprintf("**Findings**: %d before → %d after\n\n", session.ScanCountBefore, session.ScanCountAfter))
	md.WriteString("---\n\n")

	if session.ThreatModel != nil && *session.ThreatModel != "" {
		md.WriteString("## 1. STRIDE Threat Model\n\n")
		md.WriteString(*session.ThreatModel)
		md.WriteString("\n\n---\n\n")
	}
	if session.SecurityPlan != nil && *session.SecurityPlan != "" {
		md.WriteString("## 2. Security Implementation Plan\n\n")
		md.WriteString(*session.SecurityPlan)
		md.WriteString("\n\n---\n\n")
	}
	if session.Remediation != nil && *session.Remediation != "" {
		md.WriteString("## 3. Remediation Patches\n\n")
		md.WriteString(*session.Remediation)
		md.WriteString("\n\n---\n\n")
	}
	if session.PoC != nil && *session.PoC != "" {
		md.WriteString("## 4. Proof of Concept Verification\n\n")
		md.WriteString(*session.PoC)
		md.WriteString("\n\n---\n\n")
	}
	if session.AuditReport != nil && *session.AuditReport != "" {
		md.WriteString("## 5. Audit Report\n\n")
		md.WriteString(*session.AuditReport)
		md.WriteString("\n\n---\n\n")
	}
	md.WriteString("\n*Generated by AITriage SecureCoder Agent*\n")

	mdContent := md.String()

	// Resolve project path and save the export in the one writable artifact
	// tree. The source mount stays read-only in the production container.
	var projectPath string
	if product.RepoURL != nil && *product.RepoURL != "" {
		resolved, resolveErr := s.resolveProjectPath(*product.RepoURL)
		if resolveErr != nil {
			slog.Warn("Rejected runway report project path", "path", *product.RepoURL, "error", resolveErr)
		} else {
			projectPath = resolved
		}
	}

	var savedPath string
	if projectPath != "" {
		reportsRoot := runwayReportsRoot(projectPath)
		reportDir := filepath.Join(reportsRoot, "runway")
		if err := os.MkdirAll(reportDir, 0o700); err != nil {
			slog.Error("Failed to create runway report directory", "path", reportDir, "error", err)
		} else {
			filename := fmt.Sprintf("runway-report-%d-%s.md", session.ID, session.CreatedAt.Format("2006-01-02"))
			fullPath := filepath.Join(reportDir, filename)
			if err := os.WriteFile(fullPath, []byte(mdContent), 0o600); err != nil {
				slog.Error("Failed to write runway report", "path", fullPath, "error", err)
			} else {
				savedPath = filepath.Join("aitriage-reports", "runway", filename)
				slog.Info("Runway report saved", "path", fullPath)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"content":  mdContent,
		"saved_to": savedPath,
	})
}

func runwayReportsRoot(projectPath string) string {
	if configured := strings.TrimSpace(os.Getenv("AITRIAGE_REPORTS_DIR")); configured != "" {
		return configured
	}
	return filepath.Join(projectPath, "aitriage-reports")
}

func (s *Server) handleRunwayStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/runway/start/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, "invalid session id", http.StatusBadRequest)
		return
	}

	// The Runway pipeline is LLM-driven end to end. Without a configured client
	// every stage would dereference a nil interface inside a background
	// goroutine, taking the whole server down. Refuse early instead.
	if s.llmClient == nil {
		jsonError(w, llmUnavailableMessage, http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	session, err := s.runwayRepo.GetByID(ctx, id)
	if err != nil {
		jsonError(w, fmt.Sprintf("session not found: %v", err), http.StatusNotFound)
		return
	}
	if strings.EqualFold(session.Status, "running") && session.ErrorMessage == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": "Runway scan already running"})
		return
	}

	product, err := s.productRepo.GetByID(ctx, session.ProductID)
	if err != nil || product == nil {
		jsonError(w, "product not found", http.StatusNotFound)
		return
	}

	findings, err := s.findingRepo.ListByProductID(ctx, session.ProductID)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to get findings: %v", err), http.StatusInternalServerError)
		return
	}

	// The audit narrative follows the language the operator is reading the UI
	// in. Identifiers inside it stay verbatim — see prompts.LocalisationContract.
	language := prompts.NormalizeLanguage(r.URL.Query().Get("lang"))

	go s.runRunwaySession(session, product, findings, language)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": "Runway scan started"})
}

// requestedProbeHost returns the host to port-scan for a scan request. Network
// probing reports on the environment AITriage is running in rather than on the
// audited source, so it happens only when explicitly requested.
func requestedProbeHost(requested bool) string {
	if !requested {
		return ""
	}
	return "localhost"
}
