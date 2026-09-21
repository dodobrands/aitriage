package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/server/repositories"
	"github.com/dodobrands/aitriage/internal/server/utils"
)

type ReportHandler struct {
	findingRepo    *repositories.FindingRepository
	engagementRepo *repositories.EngagementRepository
	productRepo    *repositories.ProductRepository
	reportRepo     *repositories.ReportRepository
}

func NewReportHandler(findingRepo *repositories.FindingRepository, engagementRepo *repositories.EngagementRepository, productRepo *repositories.ProductRepository, reportRepo *repositories.ReportRepository) *ReportHandler {
	return &ReportHandler{
		findingRepo:    findingRepo,
		engagementRepo: engagementRepo,
		productRepo:    productRepo,
		reportRepo:     reportRepo,
	}
}

func (h *ReportHandler) HandleExecutiveReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	scope, findings, err := h.resolveScope(ctx, r.URL.Query().Get("product_id"))
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	summary := struct {
		TotalFindings int            `json:"total_findings"`
		BySeverity    map[string]int `json:"by_severity"`
		ByStatus      map[string]int `json:"by_status"`
		Open          int            `json:"open_findings"`
		NeedsReview   int            `json:"needs_review_findings"`
		Suppressed    int            `json:"suppressed_findings"`
		Scope         string         `json:"scope"`
		ProductID     *int64         `json:"product_id,omitempty"`
		RepoPath      string         `json:"repo_path,omitempty"`
	}{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByStatus:      make(map[string]int),
		Scope:         scope.label(),
		RepoPath:      scope.RepoPath,
	}
	if !scope.AllProducts {
		id := scope.ProductID
		summary.ProductID = &id
	}

	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByStatus[f.Status]++
		switch {
		case isSuppressed(f):
			summary.Suppressed++
		case needsReview(f):
			summary.NeedsReview++
			summary.Open++
		default:
			summary.Open++
		}
	}

	// The CSV view of the executive summary is the full finding list, not a
	// severity histogram: a histogram cannot be acted on or reviewed.
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=aitriage-%s.csv", scope.slug()))
		_, _ = w.Write(renderCSV(findings))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

func (h *ReportHandler) HandleEngagementReport(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/reports/engagement/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		utils.JSONError(w, "engagement_id is required", http.StatusBadRequest)
		return
	}

	engagementID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		utils.JSONError(w, "invalid engagement_id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	engagement, err := h.engagementRepo.GetByID(ctx, engagementID)
	if err != nil {
		utils.JSONError(w, "Engagement not found", http.StatusNotFound)
		return
	}

	findings, err := h.findingRepo.List(ctx, engagementID)
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	report := struct {
		EngagementName string `json:"engagement_name"`
		Findings       []any  `json:"findings"`
	}{
		EngagementName: engagement.Name,
	}

	for _, f := range findings {
		filePath := ""
		if f.FilePath != nil {
			filePath = *f.FilePath
		}
		lineNum := ""
		if f.LineNumber != nil {
			lineNum = strconv.Itoa(*f.LineNumber)
		}

		report.Findings = append(report.Findings, map[string]any{
			"title":    f.Title,
			"severity": f.Severity,
			"file":     filePath,
			"line":     lineNum,
			"status":   f.Status,
		})
	}

	format := r.URL.Query().Get("format")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=engagement_%d_report.csv", engagementID))
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"Title", "Severity", "File", "Line", "Status"})
		for _, f := range findings {
			filePath := ""
			if f.FilePath != nil {
				filePath = *f.FilePath
			}
			lineNum := ""
			if f.LineNumber != nil {
				lineNum = strconv.Itoa(*f.LineNumber)
			}
			_ = writer.Write([]string{f.Title, f.Severity, filePath, lineNum, f.Status})
		}
		writer.Flush()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func (h *ReportHandler) HandleListReportHistory(w http.ResponseWriter, r *http.Request) {
	reports, err := h.reportRepo.ListReports()
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"reports": reports,
	})
}

// resolveScope turns an optional product_id query/body value into the scope an
// artifact covers plus the findings inside it. An empty value means every
// product, which stays available but is no longer the silent default of a
// report a team is about to hand to a reviewer.
func (h *ReportHandler) resolveScope(ctx context.Context, rawProductID string) (artifactScope, []models.Finding, error) {
	raw := strings.TrimSpace(rawProductID)
	if raw == "" || raw == "all" {
		findings, err := h.findingRepo.ListAll(ctx)
		if err != nil {
			return artifactScope{}, nil, err
		}
		return artifactScope{AllProducts: true}, findings, nil
	}

	productID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return artifactScope{}, nil, fmt.Errorf("invalid product_id %q", rawProductID)
	}

	product, err := h.productRepo.GetByID(ctx, productID)
	if err != nil || product == nil {
		return artifactScope{}, nil, fmt.Errorf("product %d not found", productID)
	}

	findings, err := h.findingRepo.ListByProductID(ctx, productID)
	if err != nil {
		return artifactScope{}, nil, err
	}

	scope := artifactScope{ProductID: productID, ProductName: product.Name}
	if product.RepoURL != nil {
		scope.RepoPath = strings.TrimSpace(*product.RepoURL)
	}
	return scope, findings, nil
}

// HandleGenerateReport records a report request. The artifact itself is
// rendered on download so it always reflects the current triage state, and the
// row exists to give the team a dated audit trail of what was produced.
func (h *ReportHandler) HandleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Format    string `json:"format"`
		Scope     string `json:"scope"`
		ProductID *int64 `json:"product_id"`
		Options   struct {
			IncludeDeps bool `json:"include_deps"`
			Sign        bool `json:"sign"`
		} `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.JSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Format == "" {
		req.Format = "sarif"
	}
	format, ok := normalizeFormat(req.Format)
	if !ok {
		utils.JSONError(w, fmt.Sprintf("unsupported report format %q (use sarif, csv, pdf, cyclonedx or spdx)", req.Format), http.StatusBadRequest)
		return
	}

	rawProduct := ""
	if req.ProductID != nil {
		rawProduct = strconv.FormatInt(*req.ProductID, 10)
	}
	scope, findings, err := h.resolveScope(r.Context(), rawProduct)
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Render once up front so a report is never recorded as READY when it
	// cannot actually be produced (a missing repository path for an SBOM, say).
	if _, err := renderArtifact(r.Context(), format, scope, findings); err != nil {
		utils.JSONError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	reportID, err := h.reportRepo.CreateReport(scope.label(), string(format), "READY", scopeProductID(scope), "")
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	downloadURL := fmt.Sprintf("/api/reports/download/%d", reportID)
	if err := h.reportRepo.SetDownloadURL(reportID, downloadURL); err != nil {
		utils.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":           true,
		"id":           reportID,
		"format":       string(format),
		"scope":        scope.label(),
		"findings":     len(findings),
		"download_url": downloadURL,
	})
}

// HandleDownloadReport renders and serves a recorded report.
func (h *ReportHandler) HandleDownloadReport(w http.ResponseWriter, r *http.Request) {
	idStr := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/reports/download/"), "/")
	reportID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		utils.JSONError(w, "invalid report id", http.StatusBadRequest)
		return
	}

	report, err := h.reportRepo.GetReport(reportID)
	if err != nil || report == nil {
		utils.JSONError(w, "report not found", http.StatusNotFound)
		return
	}

	format, ok := normalizeFormat(report.Format)
	if !ok {
		utils.JSONError(w, fmt.Sprintf("report %d has an unsupported format %q", reportID, report.Format), http.StatusUnprocessableEntity)
		return
	}

	rawProduct := ""
	if report.ProductID != nil {
		rawProduct = strconv.FormatInt(*report.ProductID, 10)
	}
	scope, findings, err := h.resolveScope(r.Context(), rawProduct)
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	doc, err := renderArtifact(r.Context(), format, scope, findings)
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	w.Header().Set("Content-Type", doc.ContentType)
	// The executive document is meant to be read and printed in the browser,
	// so it opens inline; machine-readable formats download.
	disposition := "attachment"
	if format == formatExecutive {
		disposition = "inline"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s;filename=%s", disposition, doc.Filename))
	_, _ = w.Write(doc.Body)
}

func scopeProductID(scope artifactScope) *int64 {
	if scope.AllProducts {
		return nil
	}
	id := scope.ProductID
	return &id
}
