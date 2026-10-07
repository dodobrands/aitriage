package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// These settings only apply to the deterministic core engine. External engines
// keep their own configuration; the UI must not claim it can configure them here.
type coreScannerConfig struct {
	MinSeverity  string   `json:"min_severity"`
	ExcludePaths []string `json:"exclude_paths"`
}

func (s *Server) loadCoreScannerConfig() coreScannerConfig {
	cfg := coreScannerConfig{MinSeverity: "INFO", ExcludePaths: []string{}}
	if stored, err := s.configRepo.Get(context.Background(), "scanner.core"); err == nil {
		_ = json.Unmarshal([]byte(stored), &cfg)
	}
	return cfg
}

func (s *Server) handleCoreScannerConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.loadCoreScannerConfig())
	case http.MethodPut:
		var cfg coreScannerConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&cfg); err != nil {
			jsonError(w, "invalid configuration", http.StatusBadRequest)
			return
		}
		cfg.MinSeverity = strings.ToUpper(cfg.MinSeverity)
		switch cfg.MinSeverity {
		case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			jsonError(w, "invalid min_severity", http.StatusBadRequest)
			return
		}
		if len(cfg.ExcludePaths) > 100 {
			jsonError(w, "too many exclusion patterns", http.StatusBadRequest)
			return
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			jsonError(w, "invalid configuration", http.StatusBadRequest)
			return
		}
		if err := s.configRepo.Set(r.Context(), "scanner.core", string(data)); err != nil {
			jsonError(w, "failed to save configuration", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
