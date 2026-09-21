// Package suppression records findings a team has deliberately dismissed, with
// the reason, in a file that travels with the project.
//
// Suppression existed in three incompatible forms: the Web UI wrote to its own
// SQLite table, the MCP tool delegated to Antigravity's external SecureCoder
// service, and the CLI had nothing at all. A decision made in one surface was
// invisible to the others, which makes the decision worthless — the point of
// marking a false positive is that it stays marked.
//
// The store is a project file for the same reason a baseline is: it is the only
// place all three surfaces can reach. The CLI has no database, a server's
// database is local to that server, and an IDE service is not always running.
// Being a file also means the decision is reviewable and travels with the
// repository, which is what an auditor asks for.
package suppression

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/engine/baseline"
)

const (
	// File is the project-local store, next to .aitriage-baseline.json.
	File = ".aitriage-suppressions.json"
	// SchemaVersion is bumped when the stored shape changes incompatibly.
	SchemaVersion = "1"
)

// Reasons a finding may be dismissed. A suppression always carries one, so a
// reviewer can tell "we looked and it is wrong" from "we accept this risk".
const (
	ReasonFalsePositive = "false_positive"
	ReasonAcceptedRisk  = "accepted_risk"
	ReasonWontFix       = "wont_fix"
)

// NormalizeReason maps the wordings the surfaces use onto the stored set.
func NormalizeReason(reason string) (string, error) {
	// Surfaces spell this differently: a CLI flag uses hyphens, the Web UI sends
	// "False Positive", an agent may send snake_case. They all mean one thing.
	key := strings.ToLower(strings.TrimSpace(reason))
	key = strings.NewReplacer(" ", "_", "-", "_").Replace(key)

	switch key {
	case "", ReasonFalsePositive, "fp", "falsepositive":
		return ReasonFalsePositive, nil
	case ReasonAcceptedRisk, "accepted", "risk_accepted", "acceptedrisk":
		return ReasonAcceptedRisk, nil
	case ReasonWontFix, "wontfix", "won't_fix":
		return ReasonWontFix, nil
	default:
		return "", fmt.Errorf("unknown reason %q (use false_positive, accepted_risk or wont_fix)", reason)
	}
}

// Entry is one dismissed finding.
type Entry struct {
	// Fingerprint identifies the finding the same way a baseline does, so a
	// suppression survives the finding moving within its file.
	Fingerprint string `json:"fingerprint"`
	Source      string `json:"source"`
	RuleID      string `json:"rule_id"`
	File        string `json:"file,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Reason      string `json:"reason"`
	// Note is the human justification. An auditor reads this, so it is required
	// for an accepted risk and optional for a plain false positive.
	Note      string    `json:"note,omitempty"`
	Author    string    `json:"author,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Store is the whole file.
type Store struct {
	Version   string           `json:"version"`
	UpdatedAt time.Time        `json:"updated_at"`
	Entries   map[string]Entry `json:"entries"`
}

// Load reads the store, returning an empty one when the project has no file.
func Load(projectPath string) (*Store, error) {
	data, err := os.ReadFile(filepath.Join(projectPath, File))
	if os.IsNotExist(err) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read suppressions: %w", err)
	}

	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse suppressions: %w", err)
	}
	if s.Entries == nil {
		s.Entries = map[string]Entry{}
	}
	return &s, nil
}

// New returns an empty store.
func New() *Store {
	return &Store{Version: SchemaVersion, Entries: map[string]Entry{}}
}

// Save writes the store. The file is owner-only: it records security decisions.
func Save(projectPath string, s *Store) error {
	s.Version = SchemaVersion
	s.UpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode suppressions: %w", err)
	}
	if err := os.WriteFile(filepath.Join(projectPath, File), data, 0o600); err != nil {
		return fmt.Errorf("write suppressions: %w", err)
	}
	return nil
}

// Add records a dismissal and reports whether it replaced an existing one.
func (s *Store) Add(item baseline.Item, reason, note, author string) (Entry, bool, error) {
	normalized, err := NormalizeReason(reason)
	if err != nil {
		return Entry{}, false, err
	}
	// An accepted risk is a decision someone has to stand behind later; without
	// a justification the record is useless to the person reviewing it.
	if normalized == ReasonAcceptedRisk && strings.TrimSpace(note) == "" {
		return Entry{}, false, fmt.Errorf("an accepted risk needs a justification: say why the risk is acceptable")
	}

	fp := baseline.FingerprintItem(item)
	_, replaced := s.Entries[fp]
	entry := Entry{
		Fingerprint: fp,
		Source:      item.Source,
		RuleID:      item.RuleID,
		File:        item.File,
		Severity:    item.Severity,
		Reason:      normalized,
		Note:        strings.TrimSpace(note),
		Author:      strings.TrimSpace(author),
		CreatedAt:   time.Now().UTC(),
	}
	if replaced {
		// Keep the original date: a suppression's age is what makes a stale one
		// visible during review.
		entry.CreatedAt = s.Entries[fp].CreatedAt
	}
	s.Entries[fp] = entry
	return entry, replaced, nil
}

// Remove deletes a suppression by fingerprint or by rule id, returning how many
// entries went away.
func (s *Store) Remove(identifier string) int {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return 0
	}
	if _, ok := s.Entries[identifier]; ok {
		delete(s.Entries, identifier)
		return 1
	}

	removed := 0
	for fp, entry := range s.Entries {
		if strings.EqualFold(entry.RuleID, identifier) {
			delete(s.Entries, fp)
			removed++
		}
	}
	return removed
}

// Suppresses reports whether a finding has been dismissed.
func (s *Store) Suppresses(item baseline.Item) (Entry, bool) {
	if s == nil || len(s.Entries) == 0 {
		return Entry{}, false
	}
	entry, ok := s.Entries[baseline.FingerprintItem(item)]
	return entry, ok
}

// List returns the entries in a stable order: newest first, then by rule id, so
// output does not churn between runs.
func (s *Store) List() []Entry {
	if s == nil {
		return nil
	}
	out := make([]Entry, 0, len(s.Entries))
	for _, entry := range s.Entries {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// CountByReason summarises the store for a report header.
func (s *Store) CountByReason() map[string]int {
	counts := map[string]int{}
	for _, entry := range s.List() {
		counts[entry.Reason]++
	}
	return counts
}
