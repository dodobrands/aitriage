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
	"github.com/dodobrands/aitriage/internal/engine/statefile"
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

// ReportsArea is the folder under the reports directory that holds the
// dismissals written while the project is mounted read-only.
const ReportsArea = "suppressions"

// Locate returns where the dismissals of the scanned folder projectPath are
// read and written: the project's own file natively, plus a local copy under
// the reports directory in the container runtime (see statefile). Every reader
// and writer goes through it, so a decision recorded in the container is
// applied by the next scan there.
func Locate(projectPath string) statefile.Location {
	return statefile.Locate(projectPath, ReportsArea, File)
}

// LoadAt reads the dismissals that apply at loc. Natively that is the
// project's own file. In the container runtime it is that file with the local
// copy on top: an entry in either applies, and the copy's entry wins for the
// same fingerprint. A decision committed to the project after the copy was
// written still applies, and a local entry stays in force after the project
// removes its own, until the copy is committed or deleted.
func LoadAt(loc statefile.Location) (*Store, error) {
	r, err := Open(loc)
	if err != nil {
		return nil, err
	}
	return r.Applied, nil
}

// Record is the dismissals of one scanned folder as a surface that changes
// them sees them. Applied is what scans apply (see LoadAt); Add, Remove and
// Save change only the store at Location.WriteDir, because in the container
// runtime the project's own file is read-only.
type Record struct {
	Location statefile.Location
	Applied  *Store
	local    *Store
	// project is the project's own store when writes go to a local copy.
	project *Store
}

// Open reads the dismissals of the scanned folder at loc.
func Open(loc statefile.Location) (*Record, error) {
	local, err := Load(loc.WriteDir)
	if err != nil {
		return nil, err
	}
	r := &Record{Location: loc, local: local}
	if loc.Redirected() {
		if r.project, err = Load(loc.ProjectDir); err != nil {
			return nil, err
		}
	}
	r.refresh()
	return r, nil
}

func (r *Record) refresh() {
	if r.project == nil {
		r.Applied = r.local
		return
	}
	merged := New()
	merged.UpdatedAt = r.project.UpdatedAt
	if r.local.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = r.local.UpdatedAt
	}
	for fp, entry := range r.project.Entries {
		merged.Entries[fp] = entry
	}
	for fp, entry := range r.local.Entries {
		merged.Entries[fp] = entry
	}
	r.Applied = merged
}

// Add records a dismissal in the local store and reports whether it replaced
// one that applied. Re-dismissing a finding the project already dismisses
// overrides that entry locally and keeps its original date.
func (r *Record) Add(item baseline.Item, reason, note, author string) (Entry, bool, error) {
	fp := baseline.FingerprintItem(item)
	previous, existed := r.Applied.Entries[fp]
	entry, _, err := r.local.Add(item, reason, note, author)
	if err != nil {
		return Entry{}, false, err
	}
	if existed {
		entry.CreatedAt = previous.CreatedAt
		r.local.Entries[fp] = entry
	}
	r.refresh()
	return entry, existed, nil
}

// Remove deletes dismissals by fingerprint or by rule id from the local store.
// It returns how many went away there, and how many matching entries remain
// in force because the project's own file records them: this surface cannot
// change that file in the container runtime.
func (r *Record) Remove(identifier string) (removed, committed int) {
	removed = r.local.Remove(identifier)
	if r.project != nil {
		committed = len(r.project.matching(identifier))
	}
	r.refresh()
	return removed, committed
}

// Save writes the local store, creating its folder under the reports
// directory when the project is read-only.
func (r *Record) Save() error {
	if err := r.Location.Prepare(); err != nil {
		return fmt.Errorf("write suppressions: %w", err)
	}
	return Save(r.Location.WriteDir, r.local)
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
	keys := s.matching(identifier)
	for _, fp := range keys {
		delete(s.Entries, fp)
	}
	return len(keys)
}

// matching returns the fingerprints Remove deletes for identifier: the one
// entry it names exactly, or every entry of the rule it names.
func (s *Store) matching(identifier string) []string {
	identifier = strings.TrimSpace(identifier)
	if s == nil || identifier == "" {
		return nil
	}
	if _, ok := s.Entries[identifier]; ok {
		return []string{identifier}
	}
	var keys []string
	for fp, entry := range s.Entries {
		if strings.EqualFold(entry.RuleID, identifier) {
			keys = append(keys, fp)
		}
	}
	return keys
}

// Suppresses reports whether a finding has been dismissed.
//
// A dismissal recorded with the matched text covers exactly that finding. One
// recorded without it (`aitriage ignore add RULE --file F`, or an IDE call with
// no evidence) stands for the rule instead: it covers every finding of that
// rule from that scanner in F, and anywhere in the project when it names no
// file either. Scanned findings carry their evidence, and most carry a file,
// so an exact match against such an entry would practically never succeed.
func (s *Store) Suppresses(item baseline.Item) (Entry, bool) {
	if s == nil || len(s.Entries) == 0 {
		return Entry{}, false
	}
	if entry, ok := s.Entries[baseline.FingerprintItem(item)]; ok {
		return entry, true
	}
	if entry, ok := s.ruleWide(item, item.File); ok {
		return entry, true
	}
	if item.File != "" {
		return s.ruleWide(item, "")
	}
	return Entry{}, false
}

// ruleWide finds a dismissal recorded without evidence for the item's scanner
// and rule in file. An empty file is the whole project.
func (s *Store) ruleWide(item baseline.Item, file string) (Entry, bool) {
	key := baseline.FingerprintItem(baseline.Item{Source: item.Source, RuleID: item.RuleID, File: file})
	if entry, ok := s.Entries[key]; ok && recordedWithoutEvidence(key, entry) {
		return entry, true
	}
	return Entry{}, false
}

// recordedWithoutEvidence reports whether an entry was recorded without the
// matched text: its fingerprint is the one its own fields give with none. An
// entry recorded with evidence never qualifies, so it keeps matching exactly.
func recordedWithoutEvidence(key string, entry Entry) bool {
	return key == baseline.FingerprintItem(baseline.Item{Source: entry.Source, RuleID: entry.RuleID, File: entry.File})
}

// SuppressesInProject also recognises decisions written before paths were made
// project-relative, with or without evidence. Existing dismissals must keep
// working after an upgrade or after the project is checked out in a different
// directory.
func (s *Store) SuppressesInProject(root string, item baseline.Item) (Entry, bool) {
	if entry, ok := s.Suppresses(item); ok {
		return entry, true
	}
	if s == nil || item.File == "" {
		return Entry{}, false
	}
	if root != "" {
		legacy := item
		legacy.File = filepath.Join(root, filepath.FromSlash(item.File))
		if entry, ok := s.Entries[baseline.FingerprintItem(legacy)]; ok {
			return entry, true
		}
		if entry, ok := s.ruleWide(legacy, legacy.File); ok {
			return entry, true
		}
	}
	for key, entry := range s.Entries {
		if entry.RuleID != item.RuleID || !strings.EqualFold(entry.Source, item.Source) ||
			!baseline.LegacyPathMatches(entry.File, item.File) {
			continue
		}
		legacy := item
		legacy.File = entry.File
		if baseline.FingerprintItem(legacy) == key || recordedWithoutEvidence(key, entry) {
			return entry, true
		}
	}
	return Entry{}, false
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
