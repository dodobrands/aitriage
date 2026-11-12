package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dodobrands/aitriage/internal/agent/graph"
)

func writeTriageArtifact(path string, state *graph.AgentState) error {
	artifact, err := graph.BuildTriageFindingsArtifact(state)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal triage artifact: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, artifactFileMode()); err != nil {
		return fmt.Errorf("write triage artifact to %s: %w", path, err)
	}
	return nil
}

// artifactFileMode is the permission for report artifacts. On a developer's
// machine they stay private to the user (0600). Inside the scanner container
// the process runs as root and writes into a bind-mounted CI workspace; later
// CI steps (artifact upload, PR comments) run as a different user and must be
// able to read the files, so they are world-readable there (0644). They hold
// the same repository content those steps can already read.
func artifactFileMode() os.FileMode {
	if os.Getenv("AITRIAGE_RUNTIME") == "container" {
		return 0o644
	}
	return 0o600
}
