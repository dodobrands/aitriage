package graph

import (
	"context"
	"errors"
	"testing"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/scanner/external"
)

// Starting a Runway audit without a configured LLM provider used to dereference
// a nil interface deep inside the threat-model stage. Because the pipeline runs
// in a detached goroutine, that panic took the whole server process down mid
// audit rather than failing one request.

func TestRunWithoutLLMClientReturnsErrorInsteadOfPanicking(t *testing.T) {
	state := &AgentState{
		ProjectPath: t.TempDir(),
		ExternalFindings: []external.UnifiedFinding{
			{Source: "semgrep", RuleID: "sql-injection", Severity: "HIGH", File: "app.go", Line: 1, Message: "sqli"},
		},
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("graph.Run panicked on a nil client: %v", recovered)
		}
	}()

	err := Run(context.Background(), state, nil)

	if err == nil {
		t.Fatal("Run with a nil client returned no error")
	}
	if !errors.Is(err, ErrNoLLMClient) {
		t.Errorf("err = %v; want ErrNoLLMClient so callers can report it precisely", err)
	}
}

func TestStageUsageClientDoesNotPanicOnNilInner(t *testing.T) {
	// trackLLMStage wraps whatever it is given. A nil inner client must surface
	// as an error from Chat, not as a segfault inside the usage recorder.
	state := &AgentState{}
	wrapped := trackLLMStage(state, usageStageReport, nil)

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("stageUsageClient panicked wrapping a nil client: %v", recovered)
		}
	}()

	_, _, err := wrapped.Chat(context.Background(), []llm.Message{{Role: "user", Content: "hi"}})
	if err == nil {
		t.Fatal("Chat through a nil inner client returned no error")
	}
}
