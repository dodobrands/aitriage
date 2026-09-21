package graph

import (
	"context"
	"strings"
	"sync"

	"github.com/dodobrands/aitriage/internal/agent/llm"
)

const (
	usageStageThreatModel    = "threat_model"
	usageStageClassification = "classification"
	usageStagePoC            = "poc"
	usageStageReport         = "report"
	usageStageFixSpec        = "fixspec"
)

type stageUsageClient struct {
	inner        llm.Client
	state        *AgentState
	defaultStage string
	detectStage  bool
	mu           sync.Mutex
}

func trackLLMStage(state *AgentState, stage string, inner llm.Client) llm.Client {
	return &stageUsageClient{inner: inner, state: state, defaultStage: stage}
}

func trackTriageLLMStages(state *AgentState, inner llm.Client) llm.Client {
	return &stageUsageClient{inner: inner, state: state, defaultStage: usageStageClassification, detectStage: true}
}

func (c *stageUsageClient) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	// Defence in depth: the pipeline refuses a nil client up front, but this
	// wrapper is also reachable from other callers. A missing provider must
	// surface as an error, never as a segfault inside a background goroutine.
	if c == nil || c.inner == nil {
		return "", llm.Usage{}, ErrNoLLMClient
	}

	response, usage, err := c.inner.Chat(ctx, messages)
	c.record(c.stageFor(messages), usage)
	return response, usage, err
}

func (c *stageUsageClient) stageFor(messages []llm.Message) string {
	if !c.detectStage || len(messages) == 0 {
		return c.defaultStage
	}
	systemPrompt := messages[0].Content
	if strings.Contains(systemPrompt, "Threat Model & Finding Classification") {
		return usageStageThreatModel
	}
	if strings.Contains(systemPrompt, "Finding Classification") {
		return usageStageClassification
	}
	return c.defaultStage
}

func (c *stageUsageClient) record(stage string, usage llm.Usage) {
	if c.state == nil || stage == "" || isZeroUsage(usage) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state.StageUsage == nil {
		c.state.StageUsage = make(map[string]llm.Usage)
	}
	current := c.state.StageUsage[stage]
	addUsage(&current, usage)
	c.state.StageUsage[stage] = current
}

func isZeroUsage(usage llm.Usage) bool {
	return usage.PromptTokens == 0 &&
		usage.CompletionTokens == 0 &&
		usage.TotalTokens == 0 &&
		usage.CachedPromptTokens == 0 &&
		usage.CacheCreationInputTokens == 0 &&
		usage.CacheReadInputTokens == 0 &&
		!usage.CacheTelemetryReported
}
