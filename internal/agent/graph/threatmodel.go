package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/prompts"
)

// ── Threat model: tolerant decoding and bounded repair ───────────────────────
//
// The threat model is context for classification, not a verdict. A single
// malformed reply (a quoted boolean, a trailing comma, prose after the JSON)
// used to abort the whole run. It is now decoded field by field, a malformed
// reply is retried with a repair request, and if it still cannot be parsed
// classification runs without it: the classification prompt already handles
// "(no threat model available)".

// ThreatModelSource values.
const (
	threatModelSourceLLM          = "llm"
	threatModelSourceCacheSkipped = "cache_skipped"
	threatModelSourceSkippedEmpty = "skipped_empty"
	threatModelSourceFailedParse  = "failed_parse"
	threatModelSourceFailed       = "failed"
)

// maxRepairEcho bounds how much of an unparseable reply is sent back to the
// model in a repair request: enough to show it what went wrong, not so much
// that a runaway reply doubles the cost of every retry.
const maxRepairEcho = 8000

const threatModelRepairPrompt = `Your previous reply could not be parsed as the JSON object the system prompt asks for (%s).
Reply again with ONLY that JSON object: no prose, no markdown fences, no comments, no trailing commas, double-quoted keys and strings, and booleans written as true or false.`

// buildThreatModelWithRepair requests the threat model, retrying a reply that
// cannot be parsed up to maxRetries times with a repair request. It returns:
//
//   - the model and threatModelSourceLLM on success;
//   - nil, threatModelSourceFailedParse and a nil error when every reply was
//     malformed: the run continues without a threat model;
//   - a non-nil error for a provider failure (transport, auth, rate limit).
func buildThreatModelWithRepair(ctx context.Context, repoContextText, projectPath, language string, sample []EnrichedFinding, llmClient llm.Client, usage *llm.Usage, maxRetries int) (*ThreatModel, string, string, error) {
	messages := threatModelMessages(repoContextText, projectPath, language, sample)
	var lastParseErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		tm, response, err := threatModelLLMCall(ctx, messages, llmClient, usage)
		if err == nil {
			return tm, threatModelSourceLLM, "", nil
		}
		if !errors.Is(err, errThreatModelParse) {
			return nil, "", "", err
		}
		lastParseErr = err
		messages = withRepairRequest(messages, response, err)
	}
	issue := fmt.Sprintf("threat model reply was not valid JSON after %d attempt(s) (%s); classification ran without a threat model",
		maxRetries+1, failureReason(lastParseErr))
	return nil, threatModelSourceFailedParse, issue, nil
}

func threatModelMessages(repoContextText, projectPath, language string, sample []EnrichedFinding) []llm.Message {
	findingsJSON, _ := json.MarshalIndent(sample, "", "  ")
	userPrompt := fmt.Sprintf(prompts.ThreatModelUserPromptTemplate,
		repoContextText,
		projectPath,
		len(sample),
		string(findingsJSON),
	)
	return []llm.Message{
		{Role: "system", Content: prompts.ThreatModelSystemPrompt},
		{Role: "user", Content: userPrompt + prompts.LocalisationContract(language)},
	}
}

// withRepairRequest continues the conversation with the unparseable reply and
// a request to resend it as valid JSON. The original request stays first, so
// the system prompt (and the usage stage detection that relies on it) is
// unchanged.
func withRepairRequest(messages []llm.Message, response string, parseErr error) []llm.Message {
	echo := response
	if len(echo) > maxRepairEcho {
		echo = echo[:maxRepairEcho] + "\n[... reply truncated ...]"
	}
	if strings.TrimSpace(echo) == "" {
		echo = "(empty reply)"
	}
	next := make([]llm.Message, 0, len(messages)+2)
	next = append(next, messages[:2]...)
	next = append(next,
		llm.Message{Role: "assistant", Content: echo},
		llm.Message{Role: "user", Content: fmt.Sprintf(threatModelRepairPrompt, failureReason(parseErr))},
	)
	return next
}

// threatModelLLMCall sends one threat-model request and decodes the reply.
// Transport errors are returned wrapped plainly; an unparseable reply is
// wrapped with errThreatModelParse and returned together with the raw text.
func threatModelLLMCall(ctx context.Context, messages []llm.Message, llmClient llm.Client, usage *llm.Usage) (*ThreatModel, string, error) {
	response, u, err := llmClient.Chat(ctx, messages)
	addUsage(usage, u)
	if err != nil {
		return nil, "", fmt.Errorf("threat model LLM call failed: %w", err)
	}
	tm, err := decodeThreatModel(extractJSON(response))
	if err != nil {
		return nil, response, err
	}
	return tm, response, nil
}

// decodeThreatModel decodes a threat model one field at a time. Only a reply
// that is not a JSON object at all is an error; a field of the wrong shape is
// dropped instead of discarding the rest of the model.
func decodeThreatModel(jsonText string) (*ThreatModel, error) {
	var fields map[string]json.RawMessage
	if err := decodeFirstJSONValue(jsonText, &fields); err != nil {
		return nil, fmt.Errorf("%w: %v", errThreatModelParse, err)
	}
	if fields == nil {
		return nil, fmt.Errorf("%w: reply is null, not an object", errThreatModelParse)
	}
	tm := &ThreatModel{
		ComponentOverview: looseString(fields["component_overview"]),
		TrustBoundaries:   decodeTrustBounds(fields["trust_boundaries"]),
		PriorityAreas:     looseStrings(fields["priority_areas"]),
	}
	for _, obj := range looseObjects(fields["entry_points"]) {
		tm.EntryPoints = append(tm.EntryPoints, EntryPoint{
			Endpoint:   looseString(obj["endpoint"]),
			Type:       looseString(obj["type"]),
			Trusted:    FlexibleBool(parseLooseBool(obj["trusted"])),
			Validation: looseString(obj["validation"]),
		})
	}
	for _, obj := range looseObjects(fields["sensitive_data_paths"]) {
		tm.SensitiveDataPaths = append(tm.SensitiveDataPaths, DataPath{
			DataType:    looseString(obj["data_type"]),
			Source:      looseString(obj["source"]),
			Destination: looseString(obj["destination"]),
			Protection:  looseString(obj["protection"]),
		})
	}
	for _, obj := range looseObjects(fields["privileged_actions"]) {
		tm.PrivilegedActions = append(tm.PrivilegedActions, PrivAction{
			Action:   looseString(obj["action"]),
			Location: looseString(obj["location"]),
			Guard:    looseString(obj["guard"]),
		})
	}
	return tm, nil
}

// decodeFirstJSONValue decodes the first JSON value in text and ignores
// anything after it: models often append a sentence after the JSON they were
// asked for, which a strict decoder rejects as "invalid character after
// top-level value".
func decodeFirstJSONValue(text string, v any) error {
	return json.NewDecoder(strings.NewReader(strings.TrimSpace(text))).Decode(v)
}

func decodeTrustBounds(raw json.RawMessage) TrustBounds {
	var obj map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &obj) != nil {
		return TrustBounds{}
	}
	return TrustBounds{
		Authentication: looseString(obj["authentication"]),
		Authorization:  looseString(obj["authorization"]),
		ImplicitTrust:  looseString(obj["implicit_trust"]),
	}
}

// looseString reads a JSON string, tolerating scalars and arrays of strings
// where a string was expected. Anything else decodes as "".
func looseString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	switch value := v.(type) {
	case bool, float64:
		return fmt.Sprint(value)
	case []any:
		var parts []string
		for _, item := range value {
			switch item.(type) {
			case string, bool, float64:
				parts = append(parts, fmt.Sprint(item))
			}
		}
		return strings.Join(parts, "; ")
	default:
		return ""
	}
}

// looseStrings reads a list of strings, accepting a single string in place of
// a one-element list and skipping elements that are not text.
func looseStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		if s := strings.TrimSpace(looseString(raw)); s != "" {
			return []string{s}
		}
		return nil
	}
	var out []string
	for _, item := range items {
		if s := strings.TrimSpace(looseString(item)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// looseObjects reads a list of objects, accepting a single object in place of
// a one-element list and skipping elements that are not objects.
func looseObjects(raw json.RawMessage) []map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		items = []json.RawMessage{raw}
	}
	var out []map[string]json.RawMessage
	for _, item := range items {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(item, &obj); err == nil && obj != nil {
			out = append(out, obj)
		}
	}
	return out
}
