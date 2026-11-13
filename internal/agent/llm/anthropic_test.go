package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// thinkingBlock is the block Claude Sonnet 5.5 puts before its text when a
// request leaves thinking unset: adaptive thinking, with the text left out
// under the default display.
const thinkingBlock = `{"type":"thinking","thinking":"","signature":"c2lnbmF0dXJl"}`

// sonnet55Message is a Messages API reply from claude-sonnet-5-5.
func sonnet55Message(content, stopReason, stopDetails string) string {
	return fmt.Sprintf(`{"id":"msg_test","type":"message","role":"assistant","model":"claude-sonnet-5-5","content":%s,"stop_reason":%q,"stop_details":%s,"usage":{"input_tokens":120,"output_tokens":340}}`,
		content, stopReason, stopDetails)
}

// sonnet55Answer is a reply that thinks first and then answers with text.
func sonnet55Answer(text string) string {
	return sonnet55Message(`[`+thinkingBlock+`,{"type":"text","text":`+strconv.Quote(text)+`}]`, "end_turn", "null")
}

// fakeSonnet55 emulates the Claude API serving Claude Sonnet 5.5: a request
// the model rejects gets the API's 400, any other the reply.
func fakeSonnet55(t *testing.T, reply func() string) *fakeProvider {
	return newFakeProvider(t, func(w http.ResponseWriter, body map[string]json.RawMessage) {
		w.Header().Set("Content-Type", "application/json")
		if problem := sonnet55Rejects(body); problem != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"type":"error","error":{"type":"invalid_request_error","message":%q}}`, problem)
			return
		}
		_, _ = io.WriteString(w, reply())
	})
}

// sonnet55Rejects returns the reason Claude Sonnet 5.5 gives for rejecting a
// request, or "" for a request it accepts. It rejects a sampling parameter
// with a value other than its default, thinking turned off with "disabled"
// or set to a budget, a forced tool choice, and a conversation that does not
// end with a user turn (an assistant prefill).
func sonnet55Rejects(body map[string]json.RawMessage) string {
	if raw, ok := body["temperature"]; ok && string(raw) != "1" {
		return "temperature: only the default value 1 is supported for this model"
	}
	for _, name := range []string{"top_p", "top_k"} {
		if _, ok := body[name]; ok {
			return name + ": only the default value is supported for this model"
		}
	}
	var setting struct {
		Type string `json:"type"`
	}
	if raw, ok := body["thinking"]; ok {
		_ = json.Unmarshal(raw, &setting)
		switch setting.Type {
		case "adaptive", "between_tools":
		case "disabled":
			return `To turn thinking off on this model, send "thinking": {"type": "between_tools"} instead of {"type": "disabled"}.`
		default:
			return "thinking.type: " + setting.Type + " is not supported for this model"
		}
	}
	if raw, ok := body["tool_choice"]; ok {
		_ = json.Unmarshal(raw, &setting)
		if setting.Type == "any" || setting.Type == "tool" {
			return `tool_choice: type "tool" and "any" are not supported for this model.`
		}
	}
	var messages []struct {
		Role string `json:"role"`
	}
	_ = json.Unmarshal(body["messages"], &messages)
	if len(messages) == 0 || messages[len(messages)-1].Role != "user" {
		return "This model does not support assistant message prefill. The conversation must end with a user message."
	}
	return ""
}

func classificationRequest() []Message {
	return []Message{{Role: "system", Content: "classify"}, {Role: "user", Content: "finding"}}
}

func TestFakeSonnet55RejectsWhatTheModelRejects(t *testing.T) {
	for _, body := range []string{
		`{"temperature":0,"messages":[{"role":"user"}]}`,
		`{"top_p":0.9,"messages":[{"role":"user"}]}`,
		`{"thinking":{"type":"disabled"},"messages":[{"role":"user"}]}`,
		`{"thinking":{"type":"enabled","budget_tokens":1024},"messages":[{"role":"user"}]}`,
		`{"tool_choice":{"type":"any"},"messages":[{"role":"user"}]}`,
		`{"messages":[{"role":"user"},{"role":"assistant"}]}`,
	} {
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatal(err)
		}
		if sonnet55Rejects(decoded) == "" {
			t.Errorf("the fake accepts %s", body)
		}
	}
	var accepted map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"temperature":1,"thinking":{"type":"adaptive"},"tool_choice":{"type":"auto"},"messages":[{"role":"user"},{"role":"assistant"},{"role":"user"}]}`), &accepted)
	if problem := sonnet55Rejects(accepted); problem != "" {
		t.Errorf("the fake rejects a valid request: %s", problem)
	}
}

// With no model configured, requests name claude-sonnet-5-5 and are made
// the way it accepts them: no sampling parameter, no thinking setting (it
// runs adaptive thinking), max_tokens with room for thinking as well as the
// reply, and a conversation that ends with a user turn. The answer is the
// text after the thinking block.
func TestDefaultAnthropicModelIsAskedTheWaySonnet55Accepts(t *testing.T) {
	const answer = `{"finding_dispositions":[]}`
	f := fakeSonnet55(t, func() string { return sonnet55Answer(answer) })
	var log bytes.Buffer
	c := NewRetryClient(claude(Config{}, f, &log), 3)

	got, usage, err := c.Chat(context.Background(), classificationRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got != answer {
		t.Fatalf("answer = %q, want the text after the thinking block %q", got, answer)
	}
	if usage.PromptTokens != 120 || usage.CompletionTokens != 340 {
		t.Fatalf("usage = %+v, want the reply's 120 input and 340 output tokens", usage)
	}
	if model, _ := f.field(0, "model"); string(model) != `"claude-sonnet-5-5"` {
		t.Fatalf("model = %s, want claude-sonnet-5-5", model)
	}
	if maxTokens, _ := f.field(0, "max_tokens"); string(maxTokens) != "16000" {
		t.Fatalf("max_tokens = %s, want 16000", maxTokens)
	}
	for _, name := range []string{"temperature", "top_p", "top_k", "thinking", "tool_choice", "tools"} {
		if value, ok := f.field(0, name); ok {
			t.Errorf("the request carries %s: %s", name, value)
		}
	}
	if log.Len() != 0 {
		t.Fatalf("log = %q, want nothing", log.String())
	}

	// The one request that carries an earlier answer, the threat-model
	// repair request, ends with the user's request and is accepted.
	repair := append(classificationRequest(),
		Message{Role: "assistant", Content: "(empty reply)"},
		Message{Role: "user", Content: "Reply again with ONLY that JSON object"})
	if _, _, err := c.Chat(context.Background(), repair); err != nil {
		t.Fatalf("repair request: %v", err)
	}
}

// The answer is every text block, in order; thinking blocks and any other
// block are not part of it.
func TestAnthropicAnswerJoinsTheTextBlocks(t *testing.T) {
	content := `[` + thinkingBlock + `,{"type":"redacted_thinking","data":"ZW5jcnlwdGVk"},{"type":"text","text":"{\"finding_dispositions\":"},` +
		thinkingBlock + `,{"type":"text","text":"[]}"}]`
	f := fakeSonnet55(t, func() string { return sonnet55Message(content, "end_turn", "null") })
	got, _, err := claude(Config{}, f, io.Discard).Chat(context.Background(), classificationRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"finding_dispositions":[]}` {
		t.Fatalf("answer = %q, want the two text blocks joined", got)
	}
}

// A request Claude declines comes back as HTTP 200 with stop_reason
// "refusal". It is a failed request, never an answer, whether the refusal
// came before any output or after part of it: an error that matches
// ErrRefused and ErrNoAnswer, with the tokens it cost, one log line naming
// the category, and no second request with the same content.
func TestDeclinedRequestIsAFailedRequest(t *testing.T) {
	for _, tc := range []struct {
		name, content, details, category string
	}{
		{
			name:     "before any output",
			content:  `[]`,
			details:  `{"type":"refusal","category":"cyber","explanation":"This request was declined."}`,
			category: "cyber",
		},
		{
			name:     "after part of the output",
			content:  `[` + thinkingBlock + `,{"type":"text","text":"{\"finding_dispositions\":[{\"finding_index\":0"}]`,
			details:  `{"type":"refusal","category":"general_harms","explanation":null}`,
			category: "general_harms",
		},
		{
			name:     "without a category",
			content:  `[]`,
			details:  `{"type":"refusal","category":null,"explanation":null}`,
			category: "none",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fakeSonnet55(t, func() string { return sonnet55Message(tc.content, "refusal", tc.details) })
			var log bytes.Buffer
			c := NewRetryClient(claude(Config{}, f, &log), 3)

			got, usage, err := c.Chat(context.Background(), classificationRequest())
			if got != "" {
				t.Fatalf("answer = %q, want none", got)
			}
			if !errors.Is(err, ErrRefused) || !errors.Is(err, ErrNoAnswer) {
				t.Fatalf("err = %v, want one that matches ErrRefused and ErrNoAnswer", err)
			}
			var refusal *RefusalError
			if !errors.As(err, &refusal) || refusal.Model != "claude-sonnet-5-5" {
				t.Fatalf("err = %v, want a *RefusalError naming the model", err)
			}
			if !strings.Contains(err.Error(), "category "+tc.category) {
				t.Fatalf("err = %v, want the category %s", err, tc.category)
			}
			if usage.CompletionTokens != 340 {
				t.Fatalf("usage = %+v, want the tokens the declined request cost", usage)
			}
			if got := len(f.seen()); got != 1 {
				t.Fatalf("requests = %d, want 1: the same request is not sent again", got)
			}
			if lines := strings.Count(log.String(), "\n"); lines != 1 || !strings.Contains(log.String(), "category "+tc.category) {
				t.Fatalf("log = %q, want one line naming the category", log.String())
			}
		})
	}
}

// Thinking that runs into max_tokens leaves no text. That is no answer
// (ErrNoAnswer, not a refusal), and the same request is not sent again.
func TestThinkingWithoutTextIsNoAnswer(t *testing.T) {
	f := fakeSonnet55(t, func() string { return sonnet55Message(`[`+thinkingBlock+`]`, "max_tokens", "null") })
	var log bytes.Buffer
	c := NewRetryClient(claude(Config{}, f, &log), 3)

	got, _, err := c.Chat(context.Background(), classificationRequest())
	if got != "" || !errors.Is(err, ErrNoAnswer) || errors.Is(err, ErrRefused) {
		t.Fatalf("answer %q, err %v; want no answer and an error that matches ErrNoAnswer only", got, err)
	}
	if !strings.Contains(err.Error(), "stop_reason max_tokens") {
		t.Fatalf("err = %v, want the stop reason", err)
	}
	if got := len(f.seen()); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
	if log.Len() != 0 {
		t.Fatalf("log = %q, want nothing", log.String())
	}
}

// A reply is an answer only when it is complete and says something. One with
// no content blocks, with text that is empty or only whitespace, or cut off
// at the token limit is no answer: an error that matches ErrNoAnswer (and
// ErrTruncated when cut off), never empty or partial text a stage would use
// or a conversation would send back as an empty assistant turn. Like any
// reply without an answer, it is not sent again.
func TestRepliesWithoutACompleteAnswerAreNoAnswer(t *testing.T) {
	const partial = `{\"finding_dispositions\":[{\"finding_index\":0`
	for _, tc := range []struct {
		name, content, stopReason, wantText string
		truncated                           bool
	}{
		{name: "no content blocks", content: `[]`, stopReason: "end_turn", wantText: "wrote no text (stop_reason end_turn)"},
		{name: "empty text", content: `[` + thinkingBlock + `,{"type":"text","text":""}]`, stopReason: "end_turn", wantText: "wrote no text"},
		{name: "whitespace only", content: `[` + thinkingBlock + `,{"type":"text","text":" \n\t "},{"type":"text","text":"\n"}]`, stopReason: "end_turn", wantText: "wrote no text"},
		{name: "cut off in the answer", content: `[` + thinkingBlock + `,{"type":"text","text":"` + partial + `"}]`, stopReason: "max_tokens", wantText: "stop_reason max_tokens, max_tokens 16000", truncated: true},
		{name: "cut off while thinking", content: `[` + thinkingBlock + `]`, stopReason: "max_tokens", wantText: "stop_reason max_tokens", truncated: true},
		{name: "context window exceeded", content: `[{"type":"text","text":"` + partial + `"}]`, stopReason: "model_context_window_exceeded", wantText: "stop_reason model_context_window_exceeded", truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fakeSonnet55(t, func() string { return sonnet55Message(tc.content, tc.stopReason, "null") })
			var log bytes.Buffer
			c := NewRetryClient(claude(Config{}, f, &log), 3)

			got, usage, err := c.Chat(context.Background(), classificationRequest())
			if got != "" {
				t.Fatalf("answer = %q, want none", got)
			}
			if !errors.Is(err, ErrNoAnswer) || errors.Is(err, ErrRefused) || errors.Is(err, ErrTruncated) != tc.truncated {
				t.Fatalf("err = %v; want ErrNoAnswer, not ErrRefused, ErrTruncated %v", err, tc.truncated)
			}
			if !strings.Contains(err.Error(), tc.wantText) || !strings.Contains(err.Error(), "claude-sonnet-5-5") {
				t.Fatalf("err = %v, want the model and %q", err, tc.wantText)
			}
			if usage.CompletionTokens != 340 {
				t.Fatalf("usage = %+v, want the tokens the reply cost", usage)
			}
			if got := len(f.seen()); got != 1 {
				t.Fatalf("requests = %d, want 1: the same request is not sent again", got)
			}
			if log.Len() != 0 {
				t.Fatalf("log = %q, want nothing", log.String())
			}
		})
	}
}

// Text around the answer is kept as the model wrote it: only a reply with
// nothing but whitespace is no answer.
func TestAnswerWithSurroundingWhitespaceIsKept(t *testing.T) {
	f := fakeSonnet55(t, func() string {
		return sonnet55Message(`[`+thinkingBlock+`,{"type":"text","text":"\n"},{"type":"text","text":"ok\n"}]`, "end_turn", "null")
	})
	got, _, err := claude(Config{}, f, io.Discard).Chat(context.Background(), classificationRequest())
	if err != nil || got != "\nok\n" {
		t.Fatalf("answer %q, err %v; want the text blocks as written", got, err)
	}
}

// Claude Sonnet 5.5 answers 400 to any temperature but its default. The
// default model never gets one, not even a configured one, and one line says
// so. A name AITriage takes for an older model but that the endpoint serves
// as Claude Sonnet 5.5, as a gateway alias may, is refused once and asked
// again without it for the rest of the run.
func TestSonnet55NeverGetsATemperature(t *testing.T) {
	t.Run("default model", func(t *testing.T) {
		f := fakeSonnet55(t, func() string { return sonnet55Answer("ok") })
		var log bytes.Buffer
		c := claude(Config{Temperature: "0.3"}, f, &log)
		for range 2 {
			if err := chatOnce(t, c); err != nil {
				t.Fatal(err)
			}
		}
		if got := f.seen(); !sameTemperatures(got, absent, absent) {
			t.Fatalf("requests sent %v, want no temperature", got)
		}
		if lines := strings.Count(log.String(), "\n"); lines != 1 || !strings.Contains(log.String(), "claude-sonnet-5-5") {
			t.Fatalf("log = %q, want one line naming the model", log.String())
		}
		if got := EffectiveTemperature(c); got != ProviderDefaultTemperature {
			t.Fatalf("EffectiveTemperature = %q, want %q", got, ProviderDefaultTemperature)
		}
	})
	t.Run("alias served as Sonnet 5.5", func(t *testing.T) {
		f := fakeSonnet55(t, func() string { return sonnet55Answer("ok") })
		var log bytes.Buffer
		c := claude(Config{Model: "claude-sonnet-4-5"}, f, &log)
		for range 2 {
			got, _, err := c.Chat(context.Background(), classificationRequest())
			if err != nil || got != "ok" {
				t.Fatalf("answer %q, err %v; want ok", got, err)
			}
		}
		if got := f.seen(); !sameTemperatures(got, "0", absent, absent) {
			t.Fatalf("requests sent %v, want [0 %s %s]", got, absent, absent)
		}
		if lines := strings.Count(log.String(), "\n"); lines != 1 {
			t.Fatalf("log = %q, want one line", log.String())
		}
	})
}

// A user who configures an older Claude model sees no change: the request
// carries the same fields as before (temperature 0, max_tokens 8192, no
// thinking setting) and the one text block of the reply is the answer.
func TestExplicitOlderClaudeModelIsAskedAsBefore(t *testing.T) {
	f := answering(t, anthropicReply)
	got, _, err := claude(Config{Model: "claude-sonnet-4-5"}, f, io.Discard).Chat(context.Background(), classificationRequest())
	if err != nil || got != "ok" {
		t.Fatalf("answer %q, err %v; want ok", got, err)
	}
	f.mu.Lock()
	var fields []string
	for name := range f.bodies[0] {
		fields = append(fields, name)
	}
	f.mu.Unlock()
	slices.Sort(fields)
	if want := []string{"max_tokens", "messages", "model", "system", "temperature"}; !slices.Equal(fields, want) {
		t.Fatalf("request fields = %v, want %v", fields, want)
	}
	for name, want := range map[string]string{"model": `"claude-sonnet-4-5"`, "max_tokens": "8192", "temperature": "0"} {
		if value, _ := f.field(0, name); string(value) != want {
			t.Errorf("%s = %s, want %s", name, value, want)
		}
	}
}

func TestAnthropicMaxTokens(t *testing.T) {
	for _, model := range []string{"claude-sonnet-5-5", "claude-sonnet-5", "claude-opus-5-5", "claude-opus-5", "claude-haiku-5-5", "claude-fable-5-2", "claude-mythos-5-2", "claude-sonnet-6", "anthropic/claude-sonnet-5.5", "Claude-Sonnet-5-5"} {
		if !anthropicThinksByDefault(model) || anthropicMaxTokens(model) != anthropicThinkingTokens {
			t.Errorf("%s thinks by default and gets max_tokens %d, got %d", model, anthropicThinkingTokens, anthropicMaxTokens(model))
		}
	}
	for _, model := range []string{"", "claude-sonnet-4-5", "claude-sonnet-4-5-20250929", "claude-sonnet-4-20250514", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-opus-4-1", "claude-haiku-4-5", "claude-3-7-sonnet-latest", "claude-3-5-haiku-20241022", "claude-sonnet-20991231", "anthropic/claude-sonnet-4.5", "gateway-alias"} {
		if anthropicThinksByDefault(model) || anthropicMaxTokens(model) != anthropicReplyTokens {
			t.Errorf("%s keeps max_tokens %d, got %d", model, anthropicReplyTokens, anthropicMaxTokens(model))
		}
	}
}

func TestRefusalErrorMatchesNoAnswer(t *testing.T) {
	err := fmt.Errorf("anthropic chat error: %w", &RefusalError{Model: "claude-sonnet-5-5", Category: "cyber"})
	if !errors.Is(err, ErrRefused) || !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("%v does not match ErrRefused and ErrNoAnswer", err)
	}
	if errors.Is(errors.New("anthropic chat error: 529 overloaded"), ErrNoAnswer) {
		t.Fatal("an unrelated error matches ErrNoAnswer")
	}
	if !errors.Is(fmt.Errorf("anthropic chat error: %w", ErrTruncated), ErrNoAnswer) || errors.Is(err, ErrTruncated) {
		t.Fatal("ErrTruncated must match ErrNoAnswer, and a refusal is not a truncated reply")
	}
	if got := (&RefusalError{Model: "m"}).Error(); !strings.Contains(got, "category none") {
		t.Fatalf("Error() = %q, want category none when the provider named none", got)
	}
}
