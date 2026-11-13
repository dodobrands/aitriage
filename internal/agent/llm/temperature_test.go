package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const (
	openAIReply    = `{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	anthropicReply = `{"id":"msg_test","type":"message","role":"assistant","model":"test-model","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`
	absent         = "<absent>"
)

// fakeProvider is an HTTP fake of a chat API. It records the temperature of
// every request it receives and answers through respond.
type fakeProvider struct {
	mu           sync.Mutex
	temperatures []string
	bodies       []map[string]json.RawMessage
	server       *httptest.Server
}

// newFakeProvider starts a fake that answers with respond, called with the
// decoded request body.
func newFakeProvider(t *testing.T, respond func(w http.ResponseWriter, body map[string]json.RawMessage)) *fakeProvider {
	t.Helper()
	f := &fakeProvider{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request body", http.StatusTeapot)
			return
		}
		temperature := absent
		if raw, ok := body["temperature"]; ok {
			temperature = string(raw)
		}
		f.mu.Lock()
		f.temperatures = append(f.temperatures, temperature)
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		respond(w, body)
	}))
	t.Cleanup(f.server.Close)
	return f
}

// answering returns a fake that always succeeds with reply.
func answering(t *testing.T, reply string) *fakeProvider {
	return newFakeProvider(t, func(w http.ResponseWriter, _ map[string]json.RawMessage) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	})
}

// refusingTemperature returns a fake that answers status and body to every
// request carrying a temperature, and succeeds with reply otherwise.
func refusingTemperature(t *testing.T, status int, refusal, reply string) *fakeProvider {
	return newFakeProvider(t, func(w http.ResponseWriter, body map[string]json.RawMessage) {
		w.Header().Set("Content-Type", "application/json")
		if _, ok := body["temperature"]; ok {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, refusal)
			return
		}
		_, _ = io.WriteString(w, reply)
	})
}

func (f *fakeProvider) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.temperatures...)
}

func (f *fakeProvider) field(request int, name string) (json.RawMessage, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.bodies[request][name]
	return value, ok
}

func (f *fakeProvider) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.temperatures, f.bodies = nil, nil
}

func chatOnce(t *testing.T, c Client) error {
	t.Helper()
	_, _, err := c.Chat(context.Background(), []Message{{Role: "system", Content: "classify"}, {Role: "user", Content: "finding"}})
	return err
}

// openAICompatible builds the provider client for an OpenAI-compatible fake.
func openAICompatible(t *testing.T, cfg Config, f *fakeProvider, log io.Writer) Client {
	t.Helper()
	cfg.BaseURL = f.server.URL
	cfg.APIKey = "test-key-not-real"
	c, err := newProviderClient(cfg, log)
	if err != nil {
		t.Fatalf("newProviderClient(%+v): %v", cfg, err)
	}
	return c
}

func claude(cfg Config, f *fakeProvider, log io.Writer) Client {
	cfg.Provider = "anthropic"
	return newAnthropicClient(cfg, log, option.WithAPIKey("test-key-not-real"), option.WithBaseURL(f.server.URL), option.WithMaxRetries(0))
}

func sameTemperatures(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestParseTemperature(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		value    float64
		explicit bool
		omit     bool
	}{
		{raw: "", value: DefaultTemperature},
		{raw: "  ", value: DefaultTemperature},
		{raw: "0", value: 0, explicit: true},
		{raw: "-0", value: 0, explicit: true},
		{raw: "0.7", value: 0.7, explicit: true},
		{raw: " 1 ", value: 1, explicit: true},
		{raw: "2", value: 2, explicit: true},
		{raw: "default", explicit: true, omit: true},
		{raw: "Default", explicit: true, omit: true},
		{raw: "provider default", explicit: true, omit: true},
	} {
		got, err := parseTemperature(tc.raw)
		if err != nil {
			t.Errorf("parseTemperature(%q) error = %v", tc.raw, err)
			continue
		}
		if got.value != tc.value || got.explicit != tc.explicit || got.omit != tc.omit {
			t.Errorf("parseTemperature(%q) = %+v, want value %v explicit %v omit %v", tc.raw, got, tc.value, tc.explicit, tc.omit)
		}
	}
	for _, raw := range []string{"warm", "-0.1", "2.01", "NaN", "Inf", "0,5"} {
		if _, err := parseTemperature(raw); err == nil {
			t.Errorf("parseTemperature(%q) accepted an invalid value", raw)
		}
	}
	if got := formatTemperature(0); got != "0" {
		t.Errorf("formatTemperature(0) = %q, want 0", got)
	}
}

// A flag value is checked when it is parsed and wins over the configured one.
func TestTemperatureFlag(t *testing.T) {
	var flag TemperatureFlag
	if got := flag.Or("0.5"); got != "0.5" {
		t.Fatalf("unset flag Or(0.5) = %q, want the configured value", got)
	}
	if err := flag.Set("hot"); err == nil {
		t.Fatal("Set(hot) accepted an invalid temperature")
	}
	if flag != "" {
		t.Fatalf("a rejected value was stored: %q", flag)
	}
	if err := flag.Set(" 0.9 "); err != nil {
		t.Fatal(err)
	}
	if got := flag.Or("0.5"); got != "0.9" {
		t.Fatalf("Or(0.5) = %q, want the flag value 0.9", got)
	}
	if flag.String() != "0.9" || flag.Type() != "string" {
		t.Fatalf("String() = %q, Type() = %q", flag.String(), flag.Type())
	}
}

// Every OpenAI-compatible provider gets the AITriage default, 0, unless the
// configuration says otherwise.
func TestOpenAICompatibleRequestsCarryTheTemperature(t *testing.T) {
	for _, provider := range []string{"openai", "groq", "ollama", "gemini"} {
		for _, tc := range []struct {
			setting string
			want    string
		}{
			{setting: "", want: "0"},
			{setting: "0.7", want: "0.7"},
			{setting: "default", want: absent},
		} {
			f := answering(t, openAIReply)
			var log bytes.Buffer
			c := openAICompatible(t, Config{Provider: provider, Model: "test-model", Temperature: tc.setting}, f, &log)
			if err := chatOnce(t, c); err != nil {
				t.Fatalf("%s %q: %v", provider, tc.setting, err)
			}
			if got := f.seen(); !sameTemperatures(got, tc.want) {
				t.Errorf("%s with temperature %q sent %v, want [%s]", provider, tc.setting, got, tc.want)
			}
			if log.Len() != 0 {
				t.Errorf("%s with temperature %q printed %q, want nothing", provider, tc.setting, log.String())
			}
		}
	}
}

// The public constructor sends the default too.
func TestNewClientSendsTheDefaultTemperature(t *testing.T) {
	f := answering(t, openAIReply)
	c, err := NewClient(Config{Provider: "ollama", Model: "test-model", BaseURL: f.server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := chatOnce(t, c); err != nil {
		t.Fatal(err)
	}
	if got := f.seen(); !sameTemperatures(got, "0") {
		t.Fatalf("NewClient sent %v, want [0]", got)
	}
	if got := EffectiveTemperature(c); got != "0" {
		t.Fatalf("EffectiveTemperature = %q, want 0", got)
	}
}

func TestOpenAIReasoningModels(t *testing.T) {
	for _, model := range []string{"o1", "o1-mini", "o3", "o3-mini", "o3-pro", "o4-mini", "gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-5.1", "gpt-5.2-codex", "openai/o3", "openai/gpt-5", "O3-MINI"} {
		if !openAIReasoningModel(model) {
			t.Errorf("%s is an OpenAI reasoning model", model)
		}
	}
	for _, model := range []string{"", "gpt-4o", "gpt-4.1-mini", "gpt-oss-20b", "openai/gpt-oss-120b", "gemini-2.5-flash", "llama-3.3-70b-versatile", "omni-moderation-latest", "olmo2", "gpt-50"} {
		if openAIReasoningModel(model) {
			t.Errorf("%s is not an OpenAI reasoning model", model)
		}
	}
}

// Reasoning models reject any temperature but their default: they get none,
// and an explicit setting says so once.
func TestReasoningModelsGetNoTemperature(t *testing.T) {
	for _, tc := range []struct {
		provider, model, setting string
		warns                    bool
	}{
		{provider: "openai", model: "o3-mini"},
		{provider: "openai", model: "gpt-5", setting: "0.3", warns: true},
		{provider: "ollama", model: "openai/gpt-5-mini"},
	} {
		f := answering(t, openAIReply)
		var log bytes.Buffer
		c := openAICompatible(t, Config{Provider: tc.provider, Model: tc.model, Temperature: tc.setting}, f, &log)
		for range 2 {
			if err := chatOnce(t, c); err != nil {
				t.Fatal(err)
			}
		}
		if got := f.seen(); !sameTemperatures(got, absent, absent) {
			t.Errorf("%s sent %v, want no temperature", tc.model, got)
		}
		lines := strings.Count(log.String(), "\n")
		if tc.warns && (lines != 1 || !strings.Contains(log.String(), tc.model)) {
			t.Errorf("%s with an explicit temperature printed %q, want one line naming the model", tc.model, log.String())
		}
		if !tc.warns && lines != 0 {
			t.Errorf("%s with the default printed %q, want nothing", tc.model, log.String())
		}
		if got := EffectiveTemperature(c); got != ProviderDefaultTemperature {
			t.Errorf("%s EffectiveTemperature = %q, want %q", tc.model, got, ProviderDefaultTemperature)
		}
	}
}

// Turning thinking off for OpenAI-compatible reasoning endpoints does not
// change the temperature they get.
func TestDisableThinkingKeepsTheTemperature(t *testing.T) {
	for _, disable := range []bool{false, true} {
		f := answering(t, openAIReply)
		c := openAICompatible(t, Config{Provider: "openai", Model: "test-model", DisableThinking: disable}, f, io.Discard)
		if err := chatOnce(t, c); err != nil {
			t.Fatal(err)
		}
		if got := f.seen(); !sameTemperatures(got, "0") {
			t.Errorf("DisableThinking=%v sent %v, want [0]", disable, got)
		}
		thinking, ok := f.field(0, "thinking")
		if disable != ok || (disable && string(thinking) != `{"type":"disabled"}`) {
			t.Errorf("DisableThinking=%v sent thinking %s (present %v)", disable, thinking, ok)
		}
	}
}

func TestAnthropicTakesTemperature(t *testing.T) {
	for _, model := range []string{"claude-sonnet-4-5", "claude-sonnet-4-5-20250929", "claude-opus-4-1", "claude-opus-4-1-20250805", "claude-opus-4-0", "claude-opus-4-20250514", "claude-sonnet-4-20250514", "claude-opus-4-5", "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5", "claude-haiku-4-5-20251001", "claude-3-7-sonnet-latest", "claude-3-5-haiku-20241022", "claude-3-haiku-20240307", "Claude-Sonnet-4-5", "anthropic/claude-sonnet-4.5", "anthropic/claude-3.7-sonnet"} {
		if !anthropicTakesTemperature(model) {
			t.Errorf("%s accepts a temperature", model)
		}
	}
	for _, model := range []string{"", "claude-opus-4-7", "claude-opus-4-8", "claude-opus-5", "claude-opus-5-5", "claude-sonnet-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-mythos-preview", "claude-next", "anthropic/claude-opus-4.7"} {
		if anthropicTakesTemperature(model) {
			t.Errorf("%s takes only its default temperature", model)
		}
	}
}

func TestAnthropicRequestsCarryTheTemperature(t *testing.T) {
	for _, tc := range []struct {
		model, setting, want string
		warns                bool
	}{
		{model: "", want: "0"}, // the client's default model, claude-sonnet-4-5
		{model: "claude-sonnet-4-5", setting: "0.9", want: "0.9"},
		{model: "claude-sonnet-4-5", setting: "1.5", want: absent, warns: true}, // Anthropic takes 0 to 1
		{model: "claude-sonnet-4-5", setting: "default", want: absent},
		{model: "claude-opus-4-7", want: absent},
		{model: "claude-opus-4-7", setting: "0.2", want: absent, warns: true},
	} {
		f := answering(t, anthropicReply)
		var log bytes.Buffer
		c := claude(Config{Model: tc.model, Temperature: tc.setting}, f, &log)
		if err := chatOnce(t, c); err != nil {
			t.Fatalf("%s %q: %v", tc.model, tc.setting, err)
		}
		if got := f.seen(); !sameTemperatures(got, tc.want) {
			t.Errorf("%s with temperature %q sent %v, want [%s]", tc.model, tc.setting, got, tc.want)
		}
		if lines := strings.Count(log.String(), "\n"); (lines == 1) != tc.warns || lines > 1 {
			t.Errorf("%s with temperature %q printed %q, want a notice: %v", tc.model, tc.setting, log.String(), tc.warns)
		}
	}
}

// A Claude model behind an OpenAI-compatible gateway follows Claude's rules.
func TestClaudeBehindAGatewayFollowsClaudeRules(t *testing.T) {
	for _, tc := range []struct{ model, want string }{
		{model: "anthropic/claude-sonnet-4.5", want: "0"},
		{model: "anthropic/claude-opus-4.7", want: absent},
	} {
		f := answering(t, openAIReply)
		c := openAICompatible(t, Config{Provider: "openai", Model: tc.model}, f, io.Discard)
		if err := chatOnce(t, c); err != nil {
			t.Fatal(err)
		}
		if got := f.seen(); !sameTemperatures(got, tc.want) {
			t.Errorf("%s sent %v, want [%s]", tc.model, got, tc.want)
		}
	}
}

// A request that enables extended or adaptive thinking takes only the
// default temperature, so it gets none.
func TestAnthropicThinkingTakesNoTemperature(t *testing.T) {
	zero := 0.0
	for _, tc := range []struct {
		name     string
		thinking anthropic.ThinkingConfigParamUnion
		want     bool
	}{
		{name: "no thinking", want: true},
		{name: "thinking disabled", thinking: anthropic.ThinkingConfigParamUnion{OfDisabled: &anthropic.ThinkingConfigDisabledParam{}}, want: true},
		{name: "extended thinking", thinking: anthropic.ThinkingConfigParamOfEnabled(1024)},
		{name: "adaptive thinking", thinking: anthropic.ThinkingConfigParamUnion{OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{}}},
	} {
		params := anthropic.MessageNewParams{Model: "claude-sonnet-4-5", MaxTokens: 16, Thinking: tc.thinking}
		got := setAnthropicTemperature(&params, &zero)
		data, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want || strings.Contains(string(data), `"temperature"`) != tc.want {
			t.Errorf("%s: set = %v, request %s; want temperature sent: %v", tc.name, got, data, tc.want)
		}
	}
	params := anthropic.MessageNewParams{Model: "claude-sonnet-4-5", MaxTokens: 16}
	if setAnthropicTemperature(&params, nil) || params.Temperature.Valid() {
		t.Error("a request with no temperature to send got one")
	}
}

// An endpoint that refuses the temperature gets the request again without
// it, once, and no temperature for the rest of the run; one line says so.
func TestRefusedTemperatureIsDroppedForTheRun(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		refusal string
	}{
		{"openai error", http.StatusBadRequest, `{"error":{"message":"Unsupported value: 'temperature' does not support 0 with this model. Only the default (1) value is supported.","type":"invalid_request_error","param":"temperature","code":"unsupported_value"}}`},
		{"unwrapped error", http.StatusBadRequest, `{"object":"error","message":"temperature is not supported for this model","type":"BadRequestError","param":null,"code":400}`},
		{"validation error", http.StatusUnprocessableEntity, `{"detail":[{"type":"extra_forbidden","loc":["body","temperature"],"msg":"Extra inputs are not permitted"}]}`},
		{"plain text", http.StatusBadRequest, `Unsupported parameter: temperature`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := refusingTemperature(t, tc.status, tc.refusal, openAIReply)
			var log bytes.Buffer
			c := NewRetryClient(openAICompatible(t, Config{Provider: "openai", Model: "custom-model"}, f, &log), 3)
			if got := EffectiveTemperature(c); got != "0" {
				t.Fatalf("EffectiveTemperature before the run = %q, want 0", got)
			}
			if err := chatOnce(t, c); err != nil {
				t.Fatalf("first request: %v", err)
			}
			if got := f.seen(); !sameTemperatures(got, "0", absent) {
				t.Fatalf("first request sent %v, want [0 %s]", got, absent)
			}
			f.reset()
			if err := chatOnce(t, c); err != nil {
				t.Fatalf("second request: %v", err)
			}
			if got := f.seen(); !sameTemperatures(got, absent) {
				t.Fatalf("second request sent %v, want no temperature", got)
			}
			if got := EffectiveTemperature(c); got != ProviderDefaultTemperature {
				t.Fatalf("EffectiveTemperature after the refusal = %q, want %q", got, ProviderDefaultTemperature)
			}
			if lines := strings.Count(log.String(), "\n"); lines != 1 || !strings.Contains(log.String(), "custom-model") {
				t.Fatalf("log = %q, want one line naming the model", log.String())
			}
		})
	}
}

func TestAnthropicRefusedTemperatureIsDropped(t *testing.T) {
	f := refusingTemperature(t, http.StatusBadRequest, `{"type":"error","error":{"type":"invalid_request_error","message":"temperature: not supported for this model"}}`, anthropicReply)
	var log bytes.Buffer
	c := claude(Config{Model: "claude-sonnet-4-5"}, f, &log)
	for range 2 {
		if err := chatOnce(t, c); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.seen(); !sameTemperatures(got, "0", absent, absent) {
		t.Fatalf("requests sent %v, want [0 %s %s]", got, absent, absent)
	}
	if lines := strings.Count(log.String(), "\n"); lines != 1 {
		t.Fatalf("log = %q, want one line", log.String())
	}
}

// A 400 for another reason is the caller's error: the request is not repeated
// and the temperature stays.
func TestUnrelatedBadRequestKeepsTheTemperature(t *testing.T) {
	f := newFakeProvider(t, func(w http.ResponseWriter, _ map[string]json.RawMessage) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"This model's maximum context length is exceeded.","type":"invalid_request_error","param":"messages","code":"context_length_exceeded"}}`)
	})
	var log bytes.Buffer
	c := openAICompatible(t, Config{Provider: "openai", Model: "custom-model"}, f, &log)
	if err := chatOnce(t, c); err == nil {
		t.Fatal("a 400 must reach the caller")
	}
	if got := f.seen(); !sameTemperatures(got, "0") {
		t.Fatalf("requests sent %v, want one with the temperature", got)
	}
	if got := EffectiveTemperature(c); got != "0" || log.Len() != 0 {
		t.Fatalf("EffectiveTemperature = %q, log %q; want the temperature kept and nothing printed", got, log.String())
	}
}

// The request is repeated at most once: an endpoint that keeps refusing gets
// two requests and the error, never a loop.
func TestRefusalIsRetriedOnlyOnce(t *testing.T) {
	f := newFakeProvider(t, func(w http.ResponseWriter, _ map[string]json.RawMessage) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"temperature is not supported","type":"invalid_request_error","param":"temperature"}}`)
	})
	var log bytes.Buffer
	c := openAICompatible(t, Config{Provider: "openai", Model: "custom-model"}, f, &log)
	if err := chatOnce(t, c); err == nil {
		t.Fatal("want the endpoint's error")
	}
	if got := f.seen(); !sameTemperatures(got, "0", absent) {
		t.Fatalf("requests sent %v, want [0 %s]", got, absent)
	}
	if lines := strings.Count(log.String(), "\n"); lines != 1 {
		t.Fatalf("log = %q, want one line", log.String())
	}
}

// Parallel requests that are all refused print one line between them.
func TestConcurrentRefusalsPrintOneLine(t *testing.T) {
	f := refusingTemperature(t, http.StatusBadRequest, `{"error":{"message":"Unsupported parameter: 'temperature'","type":"invalid_request_error","param":"temperature"}}`, openAIReply)
	var log syncBuffer
	c := openAICompatible(t, Config{Provider: "openai", Model: "custom-model"}, f, &log)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- chatOnce(t, c) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if lines := strings.Count(log.String(), "\n"); lines != 1 {
		t.Fatalf("log = %q, want one line", log.String())
	}
	f.reset()
	if err := chatOnce(t, c); err != nil {
		t.Fatal(err)
	}
	if got := f.seen(); !sameTemperatures(got, absent) {
		t.Fatalf("a later request sent %v, want no temperature", got)
	}
}

// An invalid configured temperature is reported and replaced by the default;
// it never stops the run.
func TestInvalidConfiguredTemperatureFallsBackToTheDefault(t *testing.T) {
	f := answering(t, openAIReply)
	var log bytes.Buffer
	c := openAICompatible(t, Config{Provider: "openai", Model: "test-model", Temperature: "warm"}, f, &log)
	if err := chatOnce(t, c); err != nil {
		t.Fatal(err)
	}
	if got := f.seen(); !sameTemperatures(got, "0") {
		t.Fatalf("sent %v, want the default 0", got)
	}
	if !strings.Contains(log.String(), `"warm"`) || strings.Count(log.String(), "\n") != 1 {
		t.Fatalf("log = %q, want one line naming the invalid value", log.String())
	}
}

func TestEffectiveTemperatureOfOtherClients(t *testing.T) {
	if got := EffectiveTemperature(&mockClient{}); got != ProviderDefaultTemperature {
		t.Errorf("a client that sets no temperature reports %q, want %q", got, ProviderDefaultTemperature)
	}
	if got := EffectiveTemperature(nil); got != ProviderDefaultTemperature {
		t.Errorf("EffectiveTemperature(nil) = %q, want %q", got, ProviderDefaultTemperature)
	}
	f := answering(t, openAIReply)
	c := NewRetryClient(openAICompatible(t, Config{Provider: "openai", Model: "test-model", Temperature: "0.25"}, f, io.Discard), 3)
	if got := EffectiveTemperature(c); got != "0.25" {
		t.Errorf("EffectiveTemperature through the retry wrapper = %q, want 0.25", got)
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
