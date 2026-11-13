package llm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/openai/openai-go"
	openai_option "github.com/openai/openai-go/option"
)

const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta/openai/"

// The models requests name when the configuration sets none (llm.model,
// AITRIAGE_LLM_MODEL or --model). Verdicts differ between models, so a change
// here changes the verdicts of every run that relies on it: the README lists
// these, and the release notes say when one moves. A minor release warns the
// runs that rely on a default before a later one changes it (CONTRIBUTING.md,
// "Deprecations and default changes"), unless the provider retires the model
// before a release with the warning could reach users.
const (
	DefaultGeminiModel    = "gemini-3.5-flash-lite"
	DefaultAnthropicModel = "claude-sonnet-5-5"
	DefaultOpenAIModel    = "gpt-4o"
)

// NextDefaultOpenAIModel is the OpenAI default from AITriage 1.16 on: OpenAI
// shuts down gpt-4o's snapshots on 2027-01-14 and names gpt-6-luna as their
// replacement. Until then a run that relies on the default is warned (see
// DefaultModelNotices).
const NextDefaultOpenAIModel = "gpt-6-luna"

// openAIDefaultWarning is the warning of a run that relies on the OpenAI
// default, which changes in AITriage 1.16.
const openAIDefaultWarning = "No OpenAI model is set, so AITriage uses " + DefaultOpenAIModel +
	", whose snapshots OpenAI shuts down on 2027-01-14. AITriage 1.16 will default to " +
	NextDefaultOpenAIModel + "; set llm.model to choose a model."

// ModelFlagUsage is the help text of a --model flag.
const ModelFlagUsage = "LLM model name (unset: " + DefaultGeminiModel + " for gemini, " +
	DefaultAnthropicModel + " for anthropic, " + DefaultOpenAIModel + " for openai; groq and ollama need one)"

// DefaultModelReporter is implemented by clients that know whether their
// requests name the provider's default model because the configuration names
// none.
type DefaultModelReporter interface {
	UsesDefaultModel() bool
}

// DefaultModelNotices returns what a run prints when client's requests name
// the provider's default model because no model is configured: info names the
// model, so the reader always sees which model judged the findings, and
// warning is set when that default is about to change, as the deprecation
// policy requires. Both are empty for a configured model and for a client that
// does not know its model, such as a host agent.
func DefaultModelNotices(client Client) (info, warning string) {
	r, ok := client.(DefaultModelReporter)
	if !ok || !r.UsesDefaultModel() {
		return "", ""
	}
	provider, model := RequestModel(client)
	if model == "" {
		return "", ""
	}
	info = fmt.Sprintf("No model set; using %s, the default for %s", model, provider)
	if provider == "openai" && model == DefaultOpenAIModel {
		warning = openAIDefaultWarning
	}
	return info, warning
}

// PrintDefaultModelNotices writes the DefaultModelNotices of client to w, one
// line each, and returns the warning, if any, for the run's summary.
func PrintDefaultModelNotices(w io.Writer, client Client) string {
	info, warning := DefaultModelNotices(client)
	if info != "" {
		_, _ = fmt.Fprintf(w, "   ℹ️ %s\n", info)
	}
	if warning != "" {
		_, _ = fmt.Fprintf(w, "   ⚠️ %s\n", warning)
	}
	return warning
}

const noLLMConfiguredMsg = `no LLM provider configured

Set one of these environment variables:
  export GEMINI_API_KEY=your-key     # Google Gemini (recommended)
  export ANTHROPIC_API_KEY=your-key  # Anthropic Claude
  export OPENAI_API_KEY=your-key     # OpenAI GPT

Or add to .aitriage.yaml:
  llm:
    provider: gemini
    api_key: your-key`

// openAIClient wraps the official openai-go SDK.
type openAIClient struct {
	client       openai.Client
	cfg          Config
	temperature  *temperatureControl
	defaultModel bool // no model configured: requests name the provider default
}

// openAIModel returns the model an OpenAI-compatible request names.
func openAIModel(configured string) string {
	if configured == "" {
		return DefaultOpenAIModel
	}
	return configured
}

// EffectiveTemperature implements TemperatureReporter.
func (c *openAIClient) EffectiveTemperature() string { return c.temperature.effective() }

// RequestModel implements ModelReporter.
func (c *openAIClient) RequestModel() (provider, model string) {
	return c.cfg.Provider, openAIModel(c.cfg.Model)
}

// UsesDefaultModel implements DefaultModelReporter.
func (c *openAIClient) UsesDefaultModel() bool { return c.defaultModel }

func (c *openAIClient) Chat(ctx context.Context, messages []Message) (string, Usage, error) {
	var oaiMessages []openai.ChatCompletionMessageParamUnion
	for _, m := range messages {
		switch m.Role {
		case "system":
			oaiMessages = append(oaiMessages, openai.SystemMessage(m.Content))
		case "user":
			oaiMessages = append(oaiMessages, openai.UserMessage(m.Content))
		case "assistant":
			oaiMessages = append(oaiMessages, openai.AssistantMessage(m.Content))
		}
	}

	model := openAIModel(c.cfg.Model)

	// Build per-request options for reasoning-model control.
	var reqOpts []openai_option.RequestOption
	if c.cfg.DisableThinking {
		// Disable thinking/reasoning traces for providers that support it
		// (Z.ai GLM-5.x, Xiaomi MiMo). Sends top-level {"thinking":{"type":"disabled"}}
		// in the request body via the openai-go SDK's extra-field mechanism.
		reqOpts = append(reqOpts, openai_option.WithJSONSet("thinking", map[string]string{"type": "disabled"}))
	}

	params := openai.ChatCompletionNewParams{
		Messages: oaiMessages,
		Model:    openai.ChatModel(model),
	}
	sent := params
	temperature := c.temperature.next()
	if temperature != nil {
		sent.Temperature = openai.Float(*temperature)
	}
	completion, err := c.client.Chat.Completions.New(ctx, sent, reqOpts...)
	if err != nil && temperature != nil && c.temperature.refused(err) {
		completion, err = c.client.Chat.Completions.New(ctx, params, reqOpts...)
	}
	if err != nil {
		return "", Usage{}, fmt.Errorf("openai chat error: %w", err)
	}

	if len(completion.Choices) == 0 {
		return "", Usage{}, fmt.Errorf("empty response from openai")
	}

	usage := usageFromOpenAI(completion.Usage)

	return completion.Choices[0].Message.Content, usage, nil
}

// anthropicClientWrapper wraps the official anthropic-sdk-go SDK.
type anthropicClientWrapper struct {
	client      anthropic.Client
	cfg         Config
	temperature *temperatureControl
	log         io.Writer // a declined request is reported here
}

// newAnthropicClient builds the Anthropic client from cfg; opts carry the
// credentials and transport settings.
func newAnthropicClient(cfg Config, log io.Writer, opts ...option.RequestOption) *anthropicClientWrapper {
	if log == nil {
		log = io.Discard
	}
	return &anthropicClientWrapper{
		client:      anthropic.NewClient(opts...),
		cfg:         cfg,
		temperature: newTemperatureControl(cfg, anthropicModel(cfg.Model), log),
		log:         log,
	}
}

// anthropicModel returns the model an Anthropic request names.
func anthropicModel(configured string) string {
	if configured == "" {
		return DefaultAnthropicModel
	}
	return configured
}

// EffectiveTemperature implements TemperatureReporter.
func (c *anthropicClientWrapper) EffectiveTemperature() string { return c.temperature.effective() }

// RequestModel implements ModelReporter.
func (c *anthropicClientWrapper) RequestModel() (provider, model string) {
	return "anthropic", anthropicModel(c.cfg.Model)
}

// UsesDefaultModel implements DefaultModelReporter.
func (c *anthropicClientWrapper) UsesDefaultModel() bool { return c.cfg.Model == "" }

func (c *anthropicClientWrapper) Chat(ctx context.Context, messages []Message) (string, Usage, error) {
	var systemBlocks []anthropic.TextBlockParam
	var anthropicMessages []anthropic.MessageParam

	for _, m := range messages {
		switch m.Role {
		case "system":
			systemBlocks = append(systemBlocks, anthropic.TextBlockParam{
				Text: m.Content,
				Type: "text",
			})
		case "user":
			anthropicMessages = append(anthropicMessages,
				anthropic.NewUserMessage(anthropic.NewTextBlock(m.Content)))
		case "assistant":
			anthropicMessages = append(anthropicMessages,
				anthropic.NewAssistantMessage(anthropic.NewTextBlock(m.Content)))
		}
	}

	model := anthropicModel(c.cfg.Model)

	// No thinking parameter: each model runs its own default, adaptive
	// thinking on the Claude 5 generation (see anthropicAnswer), so a model
	// set in llm.model gets the same request as the default. Turning thinking
	// off would take {"type": "between_tools"}, which claude-sonnet-5-5 alone
	// accepts: any other model, or the same model under a gateway's name for
	// it, would answer 400.
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: anthropicMaxTokens(model),
		Messages:  anthropicMessages,
	}

	if len(systemBlocks) > 0 {
		params.System = systemBlocks
	}

	sent := params
	withTemperature := setAnthropicTemperature(&sent, c.temperature.next())
	message, err := c.client.Messages.New(ctx, sent)
	if err != nil && withTemperature && c.temperature.refused(err) {
		message, err = c.client.Messages.New(ctx, params)
	}
	if err != nil {
		return "", Usage{}, fmt.Errorf("anthropic chat error: %w", err)
	}

	usage := usageFromAnthropic(message.Usage)
	answer, err := anthropicAnswer(message, model)
	if err != nil {
		var refusal *RefusalError
		if errors.As(err, &refusal) {
			_, _ = fmt.Fprintf(c.log, "   ⚠️ %v; the request counts as failed\n", refusal)
		}
		return "", usage, err
	}
	return answer, usage, nil
}

func usageFromOpenAI(u openai.CompletionUsage) Usage {
	usage := Usage{}
	if u.TotalTokens > 0 {
		usage.PromptTokens = int(u.PromptTokens)
		usage.CompletionTokens = int(u.CompletionTokens)
		usage.TotalTokens = int(u.TotalTokens)
	}
	if u.PromptTokensDetails.CachedTokens > 0 || u.JSON.PromptTokensDetails.Valid() {
		usage.CachedPromptTokens = int(u.PromptTokensDetails.CachedTokens)
		usage.CacheTelemetryReported = true
	}
	return usage
}

func usageFromAnthropic(u anthropic.Usage) Usage {
	usage := Usage{
		PromptTokens:     int(u.InputTokens),
		CompletionTokens: int(u.OutputTokens),
		TotalTokens:      int(u.InputTokens + u.OutputTokens),
	}
	if u.CacheCreationInputTokens > 0 || u.CacheReadInputTokens > 0 ||
		u.JSON.CacheCreationInputTokens.Valid() || u.JSON.CacheReadInputTokens.Valid() {
		usage.CacheCreationInputTokens = int(u.CacheCreationInputTokens)
		usage.CacheReadInputTokens = int(u.CacheReadInputTokens)
		usage.CacheTelemetryReported = true
	}
	return usage
}

// defaultedTimeout guards against a zero request timeout: a hung provider
// request would otherwise block until the surrounding job dies, and the retry
// wrapper never gets a chance to act. The default is generous; override via
// AITRIAGE_LLM_TIMEOUT or the yaml `timeout` for slow local providers.
func defaultedTimeout(seconds int) int {
	if seconds <= 0 {
		return 600
	}
	return seconds
}

// NewClient creates an LLM client for the configured provider.
// All clients are automatically wrapped with RetryClient (3 retries,
// exponential backoff) to handle transient 429/5xx/network errors.
func NewClient(cfg Config) (Client, error) {
	inner, err := newProviderClient(cfg, os.Stderr)
	if err != nil {
		return nil, err
	}
	// Wrap with retry logic: 3 retries with exponential backoff.
	return NewRetryClient(inner, 3), nil
}

// newProviderClient builds the provider client NewClient wraps. Notices about
// the temperature go to log.
func newProviderClient(cfg Config, log io.Writer) (Client, error) {
	var inner Client
	var err error

	cfg.Timeout = defaultedTimeout(cfg.Timeout)

	switch cfg.Provider {
	case "anthropic":
		if cfg.APIKey == "" {
			return nil, errors.New(noLLMConfiguredMsg)
		}
		opts := []option.RequestOption{option.WithAPIKey(cfg.APIKey)}
		if cfg.Timeout > 0 {
			opts = append(opts, option.WithRequestTimeout(time.Duration(cfg.Timeout)*time.Second))
		}
		inner = newAnthropicClient(cfg, log, opts...)

	case "gemini":
		// Gemini uses the OpenAI-compatible API.
		// API key is resolved by config.LoadConfig() from env vars (GEMINI_API_KEY / GOOGLE_API_KEY).
		if cfg.APIKey == "" {
			return nil, errors.New(noLLMConfiguredMsg)
		}
		baseURL := geminiBaseURL
		if cfg.BaseURL != "" {
			baseURL = cfg.BaseURL
		}
		model := cfg.Model
		if model == "" {
			model = DefaultGeminiModel
		}
		opts := []openai_option.RequestOption{
			openai_option.WithAPIKey(cfg.APIKey),
			openai_option.WithBaseURL(baseURL),
		}
		if cfg.Timeout > 0 {
			opts = append(opts, openai_option.WithRequestTimeout(time.Duration(cfg.Timeout)*time.Second))
		}
		inner = &openAIClient{
			client:       openai.NewClient(opts...),
			cfg:          Config{Provider: "gemini", Model: model, APIKey: cfg.APIKey, BaseURL: baseURL, Timeout: cfg.Timeout},
			temperature:  newTemperatureControl(cfg, model, log),
			defaultModel: cfg.Model == "",
		}

	case "openai", "ollama", "groq":
		if cfg.APIKey == "" && cfg.Provider == "openai" {
			return nil, errors.New(noLLMConfiguredMsg)
		}
		if cfg.Provider != "openai" && strings.TrimSpace(cfg.Model) == "" {
			// Groq and Ollama serve models of their own. The OpenAI default
			// would reach them as a model they do not have, so the run would
			// stop at its first request instead of here.
			return nil, fmt.Errorf("the %s provider needs a model: set --model, AITRIAGE_LLM_MODEL or llm.model in .aitriage.yaml", cfg.Provider)
		}
		opts := []openai_option.RequestOption{}
		if cfg.APIKey != "" {
			opts = append(opts, openai_option.WithAPIKey(cfg.APIKey))
		}
		if cfg.BaseURL != "" {
			opts = append(opts, openai_option.WithBaseURL(cfg.BaseURL))
		}
		if cfg.Timeout > 0 {
			opts = append(opts, openai_option.WithRequestTimeout(time.Duration(cfg.Timeout)*time.Second))
		}
		inner = &openAIClient{
			client:       openai.NewClient(opts...),
			cfg:          cfg,
			temperature:  newTemperatureControl(cfg, openAIModel(cfg.Model), log),
			defaultModel: cfg.Model == "",
		}

	case "":
		return nil, errors.New(noLLMConfiguredMsg)

	default:
		return nil, fmt.Errorf("unknown LLM provider: %q\nSupported: gemini, anthropic, openai, ollama, groq", cfg.Provider)
	}

	if err != nil {
		return nil, err
	}
	return inner, nil
}
