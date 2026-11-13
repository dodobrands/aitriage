package llm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/openai/openai-go"
	openai_option "github.com/openai/openai-go/option"
)

const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta/openai/"

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
	client      openai.Client
	cfg         Config
	temperature *temperatureControl
}

// openAIModel returns the model an OpenAI-compatible request names.
func openAIModel(configured string) string {
	if configured == "" {
		return string(openai.ChatModelGPT4o)
	}
	return configured
}

// EffectiveTemperature implements TemperatureReporter.
func (c *openAIClient) EffectiveTemperature() string { return c.temperature.effective() }

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
}

// newAnthropicClient builds the Anthropic client from cfg; opts carry the
// credentials and transport settings.
func newAnthropicClient(cfg Config, log io.Writer, opts ...option.RequestOption) *anthropicClientWrapper {
	return &anthropicClientWrapper{
		client:      anthropic.NewClient(opts...),
		cfg:         cfg,
		temperature: newTemperatureControl(cfg, anthropicModel(cfg.Model), log),
	}
}

// anthropicModel returns the model an Anthropic request names.
func anthropicModel(configured string) string {
	if configured == "" {
		return anthropic.ModelClaudeSonnet4_5
	}
	return configured
}

// EffectiveTemperature implements TemperatureReporter.
func (c *anthropicClientWrapper) EffectiveTemperature() string { return c.temperature.effective() }

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

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 8192,
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

	if len(message.Content) == 0 {
		return "", Usage{}, fmt.Errorf("empty response from anthropic")
	}

	usage := usageFromAnthropic(message.Usage)

	return message.Content[0].Text, usage, nil
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
			model = "gemini-2.5-flash"
		}
		opts := []openai_option.RequestOption{
			openai_option.WithAPIKey(cfg.APIKey),
			openai_option.WithBaseURL(baseURL),
		}
		if cfg.Timeout > 0 {
			opts = append(opts, openai_option.WithRequestTimeout(time.Duration(cfg.Timeout)*time.Second))
		}
		inner = &openAIClient{
			client:      openai.NewClient(opts...),
			cfg:         Config{Provider: "gemini", Model: model, APIKey: cfg.APIKey, BaseURL: baseURL, Timeout: cfg.Timeout},
			temperature: newTemperatureControl(cfg, model, log),
		}

	case "openai", "ollama", "groq":
		if cfg.APIKey == "" && cfg.Provider == "openai" {
			return nil, errors.New(noLLMConfiguredMsg)
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
			client:      openai.NewClient(opts...),
			cfg:         cfg,
			temperature: newTemperatureControl(cfg, openAIModel(cfg.Model), log),
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
