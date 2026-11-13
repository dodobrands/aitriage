package llm

import "context"

// Message represents a single chat message.
type Message struct {
	Role    string `json:"role"` // "system" | "user" | "assistant"
	Content string `json:"content"`
}

type Usage struct {
	PromptTokens             int  `json:"prompt_tokens"`
	CompletionTokens         int  `json:"completion_tokens"`
	TotalTokens              int  `json:"total_tokens"`
	CachedPromptTokens       int  `json:"cached_prompt_tokens,omitempty"`
	CacheCreationInputTokens int  `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int  `json:"cache_read_input_tokens,omitempty"`
	CacheTelemetryReported   bool `json:"cache_telemetry_reported,omitempty"`
}

// Client is the interface for any LLM provider.
type Client interface {
	// Chat sends a list of messages and returns the model's response and usage stats.
	// An error that matches ErrNoAnswer means the provider answered without an
	// answer to use, such as a request the model declined (see RefusalError).
	Chat(ctx context.Context, messages []Message) (string, Usage, error)
}

// Config holds the LLM provider configuration from .aitriage.yaml or env.
type Config struct {
	Provider        string `yaml:"provider"` // "gemini" | "anthropic" | "openai" | "ollama" | "groq"
	Model           string `yaml:"model"`
	APIKey          string `yaml:"api_key"`
	BaseURL         string `yaml:"base_url"`         // for ollama and openai-compatible endpoints
	Timeout         int    `yaml:"timeout"`          // seconds, default 600 (see NewClient)
	DisableThinking bool   `yaml:"disable_thinking"` // Send thinking:{type:disabled} for reasoning models
	// Temperature is the sampling temperature: empty for DefaultTemperature,
	// a number from 0 to 2, or "default" to send none. Models that cannot take
	// one get none (see temperature.go).
	Temperature string `yaml:"temperature,omitempty"`
}
