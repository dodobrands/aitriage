package llm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

// RetryClient wraps any Client with exponential backoff retry logic.
// It retries on transient errors (429 rate limits, 5xx server errors,
// network timeouts, and context deadlines).
type RetryClient struct {
	inner      Client
	maxRetries int
}

// NewRetryClient wraps the given client with retry logic.
func NewRetryClient(inner Client, maxRetries int) Client {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	return &RetryClient{inner: inner, maxRetries: maxRetries}
}

func (r *RetryClient) Chat(ctx context.Context, messages []Message) (string, Usage, error) {
	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryDelay(attempt)
			fmt.Fprintf(os.Stderr, "   ⏳ LLM retry %d/%d after %s...\n", attempt, r.maxRetries, delay.Round(time.Millisecond))
			select {
			case <-ctx.Done():
				return "", Usage{}, ctx.Err()
			case <-time.After(delay):
			}
		}

		response, usage, err := r.inner.Chat(ctx, messages)
		if err == nil {
			return response, usage, nil
		}

		if !isRetryable(err) {
			return "", usage, err
		}
		lastErr = err
	}
	return "", Usage{}, fmt.Errorf("LLM call failed after %d retries: %w", r.maxRetries, lastErr)
}

// EffectiveTemperature reports the temperature of the wrapped client.
func (r *RetryClient) EffectiveTemperature() string { return EffectiveTemperature(r.inner) }

// RequestModel reports the provider and model of the wrapped client.
func (r *RetryClient) RequestModel() (provider, model string) { return RequestModel(r.inner) }

// retryDelay returns an exponential backoff duration with jitter.
// Base delay: 1s, factor: 2x. Max delay capped at 30s.
func retryDelay(attempt int) time.Duration {
	base := time.Second
	maxDelay := 30 * time.Second

	delay := time.Duration(float64(base) * math.Pow(2, float64(attempt-1)))
	if delay > maxDelay {
		delay = maxDelay
	}

	// Add ±25% jitter to prevent thundering herd
	jitter := time.Duration(rand.Int63n(int64(delay / 4)))
	if rand.Intn(2) == 0 {
		delay += jitter
	} else {
		delay -= jitter
	}

	return delay
}

// isRetryable checks whether an error is transient and worth retrying.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}

	// The provider answered, without an answer to use: the same request
	// would end the same way, so callers decide what to do with it.
	if errors.Is(err, ErrNoAnswer) {
		return false
	}

	msg := err.Error()

	// Rate limiting (429)
	if strings.Contains(msg, "429") || strings.Contains(msg, "rate limit") ||
		strings.Contains(msg, "quota") || strings.Contains(msg, "RESOURCE_EXHAUSTED") {
		return true
	}

	// Server errors (5xx)
	for _, code := range []string{"500", "502", "503", "504"} {
		if strings.Contains(msg, code) {
			return true
		}
	}

	// Overloaded (Anthropic-specific)
	if strings.Contains(msg, "overloaded") {
		return true
	}

	// Network errors
	var netErr net.Error
	if isNetError(err, &netErr) {
		return true
	}

	// Context deadline (not cancellation — cancellation is intentional)
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout") {
		return true
	}

	return false
}

// isNetError checks if any error in the chain is a net.Error.
func isNetError(err error, target *net.Error) bool {
	for err != nil {
		if ne, ok := err.(net.Error); ok {
			*target = ne
			return true
		}
		unwrapped := interface{ Unwrap() error }(nil)
		if u, ok := err.(interface{ Unwrap() error }); ok {
			unwrapped = u
		}
		if unwrapped == nil {
			return false
		}
		err = unwrapped.Unwrap()
	}
	return false
}
