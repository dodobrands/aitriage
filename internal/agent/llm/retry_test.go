package llm

import (
	"context"
	"fmt"
	"testing"
)

type mockClient struct {
	responses []mockResponse
	callCount int
}

type mockResponse struct {
	content string
	usage   Usage
	err     error
}

func (m *mockClient) Chat(ctx context.Context, messages []Message) (string, Usage, error) {
	if m.callCount >= len(m.responses) {
		return "", Usage{}, fmt.Errorf("unexpected call %d", m.callCount)
	}
	resp := m.responses[m.callCount]
	m.callCount++
	return resp.content, resp.usage, resp.err
}

func TestRetryClientSucceedsOnFirstAttempt(t *testing.T) {
	mock := &mockClient{
		responses: []mockResponse{
			{content: "ok", usage: Usage{TotalTokens: 100}, err: nil},
		},
	}

	client := NewRetryClient(mock, 3)
	content, usage, err := client.Chat(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "ok" {
		t.Fatalf("content = %q; want ok", content)
	}
	if usage.TotalTokens != 100 {
		t.Fatalf("tokens = %d; want 100", usage.TotalTokens)
	}
	if mock.callCount != 1 {
		t.Fatalf("callCount = %d; want 1", mock.callCount)
	}
}

func TestRetryClientRetriesOnRateLimit(t *testing.T) {
	mock := &mockClient{
		responses: []mockResponse{
			{err: fmt.Errorf("status 429: rate limit exceeded")},
			{err: fmt.Errorf("status 429: rate limit exceeded")},
			{content: "recovered", usage: Usage{TotalTokens: 50}, err: nil},
		},
	}

	client := NewRetryClient(mock, 3)
	content, _, err := client.Chat(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "recovered" {
		t.Fatalf("content = %q; want recovered", content)
	}
	if mock.callCount != 3 {
		t.Fatalf("callCount = %d; want 3 (2 retries + 1 success)", mock.callCount)
	}
}

func TestRetryClientRetriesOn5xx(t *testing.T) {
	mock := &mockClient{
		responses: []mockResponse{
			{err: fmt.Errorf("server error: 502 bad gateway")},
			{content: "ok", err: nil},
		},
	}

	client := NewRetryClient(mock, 3)
	content, _, err := client.Chat(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "ok" {
		t.Fatalf("content = %q; want ok", content)
	}
}

func TestRetryClientDoesNotRetryOnNonTransient(t *testing.T) {
	mock := &mockClient{
		responses: []mockResponse{
			{err: fmt.Errorf("invalid api key")},
		},
	}

	client := NewRetryClient(mock, 3)
	_, _, err := client.Chat(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if mock.callCount != 1 {
		t.Fatalf("callCount = %d; want 1 (no retry on auth error)", mock.callCount)
	}
}

func TestRetryClientExhaustsRetries(t *testing.T) {
	mock := &mockClient{
		responses: []mockResponse{
			{err: fmt.Errorf("status 429")},
			{err: fmt.Errorf("status 429")},
			{err: fmt.Errorf("status 429")},
			{err: fmt.Errorf("status 429")},
		},
	}

	client := NewRetryClient(mock, 3)
	_, _, err := client.Chat(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if mock.callCount != 4 {
		t.Fatalf("callCount = %d; want 4 (1 initial + 3 retries)", mock.callCount)
	}
}

func TestRetryClientRespectsContextCancellation(t *testing.T) {
	mock := &mockClient{
		responses: []mockResponse{
			{err: fmt.Errorf("status 429")},
			{err: fmt.Errorf("status 429")},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client := NewRetryClient(mock, 3)
	_, _, err := client.Chat(ctx, nil)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"rate limit 429", fmt.Errorf("status 429"), true},
		{"quota exhausted", fmt.Errorf("RESOURCE_EXHAUSTED"), true},
		{"server 500", fmt.Errorf("internal server error 500"), true},
		{"server 502", fmt.Errorf("502 bad gateway"), true},
		{"server 503", fmt.Errorf("503 service unavailable"), true},
		{"anthropic overloaded", fmt.Errorf("overloaded"), true},
		{"timeout", fmt.Errorf("deadline exceeded"), true},
		{"auth error", fmt.Errorf("invalid api key"), false},
		{"parse error", fmt.Errorf("json parse error"), false},
		// The provider answered: resending the same request ends the same way,
		// whatever the message happens to contain.
		{"declined request", fmt.Errorf("anthropic chat error: %w", &RefusalError{Model: "model-503", Category: "cyber"}), false},
		{"no answer", fmt.Errorf("reply 500 tokens long: %w", ErrNoAnswer), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isRetryable(tc.err)
			if result != tc.expected {
				t.Errorf("isRetryable(%q) = %v; want %v", tc.err, result, tc.expected)
			}
		})
	}
}

func TestDefaultedTimeoutGuardsAgainstZero(t *testing.T) {
	if got := defaultedTimeout(0); got != 600 {
		t.Fatalf("defaultedTimeout(0) = %d, want 600", got)
	}
	if got := defaultedTimeout(-5); got != 600 {
		t.Fatalf("defaultedTimeout(-5) = %d, want 600", got)
	}
	if got := defaultedTimeout(120); got != 120 {
		t.Fatalf("defaultedTimeout(120) = %d, want 120", got)
	}
}
