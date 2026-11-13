package llm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
)

const (
	// anthropicReplyTokens is the max_tokens a request has always carried.
	anthropicReplyTokens = 8192
	// anthropicThinkingTokens is the max_tokens of a request to a model that
	// thinks before it answers. Thinking counts toward max_tokens even when
	// its text is not returned, and thinking and reply share the limit: the
	// model decides how long it thinks, so long thinking leaves the reply
	// less than 8192 tokens, or none. Twice the old limit still suits a
	// request that is not streamed; a reply that runs into it is no answer
	// (ErrTruncated), never a cut-off one.
	anthropicThinkingTokens = 16000
)

// anthropicMaxTokens returns the max_tokens of a request to model.
func anthropicMaxTokens(model string) int64 {
	if anthropicThinksByDefault(model) {
		return anthropicThinkingTokens
	}
	return anthropicReplyTokens
}

// anthropicThinksByDefault reports whether a Claude model thinks before it
// answers when a request leaves thinking unset, as AITriage's requests do:
// the Claude 5 generation and later (claude-sonnet-5, claude-sonnet-5-5,
// claude-opus-5-5, claude-haiku-5-5) and the Fable and Mythos models. Claude
// 4.x and older answer without thinking unless a request enables it. A name
// this does not know keeps the max_tokens requests always had.
func anthropicThinksByDefault(model string) bool {
	m := baseModelName(model)
	for _, family := range []string{"claude-fable", "claude-mythos"} {
		if m == family || strings.HasPrefix(m, family+"-") {
			return true
		}
	}
	for _, family := range []string{"claude-opus-", "claude-sonnet-", "claude-haiku-"} {
		rest, ok := strings.CutPrefix(m, family)
		if !ok {
			continue
		}
		major := leadingDigits(rest)
		n, err := strconv.Atoi(major)
		// More than two digits is a snapshot date, not a generation.
		return err == nil && len(major) <= 2 && n >= 5
	}
	return false
}

// stopReasonContextWindowExceeded is the stop_reason of a reply that ran into
// the model's context window, which cuts the answer off like max_tokens.
const stopReasonContextWindowExceeded anthropic.StopReason = "model_context_window_exceeded"

// anthropicAnswer returns the answer a reply carries: the text of its text
// blocks, in order. A model that thinks by default puts thinking blocks
// before the text; they are not the answer (their text is even empty unless
// a request asks for summaries), so they are skipped, as is any other kind
// of block. A reply without a complete answer is an error that matches
// ErrNoAnswer: a declined request is a *RefusalError whatever content came
// with it, partial text included; a reply cut off at the token limit matches
// ErrTruncated, since its text is an unfinished answer; and a reply with no
// blocks, or whose text is empty or only whitespace, carries nothing to use.
// An empty answer must never reach a caller: a conversation would send it
// back as an empty assistant turn, which the API rejects.
func anthropicAnswer(message *anthropic.Message, model string) (string, error) {
	switch message.StopReason {
	case anthropic.StopReasonRefusal:
		return "", fmt.Errorf("anthropic chat error: %w", &RefusalError{Model: model, Category: string(message.StopDetails.Category)})
	case anthropic.StopReasonMaxTokens, stopReasonContextWindowExceeded:
		return "", fmt.Errorf("anthropic chat error: %s stopped before it finished its answer (stop_reason %s, max_tokens %d): %w",
			model, message.StopReason, anthropicMaxTokens(model), ErrTruncated)
	}
	var text strings.Builder
	for _, block := range message.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		stop := string(message.StopReason)
		if stop == "" {
			stop = "none"
		}
		return "", fmt.Errorf("anthropic chat error: %s wrote no text (stop_reason %s): %w", model, stop, ErrNoAnswer)
	}
	return text.String(), nil
}
