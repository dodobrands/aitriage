package llm

import (
	"errors"
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
	// its text is not returned, so the reply keeps its 8192 and thinking gets
	// about as much again, which still suits a request that is not streamed.
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

// anthropicAnswer returns the answer a reply carries: the text of its text
// blocks, in order. A model that thinks by default puts thinking blocks
// before the text; they are not the answer (their text is even empty unless
// a request asks for summaries), so they are skipped, as is any other kind
// of block. A declined request is a *RefusalError whatever content came with
// it, partial text included, and a reply with blocks but no text, such as
// thinking that ran into max_tokens, matches ErrNoAnswer.
func anthropicAnswer(message *anthropic.Message, model string) (string, error) {
	if message.StopReason == anthropic.StopReasonRefusal {
		return "", fmt.Errorf("anthropic chat error: %w", &RefusalError{Model: model, Category: string(message.StopDetails.Category)})
	}
	if len(message.Content) == 0 {
		return "", errors.New("empty response from anthropic")
	}
	var text strings.Builder
	found := false
	for _, block := range message.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
			found = true
		}
	}
	if !found {
		stop := string(message.StopReason)
		if stop == "" {
			stop = "none"
		}
		return "", fmt.Errorf("anthropic chat error: %s wrote no text (stop_reason %s): %w", model, stop, ErrNoAnswer)
	}
	return text.String(), nil
}
