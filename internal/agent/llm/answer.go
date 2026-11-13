package llm

import (
	"errors"
	"fmt"
)

// ErrNoAnswer matches a reply that came back without an answer to use: the
// model declined the request, it wrote no text (or only whitespace) before it
// stopped, or it ran out of tokens before it finished. The provider did
// answer, so this is no transport failure, and the same request sent again
// would most likely end the same way. Callers handle it like a reply they
// cannot parse, never as an empty answer.
var ErrNoAnswer = errors.New("the reply carries no answer")

// ErrRefused matches a request the model declined (see RefusalError).
var ErrRefused = errors.New("the model declined the request")

// ErrTruncated matches a reply cut off at the token limit (stop_reason
// max_tokens): whatever text it carries is an unfinished answer. It also
// matches ErrNoAnswer, so a caller splits the request or falls back instead
// of using the part it got.
var ErrTruncated error = truncatedError{}

type truncatedError struct{}

func (truncatedError) Error() string { return "the reply is cut off" }

// Is lets errors.Is match ErrNoAnswer.
func (truncatedError) Is(target error) bool { return target == ErrNoAnswer }

// RefusalError reports a request the model declined: the provider answered
// with stop_reason "refusal" and HTTP 200, and whatever content came with it
// is not an answer. It matches ErrRefused and ErrNoAnswer.
type RefusalError struct {
	// Model is the model that declined.
	Model string
	// Category is the policy category the provider named
	// (stop_details.category), such as "cyber", or "" when it named none.
	Category string
}

func (e *RefusalError) Error() string {
	category := e.Category
	if category == "" {
		category = "none"
	}
	return fmt.Sprintf("%s declined the request (stop_reason refusal, category %s)", e.Model, category)
}

// Is lets errors.Is match ErrRefused and ErrNoAnswer.
func (e *RefusalError) Is(target error) bool {
	return target == ErrRefused || target == ErrNoAnswer
}
