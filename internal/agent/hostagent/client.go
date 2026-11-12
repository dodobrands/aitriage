// Package hostagent implements a deferred llm.Client that runs the unmodified
// graph.Run while delegating each real Chat() request to an active host coding
// agent (Codex / Claude Code) through the local MCP workflow.
//
// The design is a content-addressed replay state machine:
//
//   - graph.Run calls Chat() exactly as it would against a synchronous provider.
//   - For each request the client canonicalizes the messages and computes a
//     stable fingerprint (run identity + prompt versions + state fingerprint +
//     ordered messages). The fingerprint — NOT the call order — is the request
//     identity.
//   - If a validated response for that fingerprint already exists, it is
//     replayed as if the model had answered — graph.Run never notices.
//   - If no response exists, the exact request is persisted atomically under its
//     fingerprint and a typed ErrAwaitingHostResponse is returned, unwinding
//     graph.Run so the MCP layer can hand the request to the host agent.
//
// Because identity is derived from request CONTENT, the scheme is correct even
// though graph.Run classifies finding batches concurrently: two goroutines that
// race never depend on a shared counter, and re-running graph.Run on a later
// pass recomputes the identical fingerprints and replays the confirmed answers
// in a fully deterministic, order-independent way.
package hostagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/agent/prompts"
)

// PromptVersions is the composite prompt-identity of a run. Bumping any of the
// underlying SecureCoder constants changes the fingerprint namespace so a run
// recorded under old prompts is never silently replayed under new ones.
type PromptVersions struct {
	SecureCoder string `json:"securecoder"`
	PoC         string `json:"poc"`
	Report      string `json:"report"`
	FixSpec     string `json:"fixspec"`
}

// CurrentPromptVersions returns the prompt identity compiled into this binary.
func CurrentPromptVersions() PromptVersions {
	return PromptVersions{
		SecureCoder: prompts.SecureCoderPromptVersion,
		PoC:         prompts.PoCPromptVersion,
		Report:      prompts.ReportPromptVersion,
		FixSpec:     prompts.FixSpecPromptVersion,
	}
}

// Request is the exact, replayable record of one graph.Run Chat() call. Its
// identity is RequestID (a content fingerprint); Ordinal is a display-only
// discovery index the store assigns and is never part of identity or replay.
type Request struct {
	RunID            string         `json:"run_id"`
	RequestID        string         `json:"request_id"`
	Ordinal          int            `json:"ordinal"`
	PromptVersions   PromptVersions `json:"prompt_versions"`
	StateFingerprint string         `json:"state_fingerprint"`
	Messages         []llm.Message  `json:"messages"`
	// NextStep is a safe, human-readable description of what the host agent must
	// do. It never contains credentials.
	NextStep string `json:"next_step"`
}

// Response is a host-agent answer submitted for a specific request fingerprint.
type Response struct {
	RunID     string `json:"run_id"`
	RequestID string `json:"request_id"`
	Content   string `json:"content"`
	// Usage is provider-reported usage. UsageReported must be true only when the
	// host actually reported token counts; the client never fabricates tokens.
	Usage         llm.Usage `json:"usage"`
	UsageReported bool      `json:"usage_reported"`
}

// Store persists requests and responses for a single run, keyed by request
// fingerprint. Implementations must be safe for the resume/replay contract and
// for concurrent SaveRequest calls from parallel graph.Run goroutines; see
// internal/agent/runstore for the filesystem-backed, security-hardened impl.
type Store interface {
	// SaveRequest atomically persists req under its RequestID. It is idempotent:
	// saving the same fingerprint again is a no-op.
	SaveRequest(req Request) error
	// Response returns the stored response for a request fingerprint. ok is false
	// when no response has been submitted yet.
	Response(requestID string) (Response, bool, error)
}

// ErrAwaitingHostResponse is returned by Chat when graph.Run needs a model
// answer that the host agent has not provided yet. It carries everything the
// MCP layer needs to prompt the host agent, and nothing sensitive.
type ErrAwaitingHostResponse struct {
	RunID     string
	RequestID string
	NextStep  string
}

func (e *ErrAwaitingHostResponse) Error() string {
	return fmt.Sprintf("aitriage: awaiting host-agent response for run %s (request %s)", e.RunID, e.RequestID)
}

// SuspendsRun marks the error as a pause, not a provider failure (it
// implements graph.RunSuspender). graph.Run absorbs provider failures into
// deterministic fallbacks; a pending host answer must instead unwind the run
// so it can be resumed once the host has replied.
func (e *ErrAwaitingHostResponse) SuspendsRun() bool { return true }

// IsAwaiting reports whether err is (or wraps) ErrAwaitingHostResponse.
func IsAwaiting(err error) (*ErrAwaitingHostResponse, bool) {
	for err != nil {
		if e, ok := err.(*ErrAwaitingHostResponse); ok {
			return e, true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return nil, false
		}
		err = u.Unwrap()
	}
	return nil, false
}

// Client is a deferred llm.Client. Construct it with New and pass it to
// pipeline.RunState / graph.Run. A Client instance is single-run. It holds no
// mutable state, so concurrent Chat() calls are safe.
type Client struct {
	runID            string
	stateFingerprint string
	promptVersions   PromptVersions
	store            Store
}

// New builds a deferred client bound to one run.
func New(runID, stateFingerprint string, store Store) *Client {
	return &Client{
		runID:            runID,
		stateFingerprint: stateFingerprint,
		promptVersions:   CurrentPromptVersions(),
		store:            store,
	}
}

// Chat implements llm.Client. It never contacts a provider; it replays a stored
// response or defers to the host agent.
func (c *Client) Chat(ctx context.Context, messages []llm.Message) (string, llm.Usage, error) {
	if err := ctx.Err(); err != nil {
		return "", llm.Usage{}, err
	}

	requestID := c.fingerprint(messages)

	// Replay path: a validated response already exists for this fingerprint.
	if resp, ok, err := c.store.Response(requestID); err != nil {
		return "", llm.Usage{}, fmt.Errorf("hostagent: load response %s: %w", short(requestID), err)
	} else if ok {
		if resp.UsageReported {
			return resp.Content, resp.Usage, nil
		}
		// Host did not report usage: return zero usage. graph.Run records this as
		// "provider_did_not_report"; tokens are never invented.
		return resp.Content, llm.Usage{}, nil
	}

	// Defer path: persist the exact request and unwind graph.Run.
	req := Request{
		RunID:            c.runID,
		RequestID:        requestID,
		PromptVersions:   c.promptVersions,
		StateFingerprint: c.stateFingerprint,
		Messages:         messages,
		NextStep:         "Compute the model answer for this exact request with your active session and submit it via aitriage_run_submit using the same request_id. Do not substitute your own analysis for the prompt.",
	}
	if err := c.store.SaveRequest(req); err != nil {
		return "", llm.Usage{}, fmt.Errorf("hostagent: save request %s: %w", short(requestID), err)
	}
	return "", llm.Usage{}, &ErrAwaitingHostResponse{
		RunID:     c.runID,
		RequestID: requestID,
		NextStep:  req.NextStep,
	}
}

// fingerprintPayload is the canonical, deterministically-serialised request
// identity. Field order is fixed by the struct, llm.Message order is preserved,
// and no map is involved, so the digest is stable and independently
// reproducible from the persisted request across processes. Crucially it does
// NOT include any call ordinal, so identity is independent of goroutine order.
type fingerprintPayload struct {
	RunID            string         `json:"run_id"`
	PromptVersions   PromptVersions `json:"prompt_versions"`
	StateFingerprint string         `json:"state_fingerprint"`
	Messages         []llm.Message  `json:"messages"`
}

func (c *Client) fingerprint(messages []llm.Message) string {
	return Fingerprint(c.runID, c.stateFingerprint, c.promptVersions, messages)
}

// Fingerprint computes the content-addressed request identity. It is exported so
// tests and the run store can reproduce it from a persisted request.
func Fingerprint(runID, stateFingerprint string, versions PromptVersions, messages []llm.Message) string {
	sum := sha256.Sum256(CanonicalRequestBytes(runID, stateFingerprint, versions, messages))
	return hex.EncodeToString(sum[:])
}

// CanonicalRequestBytes returns the exact serialized bytes used to compute a
// request fingerprint. Tests use it to prove the host-agent request matches the
// request the synchronous graph.Run would issue.
func CanonicalRequestBytes(runID, stateFingerprint string, versions PromptVersions, messages []llm.Message) []byte {
	payload := fingerprintPayload{
		RunID:            runID,
		PromptVersions:   versions,
		StateFingerprint: stateFingerprint,
		Messages:         messages,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		// llm.Message is plain strings; marshaling cannot realistically fail.
		panic(fmt.Sprintf("hostagent: canonicalize request: %v", err))
	}
	return raw
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

var _ llm.Client = (*Client)(nil)
