package llm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/openai/openai-go"
)

// DefaultTemperature is the sampling temperature AITriage asks for when none
// is configured. Triage is classification: the same finding should get the
// same verdict on every run, and a retried request should not draw a new one.
// Provider defaults, often 1, sample a different answer on every request.
const DefaultTemperature = 0.0

// maxTemperature is the highest temperature AITriage accepts. OpenAI-compatible
// APIs take 0 to 2; Anthropic takes 0 to 1 and gets none above that.
const maxTemperature = 2.0

// ProviderDefaultTemperature describes requests that carry no temperature, so
// the provider's own default applies. As a setting it means the same as
// "default", so a value copied from a run record works.
const ProviderDefaultTemperature = "provider default"

// TemperatureReporter is implemented by clients that know the temperature
// their requests carry.
type TemperatureReporter interface {
	// EffectiveTemperature returns the temperature requests carry, such as
	// "0", or ProviderDefaultTemperature when they carry none.
	EffectiveTemperature() string
}

// EffectiveTemperature reports the temperature client's requests carry. A
// client that sets none, such as a host agent answering with its own model,
// leaves the provider default.
func EffectiveTemperature(client Client) string {
	if r, ok := client.(TemperatureReporter); ok {
		return r.EffectiveTemperature()
	}
	return ProviderDefaultTemperature
}

// TemperatureFlagUsage is the help text of a --temperature flag.
const TemperatureFlagUsage = `LLM sampling temperature, 0 to 2, or "default" to send none and keep the provider's own (default 0; left out for models that take none)`

// TemperatureFlag is the value of a --temperature command-line flag (a
// pflag.Value). Set accepts what Config.Temperature accepts, so a typo stops
// the command before it starts any work.
type TemperatureFlag string

// String returns the flag value.
func (f *TemperatureFlag) String() string { return string(*f) }

// Set validates and stores a flag value.
func (f *TemperatureFlag) Set(value string) error {
	if _, err := parseTemperature(value); err != nil {
		return err
	}
	*f = TemperatureFlag(strings.TrimSpace(value))
	return nil
}

// Type names the value in command help.
func (f *TemperatureFlag) Type() string { return "string" }

// Or returns the flag value when the flag was given and configured otherwise:
// the command line wins over the environment and .aitriage.yaml.
func (f TemperatureFlag) Or(configured string) string {
	if f != "" {
		return string(f)
	}
	return configured
}

// temperatureSetting is a parsed Config.Temperature.
type temperatureSetting struct {
	value    float64
	explicit bool // configured, not the AITriage default
	omit     bool // "default": requests carry no temperature at all
}

// parseTemperature reads Config.Temperature: empty for DefaultTemperature, a
// number from 0 to 2, or "default" to send none.
func parseTemperature(raw string) (temperatureSetting, error) {
	value := strings.TrimSpace(raw)
	switch strings.ToLower(value) {
	case "":
		return temperatureSetting{value: DefaultTemperature}, nil
	case "default", ProviderDefaultTemperature:
		return temperatureSetting{explicit: true, omit: true}, nil
	}
	t, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(t) || t < 0 || t > maxTemperature {
		return temperatureSetting{}, fmt.Errorf("invalid LLM temperature %q: use a number from 0 to %s, or \"default\" to send none", raw, formatTemperature(maxTemperature))
	}
	// "-0" parses as negative zero, which would be sent and recorded as -0.
	return temperatureSetting{value: math.Abs(t), explicit: true}, nil
}

// formatTemperature writes a temperature the way it is configured: 0, 0.2, 1.
func formatTemperature(t float64) string {
	return strconv.FormatFloat(t, 'f', -1, 64)
}

// temperatureControl decides the temperature each request of one client
// carries. Concurrent requests share it: classification sends batches in
// parallel.
type temperatureControl struct {
	value float64
	send  bool   // false: requests carry no temperature
	model string // named in the notice when the endpoint refuses it
	log   io.Writer

	refusedByEndpoint atomic.Bool
	notice            sync.Once
}

// newTemperatureControl applies the provider rules to the configured
// temperature, once per client. A model that cannot take a temperature gets
// none; when the user configured one, one line says it is not sent. An
// invalid configured value is reported and replaced by the AITriage default:
// a sampling setting never stops a run.
func newTemperatureControl(cfg Config, model string, log io.Writer) *temperatureControl {
	if log == nil {
		log = io.Discard
	}
	setting, err := parseTemperature(cfg.Temperature)
	if err != nil {
		_, _ = fmt.Fprintf(log, "   ⚠️ %v; the AITriage default applies\n", err)
		setting = temperatureSetting{value: DefaultTemperature}
	}
	t := &temperatureControl{value: setting.value, send: !setting.omit, model: model, log: log}
	if !t.send {
		return t
	}
	if reason := temperatureUnsupported(cfg.Provider, model, setting.value); reason != "" {
		t.send = false
		if setting.explicit {
			_, _ = fmt.Fprintf(log, "   ⚠️ LLM temperature %s is not sent: %s; the provider default applies\n", formatTemperature(setting.value), reason)
		}
	}
	return t
}

// next returns the temperature for the next request, or nil for none.
func (t *temperatureControl) next() *float64 {
	if t == nil || !t.send || t.refusedByEndpoint.Load() {
		return nil
	}
	value := t.value
	return &value
}

// refused reports whether err is the endpoint refusing the temperature. The
// first refusal turns it off for the rest of the run and prints one line; the
// caller repeats its request once without it.
func (t *temperatureControl) refused(err error) bool {
	if t == nil || !temperatureRejected(err) {
		return false
	}
	t.refusedByEndpoint.Store(true)
	t.notice.Do(func() {
		_, _ = fmt.Fprintf(t.log, "   ⚠️ The LLM endpoint does not accept temperature %s for %s; requests carry none (provider default) for the rest of the run\n", formatTemperature(t.value), t.model)
	})
	return true
}

// effective returns the temperature requests carry now.
func (t *temperatureControl) effective() string {
	if t.next() == nil {
		return ProviderDefaultTemperature
	}
	return formatTemperature(t.value)
}

// temperatureUnsupported returns why model, served by provider, cannot take a
// temperature of value, or "" when it can or the model is unknown. An unknown
// model gets the temperature; if its endpoint refuses it, the client stops
// sending it (see refused).
func temperatureUnsupported(provider, model string, value float64) string {
	// Claude models follow Anthropic's rules also behind an OpenAI-compatible
	// gateway ("anthropic/claude-sonnet-4.5").
	if provider == "anthropic" || strings.HasPrefix(baseModelName(model), "claude-") {
		if !anthropicTakesTemperature(model) {
			return model + " takes only its default temperature"
		}
		if value > 1 {
			return "Claude models take a temperature from 0 to 1"
		}
		return ""
	}
	if openAIReasoningModel(model) {
		return model + " is a reasoning model and takes only its default temperature"
	}
	return ""
}

// baseModelName lowercases a model name and drops a gateway prefix such as
// "openai/", so the rules hold however the model is reached.
func baseModelName(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if i := strings.LastIndexByte(m, '/'); i >= 0 {
		m = m[i+1:]
	}
	return m
}

// anthropicTakesTemperature reports whether a Claude model accepts a
// temperature. Models released after Claude Opus 4.6 reject any value but the
// default with a 400, so only the older generations get one, and a name this
// does not know is taken for a newer model. The older ones accept it under the
// API version the pinned SDK sends; should a later version refuse it on every
// model, the refusal fallback (see refused) drops it after one request.
func anthropicTakesTemperature(model string) bool {
	m := baseModelName(model)
	if strings.HasPrefix(m, "claude-3") { // claude-3-haiku, claude-3-5-sonnet, claude-3-7-sonnet
		return true
	}
	for _, family := range []string{"claude-opus-4", "claude-sonnet-4", "claude-haiku-4"} {
		rest, ok := strings.CutPrefix(m, family)
		if !ok {
			continue
		}
		if rest == "" || rest[0] == '@' {
			return true // claude-opus-4, claude-sonnet-4: the 4.0 models
		}
		if rest[0] != '-' && rest[0] != '.' {
			return false
		}
		minor := leadingDigits(rest[1:])
		if len(minor) == 8 {
			return true // a snapshot date: claude-sonnet-4-20250514 is Sonnet 4
		}
		n, err := strconv.Atoi(minor)
		return err == nil && n <= 6
	}
	return false
}

func leadingDigits(s string) string {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	return s[:end]
}

// openAIReasoningModel reports whether model is an OpenAI reasoning model,
// which rejects any temperature but the default: the o-series (o1, o3,
// o4-mini) and the GPT-5 family (gpt-5, gpt-5-mini, gpt-5.1), whichever
// OpenAI-compatible endpoint serves it.
func openAIReasoningModel(model string) bool {
	m := baseModelName(model)
	var rest string
	switch {
	case strings.HasPrefix(m, "gpt-5"):
		rest = m[len("gpt-5"):]
	case len(m) > 1 && m[0] == 'o' && leadingDigits(m[1:]) != "":
		rest = m[1+len(leadingDigits(m[1:])):]
	default:
		return false
	}
	return rest == "" || strings.ContainsRune("-.:_@", rune(rest[0]))
}

// setAnthropicTemperature puts temperature on a request, unless there is none
// to send or the request enables thinking, which takes only the default
// temperature. It reports whether the request now carries one.
func setAnthropicTemperature(params *anthropic.MessageNewParams, temperature *float64) bool {
	if temperature == nil || params.Thinking.OfEnabled != nil || params.Thinking.OfAdaptive != nil {
		return false
	}
	params.Temperature = anthropic.Float(*temperature)
	return true
}

// temperatureRejected reports whether err is an endpoint refusing the
// temperature parameter: a 400, or the 422 some OpenAI-compatible servers use
// for request validation, whose error names temperature.
func temperatureRejected(err error) bool {
	var openAIErr *openai.Error
	if errors.As(err, &openAIErr) {
		return refusalStatus(openAIErr.StatusCode) &&
			(namesTemperature(openAIErr.Param, openAIErr.Message, openAIErr.RawJSON()) || namesTemperature(responseBody(openAIErr.Response)))
	}
	var anthropicErr *anthropic.Error
	if errors.As(err, &anthropicErr) {
		return refusalStatus(anthropicErr.StatusCode) && namesTemperature(anthropicErr.RawJSON())
	}
	return false
}

func refusalStatus(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusUnprocessableEntity
}

func namesTemperature(details ...string) bool {
	for _, detail := range details {
		if strings.Contains(strings.ToLower(detail), "temperature") {
			return true
		}
	}
	return false
}

// responseBody reads the body of an error response, which the SDK keeps for
// debugging, and puts it back. A server that does not wrap its error in
// {"error": {...}} leaves the OpenAI SDK error's own fields empty, so the body
// is the only place the refused parameter is named.
func responseBody(res *http.Response) string {
	if res == nil || res.Body == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return ""
	}
	_ = res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(data))
	return string(data)
}
