package graph

import (
	"strings"
	"testing"
)

// The line-drift fixture: a request handler whose guard sits well above the
// flagged argument of a call written one argument per line, with look-alikes
// of the guard in a comment, in a string literal and in a check after the
// call.
const (
	driftGuardLine   = 13
	driftFlaggedLine = 35
	driftGuard       = "    if not is_allowed_url(preview_url):"
	driftGuardExit   = `        raise PermissionError("preview host is not allowed")`
)

func lineDriftFixture(t *testing.T) string {
	t.Helper()
	return writeProjectFiles(t, map[string]string{
		"preview.py": strings.Join([]string{
			"import logging",                    // 1
			"from urllib.parse import urlsplit", // 2
			"",                                  // 3
			"from previews import is_allowed_url, render_card", // 4
			"",                                  // 5
			"log = logging.getLogger(__name__)", // 6
			"MAX_WIDTH = 2048",                  // 7
			"",                                  // 8
			"",                                  // 9
			"def link_preview(request, http):",  // 10
			`    preview_url = request.json.get("url", "")`,   // 11
			`    width = int(request.json.get("width", 640))`, // 12
			driftGuard,                          // 13 the guard
			driftGuardExit,                      // 14
			"    width = min(width, MAX_WIDTH)", // 15
			"    host = urlsplit(preview_url).hostname",                                 // 16
			`    log.info("rendering a preview of %s", host)`,                           // 17
			`    cache_key = f"{host}:{width}"`,                                         // 18
			"    cached = http.cache.get(cache_key)",                                    // 19
			"    if cached is not None:",                                                // 20
			"        return cached",                                                     // 21
			`    headers = {"Accept": "text/html"}`,                                     // 22
			`    headers["X-Preview-Width"] = str(width)`,                               // 23
			"    timeout = http.settings.timeout_for(host)",                             // 24
			"    retries = http.settings.retries_for(host)",                             // 25
			"    started = http.clock()",                                                // 26
			`    log.debug("fetching with %d retries", retries)`,                        // 27
			"    # is_allowed_url(preview_url) ran on entry; redirects stay off",        // 28 a comment
			`    log.debug("is_allowed_url(preview_url) passed for %s", host)`,          // 29 a string literal
			`    http.metrics.count("preview.fetch")`,                                   // 30
			`    http.metrics.gauge("preview.width", width)`,                            // 31
			"    budget = timeout * retries",                                            // 32
			`    log.debug("budget %s", budget)`,                                        // 33
			"    response = http.get(",                                                  // 34
			"        preview_url,",                                                      // 35 flagged
			"        headers=headers,",                                                  // 36
			"        timeout=budget,",                                                   // 37
			"        allow_redirects=False,",                                            // 38
			"    )",                                                                     // 39
			"    if not is_allowed_url(response.url):",                                  // 40 a check after the call
			`        raise PermissionError("redirected to a host that is not allowed")`, // 41
			`    http.metrics.timing("preview.fetch", http.clock() - started)`,          // 42
			"    card = render_card(response.text, width)",                              // 43
			"    http.cache.set(cache_key, card)",                                       // 44
			"    return card",                                                           // 45
		}, "\n"),
	})
}

// Models often quote the right code with a line number a few lines off, or
// quote a guard together with the statement under it. The observed text is
// looked up within maxEvidenceLineDrift lines of evidence.line, and every
// check then runs on the line it was found on: a nearby line is accepted
// only where citing it exactly would have been.
func TestCodeMitigationToleratesLineDrift(t *testing.T) {
	project := lineDriftFixture(t)
	const guard = "if not is_allowed_url(preview_url):"
	cases := []struct {
		name         string
		severity     string // defaults to HIGH
		cited        int
		observed     string
		wantLine     int    // the line accepted evidence names
		wantObserved string // the text accepted evidence quotes; defaults to observed
		wantReject   string // a substring of the rejection; empty when accepted
	}{
		{name: "guard on the cited line", cited: 13, observed: guard, wantLine: driftGuardLine},
		{name: "cited one line below the guard", cited: 14, observed: guard, wantLine: driftGuardLine},
		{name: "cited two lines below the guard", cited: 15, observed: guard, wantLine: driftGuardLine},
		{name: "cited three lines below the guard", cited: 16, observed: guard, wantLine: driftGuardLine},
		{name: "cited four lines below the guard", cited: 17, observed: guard, wantLine: driftGuardLine},
		{name: "cited two lines above the guard", cited: 11, observed: guard, wantLine: driftGuardLine},
		{name: "condition only, cited one line off", cited: 14, observed: "is_allowed_url(preview_url)", wantLine: driftGuardLine},
		{name: "guard and its raise quoted together", cited: 13, observed: driftGuard + "\n" + driftGuardExit, wantLine: driftGuardLine, wantObserved: driftGuard},
		{name: "guard and its raise quoted together, cited two lines off", cited: 15, observed: driftGuard + "\n" + driftGuardExit + "\n", wantLine: driftGuardLine, wantObserved: driftGuard},

		// Every check runs on the line the text was found on.
		{name: "text found only on the flagged line", cited: 32, observed: "preview_url,", wantReject: "flagged line itself"},
		{name: "text found only after the flagged line", cited: 38, observed: "if not is_allowed_url(response.url):", wantReject: "line 40 is after the flagged line 35"},
		{name: "nearest occurrence in a comment", cited: 26, observed: "is_allowed_url(preview_url)", wantReject: "inside a comment"},
		{name: "nearest occurrence in a string literal", cited: 31, observed: "is_allowed_url(preview_url)", wantReject: "inside a string literal"},
		{name: "nearest occurrence is not a guard", cited: 18, observed: "urlsplit(preview_url)", wantReject: "line 16 is an assignment to something other than preview_url"},
		{name: "guard more than five lines from the cited line", cited: 19, observed: guard, wantReject: "absent from source"},
		// The cited line is searched first: it holds the text, in a comment,
		// so the guard further up is never considered.
		{name: "cited line holds the text in a comment", cited: 28, observed: "is_allowed_url(preview_url)", wantReject: "inside a comment"},
		// Finding the line does not lift the rules that keep a finding for a
		// person.
		{name: "CRITICAL finding", severity: "CRITICAL", cited: 15, observed: guard, wantReject: "a person must decide"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			severity := tc.severity
			if severity == "" {
				severity = "HIGH"
			}
			evidence := &DispositionEvidence{Basis: "code_mitigation", File: "preview.py", Line: tc.cited, Observed: tc.observed}
			accepted, err := validateFalsePositiveEvidence(project, mitFinding("preview.py", severity, driftFlaggedLine), evidence)
			if tc.wantReject != "" {
				switch {
				case err == nil:
					t.Fatalf("evidence accepted on line %d, want rejection containing %q", accepted.Line, tc.wantReject)
				case !strings.Contains(err.Error(), tc.wantReject):
					t.Fatalf("rejection = %q, want it to contain %q", err, tc.wantReject)
				}
				return
			}
			if err != nil {
				t.Fatalf("evidence rejected: %v", err)
			}
			wantObserved := tc.wantObserved
			if wantObserved == "" {
				wantObserved = tc.observed
			}
			want := DispositionEvidence{Basis: "code_mitigation", File: "preview.py", Line: tc.wantLine, Observed: wantObserved}
			if *accepted != want {
				t.Fatalf("accepted evidence = %+v, want %+v", *accepted, want)
			}
			if evidence.Line != tc.cited || evidence.Observed != tc.observed {
				t.Fatalf("the model's evidence was changed to %+v", *evidence)
			}
		})
	}
}

// A rejection after the text was found on another line names both lines, so
// the audit shows what was checked.
func TestDriftedRejectionNamesBothLines(t *testing.T) {
	project := lineDriftFixture(t)
	evidence := &DispositionEvidence{Basis: "code_mitigation", File: "preview.py", Line: 26, Observed: "is_allowed_url(preview_url)"}
	_, err := validateFalsePositiveEvidence(project, mitFinding("preview.py", "HIGH", driftFlaggedLine), evidence)
	if err == nil || !strings.Contains(err.Error(), "the observed text is on line 28, not on the cited line 26") {
		t.Fatalf("rejection = %v, want it to name the line checked and the line cited", err)
	}
}

// A cached dismissal is revalidated under the same rules and reused with its
// evidence as validated now, on the line its code is on.
func TestCachedCodeMitigationIsReusedOnTheLineItsCodeIsOn(t *testing.T) {
	project := lineDriftFixture(t)
	cached := FindingDisposition{Disposition: "False Positive", Confidence: "high", Evidence: &DispositionEvidence{
		Basis: "code_mitigation", File: "preview.py", Line: driftGuardLine + 2, Observed: driftGuard + "\n" + driftGuardExit,
	}}
	evidence, usable := cachedVerdictUsable(classifyRequest{projectPath: project}, mitFinding("preview.py", "HIGH", driftFlaggedLine), cached)
	if !usable || evidence == nil || evidence.Line != driftGuardLine || evidence.Observed != driftGuard {
		t.Fatalf("cachedVerdictUsable() = %+v, %v; want the dismissal reused with the guard on line %d", evidence, usable, driftGuardLine)
	}
}

// test_only evidence says the flagged line is test code: it names that line,
// exactly. The drift tolerance of code_mitigation does not apply to it.
func TestTestOnlyEvidenceMustCiteTheFlaggedLine(t *testing.T) {
	project := writeProjectFiles(t, map[string]string{"tests/test_preview.py": "import os\n\nresult = eval(os.environ['EXPR'])\n"})
	finding := mitFinding("tests/test_preview.py", "HIGH", 3)
	for line, wantAccepted := range map[int]bool{3: true, 2: false, 4: false} {
		accepted, err := validateFalsePositiveEvidence(project, finding, &DispositionEvidence{Basis: "test_only", File: finding.File, Line: line})
		switch {
		case wantAccepted && (err != nil || accepted == nil || accepted.Line != 3):
			t.Errorf("line %d: evidence = %+v, error = %v; want it accepted as given", line, accepted, err)
		case !wantAccepted && (err == nil || !strings.Contains(err.Error(), "does not match finding line")):
			t.Errorf("line %d: error = %v, want the line mismatch rejected", line, err)
		}
	}
}

func TestNearestLineWith(t *testing.T) {
	lines := []string{
		"keep(x)", // 1
		"-",       // 2
		"-",       // 3
		"keep(x)", // 4
		"-",       // 5
		"keep(x)", // 6
		"-",       // 7
		"-",       // 8
		"-",       // 9
		"-",       // 10
		"-",       // 11
		"done()",  // 12
	}
	cases := []struct {
		name  string
		cited int
		text  string
		want  int
	}{
		{"the cited line holds the text", 4, "keep(x)", 4},
		{"the nearest line below", 3, "keep(x)", 4},
		{"the nearest line above", 2, "keep(x)", 1},
		{"equally near above and below: the line above", 5, "keep(x)", 4},
		{"five lines away", 11, "keep(x)", 6},
		{"six lines away", 12, "keep(x)", 0},
		{"cited past the end of the file", 14, "done()", 12},
		{"nowhere in the file", 4, "drop(x)", 0},
	}
	for _, tc := range cases {
		if got := nearestLineWith(lines, tc.cited, tc.text); got != tc.want {
			t.Errorf("%s: nearestLineWith(%d, %q) = %d, want %d", tc.name, tc.cited, tc.text, got, tc.want)
		}
	}
}

func TestFirstObservedLine(t *testing.T) {
	cases := map[string]string{
		"x = f(x)":                      "x = f(x)",
		"x = f(x) \t":                   "x = f(x)",
		"    if ok(x):\n        return": "    if ok(x):",
		"\n  \n\tif ok(x):\r\n\t\treturn None\r\n": "\tif ok(x):",
		"if ok(x):\r\n": "if ok(x):",
		" \n\t\n":       "",
		"":              "",
	}
	for observed, want := range cases {
		if got := firstObservedLine(observed); got != want {
			t.Errorf("firstObservedLine(%q) = %q, want %q", observed, got, want)
		}
	}
}
