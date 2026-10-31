package ui

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestQuietPrintsPlainOneLinePerResult(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, Options{Quiet: true, Color: true, Width: 80})
	r.Header("opredir", "0.4.1", "A-TURBO-99")
	r.ScanPlan(Plan{TargetCount: 1, ParameterCount: 1, PayloadCount: 1, RequestCount: 1})
	r.LoadingTargets(1)
	r.Progress(1, 1)
	r.Result(Result{FullURL: "https://example.test/?next=clean", Classification: "no_redirect_observed", Confirmed: false})
	r.Result(Result{FullURL: "https://example.test/?next=x", Classification: "confirmed_open_redirect", Confirmed: true, Parameter: "next", Payload: "https://marker.invalid/", StatusCode: 302, RedirectDestination: "https://marker.invalid/"})
	r.Finish(Summary{Scanned: 1, NotConfirmed: 1})
	got := strings.TrimSpace(out.String())
	if strings.Contains(got, "\033[") || strings.Contains(got, "Scan Plan") || strings.Contains(got, "Done in") {
		t.Fatalf("quiet output contains formatted UI: %q", got)
	}
	if !strings.HasPrefix(got, "VULNERABLE\t") {
		t.Fatalf("unexpected quiet output: %q", got)
	}
}

func TestJSONModeEmitsStructuredEvents(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, Options{JSON: true, Width: 80})
	r.Header("opredir", "0.4.1", "A-TURBO-99")
	r.ScanPlan(Plan{TargetCount: 1, ParameterCount: 2, PayloadCount: 3, RequestCount: 6})
	r.Result(Result{Classification: "confirmed_open_redirect", Confirmed: true, FullURL: "https://example.test/?next=x"})
	r.Finish(Summary{Duration: time.Second, Scanned: 6, Vulnerable: 1, NotConfirmed: 5})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected result and summary JSON lines, got %d: %q", len(lines), out.String())
	}
	for _, line := range lines {
		var value map[string]any
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			t.Fatalf("invalid JSON line: %v", err)
		}
	}
}

func TestPlanResponsiveToNarrowTerminal(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, Options{Width: 40})
	r.ScanPlan(Plan{TargetCount: 240, TargetSource: "urls.txt", ParameterCount: 1, PayloadCount: 12, PayloadSet: "standard set", RequestCount: 2880})
	if !strings.Contains(out.String(), "Scan Plan") || !strings.Contains(out.String(), "Requests") {
		t.Fatalf("narrow terminal plan missing expected fields: %q", out.String())
	}
}

func TestNonInteractiveProgressDoesNotWriteTerminalControls(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, Options{Width: 80, Interactive: false})
	r.Progress(10, 100)
	if out.Len() != 0 {
		t.Fatalf("non-interactive progress should not emit spinner/control output: %q", out.String())
	}
}

func TestDefaultUIShowsOnlyConfirmedFindings(t *testing.T) {
	var out bytes.Buffer
	r := New(&out, Options{Width: 80})
	r.Result(Result{FullURL: "https://example.test/?next=reflected", Classification: "reflected_input_only"})
	r.Result(Result{FullURL: "https://example.test/?next=confirmed", Classification: "confirmed_open_redirect", Confirmed: true})
	if strings.Contains(out.String(), "reflected") || !strings.Contains(out.String(), "VULNERABLE") {
		t.Fatalf("default UI must show confirmed findings only: %q", out.String())
	}
}
