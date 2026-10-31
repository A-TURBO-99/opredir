package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/A-TURBO-99/opredir/internal/generator"
	"github.com/A-TURBO-99/opredir/internal/model"
	"github.com/A-TURBO-99/opredir/internal/requester"
	"github.com/A-TURBO-99/opredir/internal/targets"
	"github.com/A-TURBO-99/opredir/internal/ui"
	"github.com/A-TURBO-99/opredir/internal/verifier"
)

const version = "0.5.1"
const author = "A-TURBO-99"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "--version", "-version":
		fmt.Printf("opredir %s\n", version)
		return
	case "help", "--help", "-h":
		usage()
		return
	case "request":
		err = runRequest(os.Args[2:])
	case "ui-demo":
		err = runUIDemo(os.Args[2:])
	default:
		if strings.HasPrefix(os.Args[1], "-") {
			err = runCLI(os.Args[1:])
		} else {
			usage()
			err = fmt.Errorf("unknown command %q", os.Args[1])
		}
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(`opredir %s — Open Redirect Scanner
by %s

Usage:
  opredir -d DOMAIN [-dl 500ms] [-t 4] [-o report.json] [options]
  opredir -l FILE   [-dl 1s]    [-t 2] [-o report.json] [options]
  opredir request [options]               Replay existing generated cases
  opredir ui-demo [--quiet|--json]        Preview terminal UI with mock data
  opredir version                         Print version

Target input:
  -d, --domain DOMAIN  One domain or endpoint URL. Bare domains default to HTTPS.
  -l, --list FILE      Subdomains/endpoints, one per line.

Scan controls:
  -dl, --delay DURATION  Minimum delay between request starts (default 500ms; 0 disables).
  -t, --threads N        Maximum concurrent HTTP workers (default 4; range 1..100).
  -o, --output FILE      Detailed JSON report (default opredir-report.json).
  -param NAME|FILE       Test only one parameter, or load selected names from a file.
  --level N              Payload coverage: 1=first third, 2=first two thirds, 3=all (default 1).
  -hide                  Hide confirmed findings on screen; still save them in the report.
  --json                 Print confirmed findings and summary as JSONL.

The scanner derives its exact host scope from -d / -l, rejects request URLs
whose authority differs from the target, and never follows HTTP redirects.
Use only against systems you own or are explicitly authorized to test.

Run "opredir -h" for scan options or "opredir request -h" for replay options.
`, version, author)
}

func runRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var casesPath, output, userAgent string
	var headerFlags, cookies stringList
	var concurrency, maxRequests int
	var rate float64
	var delay, timeout time.Duration
	var maxBody int64
	fs.StringVar(&casesPath, "cases", "", "Generated JSONL test-case file (required)")
	fs.StringVar(&output, "out", "responses.jsonl", "Response evidence JSONL output")
	fs.IntVar(&concurrency, "t", 4, "Maximum concurrent HTTP workers (1..100)")
	fs.IntVar(&concurrency, "threads", 4, "Alias for -t")
	fs.IntVar(&concurrency, "concurrency", 4, "Alias for -t")
	fs.DurationVar(&delay, "dl", 500*time.Millisecond, "Minimum delay between request starts; examples: 250ms, 1s; 0 disables")
	fs.DurationVar(&delay, "delay", 500*time.Millisecond, "Alias for -dl")
	fs.Float64Var(&rate, "rate", 0, "Optional additional maximum rate in requests/second (0 disables)")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "Per-request timeout")
	fs.IntVar(&maxRequests, "max-requests", 200, "Maximum cases to send (1..5000)")
	fs.Int64Var(&maxBody, "max-body-bytes", 4096, "Maximum response body preview bytes (0..1048576)")
	fs.StringVar(&userAgent, "user-agent", "opredir/"+version, "HTTP User-Agent")
	fs.Var(&headerFlags, "header", "Additional request header as 'Name: value'; repeatable")
	fs.Var(&cookies, "cookie", "Cookie header value; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if casesPath == "" {
		return errors.New("--cases is required")
	}
	headers, err := requester.ParseHeaderFlags(headerFlags)
	if err != nil {
		return err
	}
	cases, err := requester.LoadCases(casesPath, maxRequests)
	if err != nil {
		return err
	}
	scopeHosts, err := requester.ScopeHostsFromCases(cases)
	if err != nil {
		return err
	}
	cfg := requester.Config{Concurrency: concurrency, Delay: delay, RatePerSec: rate, Timeout: timeout, MaxRequests: maxRequests, MaxBodyBytes: maxBody, UserAgent: userAgent, Headers: headers, Cookies: cookies, ScopeHosts: scopeHosts}
	// Preflight runs before creating the output file or sending any request.
	if err := requester.ValidateCases(cases, cfg); err != nil {
		return err
	}
	if err := ensureParent(output); err != nil {
		return err
	}
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	count, err := requester.Run(ctx, cases, cfg, f)
	if err != nil {
		return err
	}
	return printJSON(os.Stdout, map[string]any{"tool": "opredir", "author": author, "version": version, "cases_loaded": len(cases), "responses_written": count, "output": output, "delay": delay.String(), "threads": concurrency, "redirect_following": false, "scope_hosts": scopeHosts, "note": "Each response is captured without following HTTP redirects. Store evidence files securely."})
}

func runCLI(args []string) error {
	fs := flag.NewFlagSet("opredir", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var domain, listPath, parametersPath, parameterSelection, corpusPath, varsPath string
	var attackerHost, allowedHost, outputPath, userAgent string
	var headerFlags, cookies stringList
	var hide, jsonMode bool
	var level, concurrency int
	var rate float64
	var delay, timeout time.Duration
	var maxBody int64
	fs.StringVar(&domain, "d", "", "One domain or endpoint URL (mutually exclusive with -l)")
	fs.StringVar(&domain, "domain", "", "Alias for -d")
	fs.StringVar(&listPath, "l", "", "File containing subdomains or endpoint URLs, one per line (mutually exclusive with -d)")
	fs.StringVar(&listPath, "list", "", "Alias for -l")
	fs.DurationVar(&delay, "dl", 500*time.Millisecond, "Minimum delay between consecutive request starts; examples: 250ms, 1s; 0 disables")
	fs.DurationVar(&delay, "delay", 500*time.Millisecond, "Alias for -dl")
	fs.IntVar(&concurrency, "t", 4, "Maximum concurrent HTTP workers (1..100)")
	fs.IntVar(&concurrency, "threads", 4, "Alias for -t")
	fs.IntVar(&concurrency, "concurrency", 4, "Alias for -t")
	fs.IntVar(&level, "level", 1, "Payload coverage: 1=first third, 2=first two thirds, 3=all")
	fs.StringVar(&parametersPath, "parameters", "data/parameters.txt", "Default parameter names wordlist")
	fs.StringVar(&parameterSelection, "param", "", "Only one parameter name, or a file containing selected parameter names")
	fs.StringVar(&corpusPath, "corpus", "data/payloads/url_value_candidates.json", "Cleaned URL-value payload corpus")
	fs.StringVar(&varsPath, "vars-json", "", "JSON object mapping runtime placeholders to values")
	fs.StringVar(&attackerHost, "attacker-host", "opredir-marker.invalid", "Marker hostname used for ATTACKER_HOST")
	fs.StringVar(&allowedHost, "allowed-host", "", "Override ALLOWED_HOST (default: current target hostname)")
	fs.Float64Var(&rate, "rate", 0, "Optional additional maximum rate in requests/second (0 disables)")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "Per-request timeout")
	fs.Int64Var(&maxBody, "max-body-bytes", 8192, "Maximum response body preview bytes (0..1048576)")
	fs.StringVar(&userAgent, "user-agent", "opredir/"+version, "HTTP User-Agent")
	fs.Var(&headerFlags, "header", "Additional request header as 'Name: value'; repeatable")
	fs.Var(&cookies, "cookie", "Cookie header value; repeatable")
	fs.StringVar(&outputPath, "o", "opredir-report.json", "Detailed JSON report output file")
	fs.StringVar(&outputPath, "output", "opredir-report.json", "Alias for -o")
	fs.BoolVar(&hide, "hide", false, "Hide confirmed findings on screen; findings remain in the report")
	fs.BoolVar(&jsonMode, "json", false, "Print confirmed findings and summary as JSONL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if (domain == "") == (listPath == "") {
		return errors.New("supply exactly one target source: -d DOMAIN or -l FILE")
	}
	if level < 1 || level > 3 {
		return errors.New("--level must be 1, 2, or 3")
	}

	options := ui.DetectOptions(os.Stdout, false, jsonMode, hide)
	reporter := ui.New(os.Stdout, options)
	reporter.Header("opredir", version, author)

	var targetURLs, scopeHosts []string
	var err error
	if domain != "" {
		targetURLs, scopeHosts, err = targets.FromDomain(domain)
	} else {
		targetURLs, scopeHosts, err = targets.FromList(listPath)
	}
	if err != nil {
		return err
	}
	parameters, err := generator.LoadParameterSelection(parameterSelection, parametersPath)
	if err != nil {
		return err
	}
	payloads, err := generator.LoadPayloads(corpusPath)
	if err != nil {
		return err
	}
	payloads, err = generator.SelectPayloadLevel(payloads, level)
	if err != nil {
		return err
	}
	variables := map[string]string{"ATTACKER_HOST": attackerHost}
	if varsPath != "" {
		b, readErr := os.ReadFile(varsPath)
		if readErr != nil {
			return readErr
		}
		if decodeErr := json.Unmarshal(b, &variables); decodeErr != nil {
			return fmt.Errorf("decode --vars-json: %w", decodeErr)
		}
		if variables == nil {
			variables = make(map[string]string)
		}
		if attackerHost != "" {
			variables["ATTACKER_HOST"] = attackerHost
		}
	}

	var allCases []model.TestCase
	combinedStats := map[string]int{"generated": 0, "skipped_missing_placeholders": 0, "skipped_invalid_targets": 0}
	for _, targetURL := range targetURLs {
		targetHost := ""
		for _, host := range scopeHosts {
			if strings.EqualFold(host, mustHostname(targetURL)) {
				targetHost = host
				break
			}
		}
		targetVars := make(map[string]string, len(variables)+1)
		for k, v := range variables {
			targetVars[k] = v
		}
		if allowedHost != "" {
			targetVars["ALLOWED_HOST"] = allowedHost
		} else if strings.TrimSpace(targetVars["ALLOWED_HOST"]) == "" && targetHost != "" {
			targetVars["ALLOWED_HOST"] = targetHost
		}
		generated, stats, genErr := generator.Generate([]string{targetURL}, parameters, payloads, targetVars)
		if genErr != nil {
			return genErr
		}
		for i := range generated {
			generated[i].CaseID = fmt.Sprintf("OR-SCAN-%07d", len(allCases)+i+1)
		}
		allCases = append(allCases, generated...)
		for k, v := range stats {
			combinedStats[k] += v
		}
	}
	if len(allCases) == 0 {
		return errors.New("no test cases generated; check the payload corpus and required --vars-json placeholders")
	}

	headers, err := requester.ParseHeaderFlags(headerFlags)
	if err != nil {
		return err
	}
	// MaxRequests=0 means the scanner runs the complete generated matrix.
	// The separate `request` subcommand retains its own explicit bounded cap.
	cfg := requester.Config{Concurrency: concurrency, Delay: delay, RatePerSec: rate, Timeout: timeout, MaxBodyBytes: maxBody, UserAgent: userAgent, Headers: headers, Cookies: cookies, ScopeHosts: scopeHosts}
	if err := requester.ValidateCases(allCases, cfg); err != nil {
		return fmt.Errorf("scan preflight rejected before network traffic: %w", err)
	}
	if outputPath == "" {
		return errors.New("-o output path cannot be empty")
	}
	if err := ensureParent(outputPath); err != nil {
		return err
	}

	payloadSet := fmt.Sprintf("Level %d/3", level)
	if parametersPath != "data/parameters.txt" || corpusPath != "data/payloads/url_value_candidates.json" {
		payloadSet += " (custom corpus/parameters)"
	}
	sourceLabel := domain
	if listPath != "" {
		sourceLabel = listPath
	}
	plan := ui.Plan{TargetCount: len(targetURLs), TargetSource: sourceLabel, ParameterCount: len(parameters), PayloadCount: len(payloads), PayloadSet: payloadSet, RequestCount: len(allCases)}
	reporter.ScanPlan(plan)
	reporter.LoadingTargets(len(targetURLs))

	started := time.Now()
	findings := make([]verifier.Finding, 0)
	scanned := 0
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	responseCount, runErr := requester.RunWithCallback(ctx, allCases, cfg, io.Discard, func(rec model.ResponseRecord) {
		scanned++
		finding := verifier.VerifyRecord(rec)
		if finding.Confirmed {
			findings = append(findings, finding)
			reporter.Result(ui.Result{
				TargetURL: finding.TargetURL, FullURL: finding.RequestURL, Payload: finding.PayloadResolved,
				Parameter: finding.Parameter, StatusCode: finding.StatusCode,
				RedirectDestination: finding.ResolvedDestination, Classification: string(finding.Classification),
				Confirmed: true, Reason: finding.Reason, DurationMS: rec.DurationMS,
			})
		}
		reporter.Progress(scanned, len(allCases))
	})
	if runErr != nil {
		return runErr
	}
	if responseCount != len(allCases) {
		return fmt.Errorf("scan incomplete: received %d of %d responses", responseCount, len(allCases))
	}
	duration := time.Since(started)
	report := map[string]any{
		"tool": "opredir", "version": version, "author": author,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"duration_ms":  duration.Milliseconds(),
		"level":        level,
		"targets":      targetURLs, "target_count": len(targetURLs),
		"parameters_loaded": len(parameters), "payload_records_selected": len(payloads),
		"requests_generated": len(allCases), "requests_completed": responseCount,
		"threads": concurrency, "delay": delay.String(),
		"confirmed_findings_count": len(findings), "confirmed_findings": findings,
		"generation_stats":             combinedStats,
		"redirect_following":           false,
		"findings_hidden_from_console": hide,
		"note":                         "Only findings verified by a matching external HTTP Location or Refresh destination are included. Non-confirmed candidates are intentionally omitted.",
	}
	if err := writeJSONFile(outputPath, report); err != nil {
		return fmt.Errorf("write detailed report: %w", err)
	}
	reporter.Finish(ui.Summary{Duration: duration, Scanned: responseCount, Vulnerable: len(findings), NotConfirmed: responseCount - len(findings), ReportPath: outputPath})
	return nil
}

func runUIDemo(args []string) error {
	fs := flag.NewFlagSet("ui-demo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var quiet, jsonMode bool
	var reportPath string
	var width int
	fs.BoolVar(&quiet, "quiet", false, "Print one plain-text line per mock result")
	fs.BoolVar(&jsonMode, "json", false, "Emit newline-delimited JSON events instead of terminal UI")
	fs.StringVar(&reportPath, "report", "opredir-demo-report.html", "HTML mock report output path")
	fs.IntVar(&width, "width", 0, "Override terminal width for preview (32..120)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if quiet && jsonMode {
		return errors.New("--quiet and --json cannot be used together")
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if width != 0 && (width < 32 || width > 120) {
		return errors.New("--width must be between 32 and 120")
	}

	options := ui.DetectOptions(os.Stdout, quiet, jsonMode, false)
	if width != 0 {
		options.Width = width
	}
	reporter := ui.New(os.Stdout, options)
	plan := ui.Plan{
		TargetCount: 240, TargetSource: "urls.txt", ParameterCount: 1,
		PayloadCount: 12, PayloadSet: "standard set", RequestCount: 2880,
	}
	reporter.Header("opredir", version, author)
	reporter.ScanPlan(plan)
	reporter.LoadingTargets(plan.TargetCount)

	start := time.Now()
	vulnerableIndexes := map[int]bool{186: true, 1140: true, 2479: true}
	for i := 1; i <= plan.RequestCount; i++ {
		result := ui.Result{
			TargetURL: fmt.Sprintf("https://target-%03d.example.test/redirect", ((i-1)%plan.TargetCount)+1),
			FullURL:   fmt.Sprintf("https://target-%03d.example.test/redirect?next=PAYLOAD-%02d", ((i-1)%plan.TargetCount)+1, ((i-1)%plan.PayloadCount)+1),
			Parameter: "next", Classification: "clean", Confirmed: false,
			StatusCode: 200,
		}
		if vulnerableIndexes[i] {
			result.Classification = "confirmed_open_redirect"
			result.Confirmed = true
			result.Payload = "https://redirect-marker.invalid/landing"
			result.StatusCode = 302
			result.RedirectDestination = "https://redirect-marker.invalid/landing"
			result.Reason = "Mock 302 Location matched the supplied external test destination."
		} else {
			result.Reason = "Mock response did not demonstrate an external redirect."
		}
		reporter.Result(result)
		if i%24 == 0 || i == plan.RequestCount {
			reporter.Progress(i, plan.RequestCount)
		}
		if i%24 == 0 {
			time.Sleep(8 * time.Millisecond)
		}
	}

	if reportPath != "" {
		if err := writeMockHTMLReport(reportPath, plan, vulnerableIndexes); err != nil {
			return fmt.Errorf("write mock HTML report: %w", err)
		}
	}
	reporter.Finish(ui.Summary{
		Duration: time.Since(start), Scanned: plan.RequestCount,
		Vulnerable: len(vulnerableIndexes), NotConfirmed: plan.RequestCount - len(vulnerableIndexes),
		ReportPath: reportPath,
	})
	return nil
}

func writeMockHTMLReport(path string, plan ui.Plan, findings map[int]bool) error {
	if err := ensureParent(path); err != nil {
		return err
	}
	content := fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>opredir mock scan report</title><style>body{font:15px system-ui;margin:40px auto;max-width:900px;padding:0 20px;color:#222}h1{color:#b42318}.notice{padding:12px;background:#fff4ce;border:1px solid #e5c65a;border-radius:8px}table{border-collapse:collapse;width:100%%}td,th{padding:9px;border-bottom:1px solid #ddd;text-align:left}.bad{color:#b42318;font-weight:bold}</style></head>
<body><h1>opredir — Mock Scan Report</h1><p class="notice"><strong>DEMO DATA:</strong> This report was generated by <code>opredir ui-demo</code>. It is not evidence from a real target.</p>
<h2>Scan plan</h2><p>Targets: %d (%s) · Parameters: %d · Payloads: %d (%s) · Requests: %d</p>
<h2>Mock findings</h2><table><thead><tr><th>Target</th><th>Parameter</th><th>Status</th><th>Destination</th></tr></thead><tbody>
<tr><td>https://target-186.example.test/redirect</td><td>next</td><td>302</td><td class="bad">https://redirect-marker.invalid/landing</td></tr>
<tr><td>https://target-180.example.test/redirect</td><td>next</td><td>302</td><td class="bad">https://redirect-marker.invalid/landing</td></tr>
<tr><td>https://target-079.example.test/redirect</td><td>next</td><td>302</td><td class="bad">https://redirect-marker.invalid/landing</td></tr>
</tbody></table><p>Generated for UI preview · A-TURBO-99</p></body></html>`, plan.TargetCount, htmlEscape(plan.TargetSource), plan.ParameterCount, plan.PayloadCount, htmlEscape(plan.PayloadSet), plan.RequestCount)
	return os.WriteFile(path, []byte(content), 0o644)
}

func htmlEscape(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;").Replace(value)
}

func mustHostname(raw string) string {
	u, err := generator.ValidateTargetURL(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

func ensureParent(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func writeJSONFile(path string, value any) error {
	if err := ensureParent(path); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(value)
}

func printJSON(w *os.File, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
