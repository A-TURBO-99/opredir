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

const version = "0.4.3"
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
	case "generate":
		err = runGenerate(os.Args[2:])
	case "request":
		err = runRequest(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "ui-demo":
		err = runUIDemo(os.Args[2:])
	default:
		if strings.HasPrefix(os.Args[1], "-") {
			err = runScan(os.Args[1:])
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
  opredir scan [options]
  opredir generate [options]              Generate test cases only
  opredir request [options]               Send existing generated cases
  opredir verify -in FILE [options]       Verify captured response JSONL
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
  --quiet                Print confirmed findings as plain text only.
  --json                 Print confirmed findings and summary as JSONL.

The scanner derives its exact host scope from -d / -l, rejects request URLs
whose authority differs from the target, and never follows HTTP redirects.
Use only against systems you own or are explicitly authorized to test.

Run "opredir <command> -h" for command options.
`, version, author)
}

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var targets stringList
	var families stringList
	var urlsFile, parametersPath, parameterSelection, corpusPath, varsPath, output, mode, attackerHost, allowedHost string
	var maxCases int
	fs.Var(&targets, "url", "Target endpoint URL; repeatable")
	fs.StringVar(&urlsFile, "urls-file", "", "File containing one target URL per line")
	fs.StringVar(&parametersPath, "parameters", "data/parameters.txt", "Default parameter names wordlist")
	fs.StringVar(&parameterSelection, "param", "", "Only one parameter name, or a file containing selected parameter names")
	fs.StringVar(&corpusPath, "corpus", "data/payloads/url_value_candidates.json", "Cleaned URL-value payload corpus")
	fs.StringVar(&varsPath, "vars-json", "", "JSON object mapping placeholder names to values")
	fs.StringVar(&attackerHost, "attacker-host", "", "Tester-controlled hostname for ATTACKER_HOST")
	fs.StringVar(&allowedHost, "allowed-host", "", "Allowed hostname for ALLOWED_HOST")
	fs.Var(&families, "family", "Exact payload family filter; repeatable")
	fs.StringVar(&mode, "mode", "auto", "Parameter mode: auto, append, replace-all, replace-first")
	fs.IntVar(&maxCases, "max-cases", 10000, "Maximum generated cases (1..200000)")
	fs.StringVar(&output, "out", "generated-cases.jsonl", "Output JSONL file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (len(targets) == 0) == (urlsFile == "") {
		return errors.New("supply either --url (repeatable) or --urls-file")
	}
	if maxCases < 1 || maxCases > 200000 {
		return errors.New("--max-cases must be between 1 and 200000")
	}
	if mode != "auto" && mode != "append" && mode != "replace-all" && mode != "replace-first" {
		return fmt.Errorf("unsupported --mode %q", mode)
	}
	if urlsFile != "" {
		lines, err := readLines(urlsFile)
		if err != nil {
			return err
		}
		targets = append(targets, lines...)
	}
	if len(targets) == 0 {
		return errors.New("no target URLs supplied")
	}
	parameters, err := generator.LoadParameterSelection(parameterSelection, parametersPath)
	if err != nil {
		return err
	}
	familySet := make(map[string]bool)
	for _, f := range families {
		familySet[f] = true
	}
	payloads, err := generator.LoadPayloads(corpusPath, familySet)
	if err != nil {
		return err
	}
	variables := make(map[string]string)
	if varsPath != "" {
		b, err := os.ReadFile(varsPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &variables); err != nil {
			return fmt.Errorf("decode --vars-json: %w", err)
		}
	}
	if attackerHost != "" {
		variables["ATTACKER_HOST"] = attackerHost
	}
	if allowedHost != "" {
		variables["ALLOWED_HOST"] = allowedHost
	}
	cases, stats, err := generator.Generate(targets, parameters, payloads, variables, mode, maxCases)
	if err != nil {
		return err
	}
	if len(cases) == 0 {
		return errors.New("no cases generated; check target URLs and required payload placeholders")
	}
	if err := writeJSONL(output, cases); err != nil {
		return err
	}
	summary := map[string]any{"tool": "opredir", "author": author, "version": version, "output": output, "targets": len(targets), "parameters_loaded": len(parameters), "payload_records_selected": len(payloads), "max_cases": maxCases, "stats": stats, "note": "Generated only; no HTTP requests were sent."}
	return printJSON(os.Stdout, summary)
}

func runRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var casesPath, output, userAgent string
	var headerFlags, cookies stringList
	var tlsInsecure bool
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
	fs.BoolVar(&tlsInsecure, "tls-insecure", false, "Skip TLS certificate verification (not recommended)")
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
	cfg := requester.Config{Concurrency: concurrency, Delay: delay, RatePerSec: rate, Timeout: timeout, MaxRequests: maxRequests, MaxBodyBytes: maxBody, UserAgent: userAgent, Headers: headers, Cookies: cookies, TLSInsecure: tlsInsecure, ScopeHosts: scopeHosts}
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

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var domain, listPath, parametersPath, parameterSelection, corpusPath, varsPath string
	var attackerHost, allowedHost, mode, outputPath, userAgent string
	var familyFlags, headerFlags, cookies stringList
	var tlsInsecure, quiet, jsonMode bool
	var maxCases, concurrency int
	var rate float64
	var delay, timeout time.Duration
	var maxBody int64
	fs.StringVar(&domain, "d", "", "One domain or endpoint URL (mutually exclusive with -l)")
	fs.StringVar(&domain, "domain", "", "Alias for -d")
	fs.StringVar(&listPath, "l", "", "File containing subdomains or endpoint URLs, one per line (mutually exclusive with -d)")
	fs.StringVar(&listPath, "list", "", "Alias for -l")
	fs.DurationVar(&delay, "dl", 500*time.Millisecond, "Minimum delay between consecutive request starts; examples: 250ms, 1s; 0 disables")
	fs.DurationVar(&delay, "delay", 500*time.Millisecond, "Alias for -dl")
	fs.StringVar(&parametersPath, "parameters", "data/parameters.txt", "Default parameter names wordlist")
	fs.StringVar(&parameterSelection, "param", "", "Only one parameter name, or a file containing selected parameter names")
	fs.StringVar(&corpusPath, "corpus", "data/payloads/url_value_candidates.json", "Cleaned URL-value payload corpus")
	fs.StringVar(&varsPath, "vars-json", "", "JSON object mapping runtime placeholders to values")
	fs.StringVar(&attackerHost, "attacker-host", "opredir-marker.invalid", "Marker hostname used for ATTACKER_HOST")
	fs.StringVar(&allowedHost, "allowed-host", "", "Override ALLOWED_HOST (default: current target hostname)")
	fs.Var(&familyFlags, "family", "Exact payload family filter; repeatable")
	fs.StringVar(&mode, "mode", "auto", "Parameter mode: auto, append, replace-all, replace-first")
	fs.IntVar(&maxCases, "max-cases", 500, "Maximum active requests (1..5000)")
	fs.IntVar(&concurrency, "t", 4, "Maximum concurrent HTTP workers (1..100)")
	fs.IntVar(&concurrency, "threads", 4, "Alias for -t")
	fs.IntVar(&concurrency, "concurrency", 4, "Alias for -t")
	fs.Float64Var(&rate, "rate", 0, "Optional additional maximum rate in requests/second (0 disables)")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "Per-request timeout")
	fs.Int64Var(&maxBody, "max-body-bytes", 8192, "Maximum response body preview bytes (0..1048576)")
	fs.StringVar(&userAgent, "user-agent", "opredir/"+version, "HTTP User-Agent")
	fs.Var(&headerFlags, "header", "Additional request header as 'Name: value'; repeatable")
	fs.Var(&cookies, "cookie", "Cookie header value; repeatable")
	fs.BoolVar(&tlsInsecure, "tls-insecure", false, "Skip TLS certificate verification (not recommended)")
	fs.StringVar(&outputPath, "o", "opredir-report.json", "Detailed JSON report output file")
	fs.StringVar(&outputPath, "output", "opredir-report.json", "Alias for -o")
	fs.BoolVar(&quiet, "quiet", false, "Print confirmed findings as plain text only")
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
	if quiet && jsonMode {
		return errors.New("--quiet and --json cannot be used together")
	}
	if maxCases < 1 || maxCases > 5000 {
		return errors.New("--max-cases must be between 1 and 5000")
	}
	if mode != "auto" && mode != "append" && mode != "replace-all" && mode != "replace-first" {
		return fmt.Errorf("unsupported --mode %q", mode)
	}

	options := ui.DetectOptions(os.Stdout, quiet, jsonMode)
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
	familySet := make(map[string]bool)
	for _, family := range familyFlags {
		familySet[family] = true
	}
	payloads, err := generator.LoadPayloads(corpusPath, familySet)
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
	if len(targetURLs) > maxCases {
		return fmt.Errorf("the target source contains %d targets but --max-cases is %d; increase --max-cases so every target receives at least one test", len(targetURLs), maxCases)
	}

	var allCases []model.TestCase
	combinedStats := map[string]int{"generated": 0, "skipped_missing_placeholders": 0, "skipped_invalid_targets": 0}
	baseQuota, extraQuota := maxCases/len(targetURLs), maxCases%len(targetURLs)
	for targetIndex, targetURL := range targetURLs {
		quota := baseQuota
		if targetIndex < extraQuota {
			quota++
		}
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
		generated, stats, genErr := generator.Generate([]string{targetURL}, parameters, payloads, targetVars, mode, quota)
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
	cfg := requester.Config{Concurrency: concurrency, Delay: delay, RatePerSec: rate, Timeout: timeout, MaxRequests: maxCases, MaxBodyBytes: maxBody, UserAgent: userAgent, Headers: headers, Cookies: cookies, TLSInsecure: tlsInsecure, ScopeHosts: scopeHosts}
	if err := requester.ValidateCases(allCases, cfg); err != nil {
		return fmt.Errorf("scan preflight rejected before network traffic: %w", err)
	}
	if err := ensureParent(outputPath); err != nil {
		return err
	}
	if outputPath == "" {
		return errors.New("-o output path cannot be empty")
	}

	payloadSet := "standard set"
	if len(familyFlags) > 0 || parametersPath != "data/parameters.txt" || corpusPath != "data/payloads/url_value_candidates.json" {
		payloadSet = "custom/filtered set"
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
		"targets":      targetURLs, "target_count": len(targetURLs),
		"parameters_loaded": len(parameters), "payload_records_selected": len(payloads),
		"requests_generated": len(allCases), "requests_completed": responseCount,
		"threads": concurrency, "delay": delay.String(),
		"confirmed_findings_count": len(findings), "confirmed_findings": findings,
		"generation_stats":   combinedStats,
		"redirect_following": false,
		"note":               "Only findings verified by a matching external HTTP Location or Refresh destination are included. Non-confirmed candidates are intentionally omitted.",
	}
	if err := writeJSONFile(outputPath, report); err != nil {
		return fmt.Errorf("write detailed report: %w", err)
	}
	reporter.Finish(ui.Summary{Duration: duration, Scanned: responseCount, Vulnerable: len(findings), NotConfirmed: responseCount - len(findings), ReportPath: outputPath})
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var input, output string
	var maxRecords int
	fs.StringVar(&input, "in", "", "Captured response JSONL file (required)")
	fs.StringVar(&output, "out", "opredir-findings.jsonl", "Findings JSONL output")
	fs.IntVar(&maxRecords, "max-records", 5000, "Maximum response records to verify")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if input == "" {
		return errors.New("verify requires --in FILE")
	}
	if input == output {
		return errors.New("input and output files must be different")
	}
	responses, err := verifier.LoadResponses(input, maxRecords)
	if err != nil {
		return err
	}
	findings := verifier.VerifyAll(responses)
	if err := verifier.WriteFindings(output, findings); err != nil {
		return err
	}
	counts := make(map[string]int)
	confirmed := 0
	for _, finding := range findings {
		counts[string(finding.Classification)]++
		if finding.Confirmed {
			confirmed++
		}
	}
	return printJSON(os.Stdout, map[string]any{"tool": "opredir", "author": author, "version": version, "verified_records": len(responses), "confirmed_findings": confirmed, "classification_counts": counts, "output": output})
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

	options := ui.DetectOptions(os.Stdout, quiet, jsonMode)
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

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		v := strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if v != "" && !strings.HasPrefix(v, "#") {
			out = append(out, v)
		}
	}
	return out, nil
}

func writeJSONL(path string, cases []model.TestCase) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, tc := range cases {
		if err := enc.Encode(tc); err != nil {
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
