package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Options struct {
	Quiet       bool
	JSON        bool
	Verbose     bool
	Color       bool
	Interactive bool
	Width       int
}

type Plan struct {
	TargetCount    int    `json:"target_count"`
	TargetSource   string `json:"target_source"`
	ParameterCount int    `json:"parameter_count"`
	PayloadCount   int    `json:"payload_count"`
	PayloadSet     string `json:"payload_set"`
	RequestCount   int    `json:"request_count"`
}

type Result struct {
	TargetURL           string `json:"target_url"`
	FullURL             string `json:"full_url"`
	Payload             string `json:"payload,omitempty"`
	Parameter           string `json:"parameter,omitempty"`
	StatusCode          int    `json:"status_code,omitempty"`
	RedirectDestination string `json:"redirect_destination,omitempty"`
	Classification      string `json:"classification"`
	Confirmed           bool   `json:"confirmed"`
	Reason              string `json:"reason,omitempty"`
	DurationMS          int64  `json:"duration_ms,omitempty"`
}

type Summary struct {
	Duration   time.Duration `json:"duration"`
	Scanned    int           `json:"scanned"`
	Vulnerable int           `json:"vulnerable"`
	Clean      int           `json:"clean"`
	Other      int           `json:"other,omitempty"`
	ReportPath string        `json:"report_path,omitempty"`
}

type Reporter struct {
	out     io.Writer
	options Options
	start   time.Time
	plan    Plan
	lastPct int
	spin    int
}

func New(out io.Writer, options Options) *Reporter {
	if options.Width <= 0 {
		options.Width = terminalWidth()
	}
	if options.Width < 32 {
		options.Width = 32
	}
	if options.Width > 120 {
		options.Width = 120
	}
	return &Reporter{out: out, options: options, start: time.Now(), lastPct: -1}
}

func DetectOptions(out *os.File, quiet, jsonMode, verbose bool) Options {
	color, interactive := false, false
	if out != nil {
		if info, err := out.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			interactive = true
			color = os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
		}
	}
	return Options{Quiet: quiet, JSON: jsonMode, Verbose: verbose, Color: color, Interactive: interactive, Width: terminalWidth()}
}

func terminalWidth() int {
	if value := strings.TrimSpace(os.Getenv("COLUMNS")); value != "" {
		if n, err := strconv.Atoi(value); err == nil && n >= 32 {
			return n
		}
	}
	return 80
}

func (r *Reporter) Header(name, version, author string) {
	if r.options.Quiet || r.options.JSON {
		return
	}
	title := fmt.Sprintf("⚡ %s v%s — Open Redirect Scanner", name, version)
	fmt.Fprintln(r.out, r.paint("36;1", title))
	if author != "" {
		fmt.Fprintln(r.out, r.paint("90", "   by "+author))
	}
	fmt.Fprintln(r.out)
}

func (r *Reporter) ScanPlan(plan Plan) {
	r.plan = plan
	if r.options.Quiet || r.options.JSON {
		return
	}
	rows := []string{
		fmt.Sprintf("Targets      %s URLs  (%s)", comma(plan.TargetCount), plan.TargetSource),
		fmt.Sprintf("Parameters   %s names", comma(plan.ParameterCount)),
		fmt.Sprintf("Payloads     %s payloads  (%s)", comma(plan.PayloadCount), plan.PayloadSet),
		fmt.Sprintf("Requests     %s total  (%s × %s × %s)", comma(plan.RequestCount), comma(plan.TargetCount), comma(plan.ParameterCount), comma(plan.PayloadCount)),
	}
	if r.options.Width < 58 {
		fmt.Fprintln(r.out, r.paint("36;1", "Scan Plan"))
		for _, row := range rows {
			fmt.Fprintln(r.out, "  "+truncate(row, r.options.Width-4))
		}
		fmt.Fprintln(r.out)
		return
	}
	boxWidth := r.options.Width - 2
	if boxWidth > 72 {
		boxWidth = 72
	}
	inner := boxWidth - 2
	fmt.Fprintln(r.out, r.paint("36", "╭─ Scan Plan "+strings.Repeat("─", max(0, inner-12))+"╮"))
	for _, row := range rows {
		fmt.Fprintf(r.out, "│  %-*s │\n", inner-3, truncate(row, inner-3))
	}
	fmt.Fprintln(r.out, r.paint("36", "╰"+strings.Repeat("─", inner)+"╯"))
	fmt.Fprintln(r.out)
}

func (r *Reporter) LoadingTargets(count int) {
	if r.options.Quiet || r.options.JSON {
		return
	}
	fmt.Fprintf(r.out, "%s Loading targets...   %s URLs\n", r.paint("33", "◐"), comma(count))
}

func (r *Reporter) Progress(scanned, total int) {
	if r.options.Quiet || r.options.JSON || !r.options.Interactive || total <= 0 {
		return
	}
	if scanned < 0 {
		scanned = 0
	}
	if scanned > total {
		scanned = total
	}
	pct := scanned * 100 / total
	if scanned > 0 && pct == 0 {
		pct = 1
	}
	barWidth := r.options.Width - 43
	if barWidth < 10 {
		barWidth = 10
	}
	if barWidth > 30 {
		barWidth = 30
	}
	filled := barWidth * scanned / total
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	spin := []string{"◐", "◓", "◑", "◒"}[r.spin%4]
	r.spin++
	line := fmt.Sprintf("%s Scanning...   %s  %3d%%  (%s/%s)", spin, bar, pct, comma(scanned), comma(total))
	if !r.options.Color {
		line = strings.ReplaceAll(line, "█", "#")
		line = strings.ReplaceAll(line, "░", "-")
	}
	fmt.Fprintf(r.out, "\r\033[K%s", r.paint("36", line))
	r.lastPct = pct
}

func (r *Reporter) Result(result Result) {
	if r.options.JSON {
		r.writeJSON(map[string]any{"type": "result", "result": result})
		return
	}
	if r.options.Quiet {
		fmt.Fprintln(r.out, r.plainResult(result))
		return
	}
	show := result.Confirmed || r.options.Verbose
	if !show {
		return
	}
	if r.lastPct >= 0 && r.options.Interactive {
		fmt.Fprint(r.out, "\r\033[K")
	}
	if result.Confirmed {
		fmt.Fprintf(r.out, "%s %s   %s\n", r.paint("31;1", "✖"), r.paint("31;1", "VULNERABLE"), result.FullURL)
		fmt.Fprintf(r.out, "                  %s %s\n", r.paint("90", "payload:"), r.paint("90", result.Payload))
		fmt.Fprintf(r.out, "                  %s %s\n", r.paint("90", "param:  "), r.paint("90", result.Parameter))
		fmt.Fprintf(r.out, "                  %s %d → %s\n", r.paint("90", "status: "), result.StatusCode, result.RedirectDestination)
	} else if result.Classification == "clean" {
		fmt.Fprintf(r.out, "%s CLEAN         %s\n", r.paint("32", "✔"), result.FullURL)
	} else {
		fmt.Fprintf(r.out, "%s %-13s %s\n", r.paint("33", "!"), strings.ToUpper(result.Classification), result.FullURL)
		if result.Reason != "" {
			fmt.Fprintf(r.out, "                  %s %s\n", r.paint("90", "reason:"), r.paint("90", result.Reason))
		}
	}
	if r.lastPct >= 0 {
		r.ProgressFromPct(result)
	}
}

// ProgressFromPct redraws the progress row after a streamed finding. It uses
// the last observed percentage and does not need scanner internals.
func (r *Reporter) ProgressFromPct(_ Result) {
	// Progress is redrawn by the scan loop on its next update. Writing a newline
	// here keeps findings stable and avoids stale in-place terminal content.
	r.lastPct = -1
}

func (r *Reporter) Finish(summary Summary) {
	if r.options.JSON {
		r.writeJSON(map[string]any{"type": "summary", "summary": summary})
		return
	}
	if r.options.Quiet {
		return
	}
	if r.lastPct >= 0 && r.options.Interactive {
		fmt.Fprintln(r.out)
	}
	fmt.Fprintln(r.out, r.paint("90", strings.Repeat("─", min(r.options.Width-2, 60))))
	fmt.Fprintf(r.out, "Done in %.2fs\n\n", summary.Duration.Seconds())
	fmt.Fprintf(r.out, "  %-12s %s requests\n", "Scanned", comma(summary.Scanned))
	fmt.Fprintf(r.out, "  %-12s %s\n", r.paint("31;1", "Vulnerable"), comma(summary.Vulnerable))
	fmt.Fprintf(r.out, "  %-12s %s\n", r.paint("32", "Clean"), comma(summary.Clean))
	if summary.Other > 0 {
		fmt.Fprintf(r.out, "  %-12s %s\n", "Other", comma(summary.Other))
	}
	if summary.ReportPath != "" {
		fmt.Fprintf(r.out, "\nReport saved: %s\n", summary.ReportPath)
	}
}

func (r *Reporter) writeJSON(value any) {
	enc := json.NewEncoder(r.out)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)
}

func (r *Reporter) plainResult(result Result) string {
	status := strconv.Itoa(result.StatusCode)
	if result.StatusCode == 0 {
		status = "-"
	}
	label := strings.ToUpper(result.Classification)
	if result.Confirmed {
		label = "VULNERABLE"
	}
	return strings.Join([]string{label, result.FullURL, "param=" + result.Parameter, "status=" + status, "location=" + result.RedirectDestination}, "\t")
}

func (r *Reporter) paint(code, value string) string {
	if !r.options.Color || r.options.Quiet || r.options.JSON {
		return value
	}
	return "\033[" + code + "m" + value + "\033[0m"
}

func comma(value int) string {
	s := strconv.Itoa(value)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func truncate(value string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= maxWidth {
		return value
	}
	runes := []rune(value)
	if maxWidth <= 3 {
		return string(runes[:maxWidth])
	}
	return string(runes[:maxWidth-3]) + "..."
}
