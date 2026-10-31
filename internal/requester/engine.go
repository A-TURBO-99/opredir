package requester

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/A-TURBO-99/opredir/internal/model"
)

const hardMaxRequests = 5000

// Config controls bounded HTTP execution. Redirect following is always disabled.
type Config struct {
	Concurrency  int
	Delay        time.Duration
	RatePerSec   float64
	Timeout      time.Duration
	MaxRequests  int
	MaxBodyBytes int64
	UserAgent    string
	Headers      http.Header
	Cookies      []string
	ScopeHosts   []string
}

// LoadCases reads newline-delimited JSON test cases, bounded by maxRequests.
func LoadCases(path string, maxRequests int) ([]model.TestCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cases file: %w", err)
	}
	defer f.Close()
	if maxRequests <= 0 || maxRequests > hardMaxRequests {
		return nil, fmt.Errorf("max requests must be between 1 and %d", hardMaxRequests)
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var cases []model.TestCase
	line := 0
	for s.Scan() {
		line++
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var tc model.TestCase
		if err := json.Unmarshal(s.Bytes(), &tc); err != nil {
			return nil, fmt.Errorf("decode case line %d: %w", line, err)
		}
		cases = append(cases, tc)
		if len(cases) >= maxRequests {
			break
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read cases file: %w", err)
	}
	if len(cases) == 0 {
		return nil, errors.New("cases file contains no test cases")
	}
	return cases, nil
}

// ScopeHostsFromCases derives the exact allowed host set from the target_url
// values in a generated case file. Request URLs are still required to retain
// the same scheme, hostname and effective port as their corresponding target.
func ScopeHostsFromCases(cases []model.TestCase) ([]string, error) {
	seen := make(map[string]struct{}, len(cases))
	hosts := make([]string, 0, len(cases))
	for i, tc := range cases {
		u, err := parseHTTPURL(tc.TargetURL)
		if err != nil {
			return nil, fmt.Errorf("case %s target_url: %w", caseLabel(tc, i), err)
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("no target hosts found in test cases")
	}
	return hosts, nil
}

// ValidateConfig enforces bounded execution and a target-derived host scope before
// any network request is sent.
func ValidateConfig(cfg Config) error {
	if len(cfg.ScopeHosts) == 0 {
		return errors.New("at least one target-derived scope host is required for active requests")
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > 100 {
		return errors.New("concurrency must be between 1 and 100")
	}
	if cfg.Delay < 0 || cfg.Delay > time.Hour {
		return errors.New("delay must be between 0 and 1h")
	}
	if math.IsNaN(cfg.RatePerSec) || math.IsInf(cfg.RatePerSec, 0) || cfg.RatePerSec < 0 || cfg.RatePerSec > 100 {
		return errors.New("rate must be between 0 and 100 requests/second; 0 disables the rate cap")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.MaxRequests < 0 || cfg.MaxRequests > hardMaxRequests {
		return fmt.Errorf("max requests must be 0 (unlimited) or between 1 and %d", hardMaxRequests)
	}
	if cfg.MaxBodyBytes < 0 || cfg.MaxBodyBytes > 1024*1024 {
		return errors.New("max body bytes must be between 0 and 1048576")
	}
	for _, rule := range cfg.ScopeHosts {
		rule = strings.TrimSpace(rule)
		if rule == "" || strings.ContainsAny(rule, "/\\@?# 	\r\n") {
			return fmt.Errorf("invalid internal scope rule %q; supply a hostname only", rule)
		}
		if strings.Contains(rule, "*") && (!strings.HasPrefix(rule, "*.") || strings.Count(rule, "*") != 1 || len(rule) <= 2) {
			return fmt.Errorf("invalid wildcard scope rule %q; use *.example.com", rule)
		}
		plainHost := strings.Trim(rule, "[]")
		if !strings.HasPrefix(rule, "*.") && strings.Contains(rule, ":") && net.ParseIP(plainHost) == nil {
			return fmt.Errorf("scope rule %q must not include a port", rule)
		}
	}
	return nil
}

// ValidateCases performs a complete preflight before sending the first request.
func ValidateCases(cases []model.TestCase, cfg Config) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if cfg.MaxRequests > 0 && len(cases) > cfg.MaxRequests {
		return fmt.Errorf("case count %d exceeds configured max requests %d", len(cases), cfg.MaxRequests)
	}
	for i, tc := range cases {
		target, err := parseHTTPURL(tc.TargetURL)
		if err != nil {
			return fmt.Errorf("case %s target_url: %w", caseLabel(tc, i), err)
		}
		reqURL, err := parseHTTPURL(tc.RequestURL)
		if err != nil {
			return fmt.Errorf("case %s request_url: %w", caseLabel(tc, i), err)
		}
		if !sameAuthority(target, reqURL) {
			return fmt.Errorf("case %s rejected: request URL authority differs from target URL", caseLabel(tc, i))
		}
		if !hostInScope(target.Hostname(), cfg.ScopeHosts) {
			return fmt.Errorf("case %s rejected: host %q is not in the supplied scope", caseLabel(tc, i), target.Hostname())
		}
		method := tc.Method
		if method == "" {
			method = http.MethodGet
		}
		if !validMethod(method) {
			return fmt.Errorf("case %s has invalid HTTP method %q", caseLabel(tc, i), method)
		}
	}
	return nil
}

func parseHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("URL must be absolute HTTP(S)")
	}
	if u.User != nil {
		return nil, errors.New("embedded URL credentials are not allowed")
	}
	if u.Fragment != "" {
		return nil, errors.New("fragment must not be present in HTTP request URL")
	}
	return u, nil
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func sameAuthority(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func hostInScope(host string, rules []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, raw := range rules {
		rule := strings.ToLower(strings.TrimSpace(raw))
		if rule == "" {
			continue
		}
		if strings.HasPrefix(rule, "*.") {
			base := strings.TrimSuffix(strings.TrimPrefix(rule, "*."), ".")
			if host != base && strings.HasSuffix(host, "."+base) {
				return true
			}
		} else if host == strings.TrimSuffix(rule, ".") {
			return true
		}
	}
	return false
}

var methodPattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

func validMethod(method string) bool { return methodPattern.MatchString(method) }

func caseLabel(tc model.TestCase, index int) string {
	if tc.CaseID != "" {
		return tc.CaseID
	}
	return fmt.Sprintf("line-%d", index+1)
}

// Run executes cases concurrently, observes a global rate limit and writes one
// response record per case. HTTP redirects are captured, never followed.
func Run(ctx context.Context, cases []model.TestCase, cfg Config, output io.Writer) (int, error) {
	return RunWithCallback(ctx, cases, cfg, output, nil)
}

// RunWithCallback executes cases and invokes onResponse in completion order.
// The callback runs from the single result-consumer goroutine, so callers may
// safely update a live reporter and append findings without additional locks.
func RunWithCallback(ctx context.Context, cases []model.TestCase, cfg Config, output io.Writer, onResponse func(model.ResponseRecord)) (int, error) {
	if err := ValidateCases(cases, cfg); err != nil {
		return 0, err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          cfg.Concurrency * 2,
		MaxIdleConnsPerHost:   cfg.Concurrency,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   cfg.Timeout,
		ExpectContinueTimeout: time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: cfg.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	limiter := newRequestPacer(cfg.Delay, cfg.RatePerSec)
	jobs := make(chan model.TestCase)
	results := make(chan model.ResponseRecord, cfg.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tc := range jobs {
				results <- executeOne(ctx, client, tc, cfg, limiter)
			}
		}()
	}
	go func() {
		for _, tc := range cases {
			jobs <- tc
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	enc := json.NewEncoder(output)
	enc.SetEscapeHTML(false)
	count := 0
	for rec := range results {
		if output != nil {
			if err := enc.Encode(rec); err != nil {
				return count, fmt.Errorf("write response JSONL: %w", err)
			}
		}
		count++
		if onResponse != nil {
			onResponse(rec)
		}
	}
	return count, nil
}

func executeOne(ctx context.Context, client *http.Client, tc model.TestCase, cfg Config, pacer *requestPacer) model.ResponseRecord {
	method := tc.Method
	if method == "" {
		method = http.MethodGet
	}
	rec := model.ResponseRecord{CaseID: tc.CaseID, Method: method, RequestURL: tc.RequestURL, TargetURL: tc.TargetURL, PayloadID: tc.PayloadID, Parameter: tc.Parameter, PayloadResolved: tc.PayloadResolved, PayloadFamilies: tc.PayloadFamilies, RedirectFollowed: false}
	var body io.Reader
	if tc.RequestBody != "" {
		body = strings.NewReader(tc.RequestBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, tc.RequestURL, body)
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	for key, values := range cfg.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if len(cfg.Cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(cfg.Cookies, "; "))
	}
	var remoteAddr string
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if info.Conn != nil {
			remoteAddr = info.Conn.RemoteAddr().String()
		}
	}}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	if err := pacer.Wait(ctx); err != nil {
		rec.Error = err.Error()
		return rec
	}
	start := time.Now()
	resp, err := client.Do(req)
	rec.RemoteAddress = remoteAddr
	if err != nil {
		rec.DurationMS = time.Since(start).Milliseconds()
		rec.Error = err.Error()
		return rec
	}
	defer resp.Body.Close()
	rec.StatusCode, rec.Status = resp.StatusCode, resp.Status
	rec.Location = resp.Header.Get("Location")
	rec.Headers = selectedHeaders(resp.Header)
	if cfg.MaxBodyBytes > 0 {
		limited := io.LimitReader(resp.Body, cfg.MaxBodyBytes+1)
		b, readErr := io.ReadAll(limited)
		rec.BodyBytesRead = int64(len(b))
		if int64(len(b)) > cfg.MaxBodyBytes {
			rec.BodyTruncated = true
			b = b[:cfg.MaxBodyBytes]
		}
		if len(b) > 0 {
			rec.BodyPreview = string(b)
		}
		if readErr != nil {
			rec.Error = "response body read: " + readErr.Error()
		}
	} else {
		// Drain a small bounded amount to improve keep-alive reuse without storing body data.
		n, _ := io.CopyN(io.Discard, resp.Body, 64*1024)
		rec.BodyBytesRead = n
	}
	rec.DurationMS = time.Since(start).Milliseconds()
	return rec
}

func selectedHeaders(h http.Header) map[string]string {
	allow := []string{"Content-Type", "Location", "Cache-Control", "Server", "Via", "Refresh", "X-Redirect-By", "X-Powered-By"}
	out := make(map[string]string)
	for _, key := range allow {
		if v := h.Values(key); len(v) > 0 {
			out[http.CanonicalHeaderKey(key)] = strings.Join(v, ", ")
		}
	}
	return out
}

// requestPacer applies one global minimum interval between request starts.
// When --rate is also supplied, the stricter (larger) interval wins.
type requestPacer struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newRequestPacer(delay time.Duration, rate float64) *requestPacer {
	interval := delay
	if rate > 0 {
		rateInterval := time.Duration(float64(time.Second) / rate)
		if rateInterval > interval {
			interval = rateInterval
		}
	}
	return &requestPacer{interval: interval}
}

func (r *requestPacer) Wait(ctx context.Context) error {
	if r == nil || r.interval <= 0 {
		return nil
	}
	r.mu.Lock()
	now := time.Now()
	scheduled := r.next
	if scheduled.Before(now) {
		scheduled = now
	}
	r.next = scheduled.Add(r.interval)
	r.mu.Unlock()
	delay := time.Until(scheduled)
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ParseHeaderFlags converts repeated "Name: value" options into safe HTTP headers.
func ParseHeaderFlags(values []string) (http.Header, error) {
	h := make(http.Header)
	for _, raw := range values {
		name, value, ok := strings.Cut(raw, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid header %q; expected 'Name: value'", raw)
		}
		if strings.EqualFold(name, "Host") || strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") || strings.EqualFold(name, "Cookie") {
			return nil, fmt.Errorf("header %q cannot be overridden; use --cookie for cookies", name)
		}
		if strings.ContainsAny(name+value, "\r\n") {
			return nil, errors.New("header names and values must not contain CR/LF")
		}
		if !validHeaderName(name) {
			return nil, fmt.Errorf("invalid header name %q", name)
		}
		h.Add(http.CanonicalHeaderKey(name), value)
	}
	return h, nil
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}
