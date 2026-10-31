package requester

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/A-TURBO-99/opredir/internal/model"
)

func testConfig(host string) Config {
	return Config{Concurrency: 2, RatePerSec: 100, Timeout: 2 * time.Second, MaxRequests: 10, MaxBodyBytes: 8, UserAgent: "opredir-test", ScopeHosts: []string{host}, Headers: make(http.Header)}
}

func TestRunCapturesRedirectWithoutFollowing(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Test") != "present" {
			t.Errorf("custom header missing")
		}
		w.Header().Set("Location", "https://outside.invalid/landing")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("redirect response body"))
	}))
	defer srv.Close()
	cfg := testConfig("127.0.0.1")
	cfg.Headers.Set("X-Test", "present")
	cases := []model.TestCase{{CaseID: "case-1", Method: "GET", TargetURL: srv.URL + "/redirect", RequestURL: srv.URL + "/redirect", PayloadID: "p1", Parameter: "next"}}
	var out strings.Builder
	count, err := Run(context.Background(), cases, cfg, &out)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || hits.Load() != 1 {
		t.Fatalf("count=%d hits=%d", count, hits.Load())
	}
	if !strings.Contains(out.String(), `"status_code":302`) || !strings.Contains(out.String(), `"location":"https://outside.invalid/landing"`) {
		t.Fatalf("response evidence missing: %s", out.String())
	}
	if !strings.Contains(out.String(), `"body_truncated":true`) {
		t.Fatalf("expected bounded body preview: %s", out.String())
	}
}

func TestRunWithCallbackReceivesResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := testConfig("127.0.0.1")
	cases := []model.TestCase{{CaseID: "callback-1", TargetURL: srv.URL, RequestURL: srv.URL}}
	called := 0
	count, err := RunWithCallback(context.Background(), cases, cfg, nil, func(rec model.ResponseRecord) {
		called++
		if rec.CaseID != "callback-1" || rec.StatusCode != http.StatusOK {
			t.Errorf("unexpected callback response: %#v", rec)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || called != 1 {
		t.Fatalf("count=%d callback calls=%d", count, called)
	}
}

func TestValidateConfigDoesNotRequireCLIAuthorizationFlag(t *testing.T) {
	cfg := testConfig("127.0.0.1")
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("target-derived scope should be sufficient: %v", err)
	}
}

func TestScopeHostsFromCases(t *testing.T) {
	cases := []model.TestCase{
		{TargetURL: "https://example.com/path", RequestURL: "https://example.com/path"},
		{TargetURL: "https://api.example.com/", RequestURL: "https://api.example.com/"},
		{TargetURL: "https://example.com/other", RequestURL: "https://example.com/other"},
	}
	hosts, err := ScopeHostsFromCases(cases)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0] != "example.com" || hosts[1] != "api.example.com" {
		t.Fatalf("unexpected derived hosts: %#v", hosts)
	}
}

func TestValidateCasesRejectsOutOfScopeHost(t *testing.T) {
	cfg := testConfig("example.com")
	cases := []model.TestCase{{CaseID: "bad", TargetURL: "http://127.0.0.1/", RequestURL: "http://127.0.0.1/"}}
	if err := ValidateCases(cases, cfg); err == nil || !strings.Contains(err.Error(), "not in the supplied scope") {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}

func TestValidateCasesRejectsAuthorityChange(t *testing.T) {
	cfg := testConfig("example.com")
	cases := []model.TestCase{{CaseID: "bad", TargetURL: "https://example.com/path", RequestURL: "https://other.example/path"}}
	if err := ValidateCases(cases, cfg); err == nil || !strings.Contains(err.Error(), "authority differs") {
		t.Fatalf("expected authority rejection, got %v", err)
	}
}

func TestWildcardScope(t *testing.T) {
	if !hostInScope("api.example.com", []string{"*.example.com"}) {
		t.Fatal("subdomain should match wildcard")
	}
	if hostInScope("example.com", []string{"*.example.com"}) {
		t.Fatal("wildcard must not match apex")
	}
}

func TestHeaderParserRejectsHostOverride(t *testing.T) {
	if _, err := ParseHeaderFlags([]string{"Host: other.example"}); err == nil {
		t.Fatal("expected Host override to be rejected")
	}
	if _, err := ParseHeaderFlags([]string{"X-Test: okay"}); err != nil {
		t.Fatal(err)
	}
}
