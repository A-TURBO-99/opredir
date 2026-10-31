package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/A-TURBO-99/opredir/internal/model"
)

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	callErr := fn()
	_ = w.Close()
	os.Stdout = old
	b, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(b), callErr
}

func TestScanStreamsConfirmedFindingAndWritesDetailedReport(t *testing.T) {
	const destination = "https://redirect-marker.invalid/landing"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("amr"); got != destination {
			t.Errorf("payload mismatch: got %q want %q", got, destination)
		}
		w.Header().Set("Location", destination)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	corpus := model.PayloadCorpus{
		Name: "integration-test", RecordType: "url_value_candidate", Count: 1,
		Records: []model.PayloadRecord{{
			ID: "TEST-1", Payload: destination, RuntimeValue: destination,
			RecordType: "url_value_candidate", Families: []string{"http_https_scheme_or_absolute_url"},
		}},
	}
	corpusBytes, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(dir, "corpus.json")
	if err := os.WriteFile(corpusPath, corpusBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "detailed-report.json")

	output, err := captureStdout(t, func() error {
		return runScan([]string{
			"-d", srv.URL + "/redirect", "-dl", "0s", "-t", "2",
			"-o", reportPath, "-param", "amr",
			"--corpus", corpusPath, "--max-cases", "1",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "opredir v0.4.3 — Open Redirect Scanner") {
		t.Fatalf("banner missing from standard output: %s", output)
	}
	if !strings.Contains(output, "VULNERABLE") || !strings.Contains(output, destination) {
		t.Fatalf("confirmed finding missing from standard output: %s", output)
	}

	b, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		ConfirmedFindingsCount int `json:"confirmed_findings_count"`
		ConfirmedFindings      []struct {
			Classification      string `json:"classification"`
			Parameter           string `json:"parameter"`
			PayloadResolved     string `json:"payload_resolved"`
			StatusCode          int    `json:"status_code"`
			ResolvedDestination string `json:"resolved_destination"`
		} `json:"confirmed_findings"`
	}
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	if report.ConfirmedFindingsCount != 1 || len(report.ConfirmedFindings) != 1 {
		t.Fatalf("expected exactly one confirmed finding: %s", b)
	}
	finding := report.ConfirmedFindings[0]
	if finding.Classification != "confirmed_open_redirect" || finding.Parameter != "amr" || finding.PayloadResolved != destination || finding.StatusCode != http.StatusFound || finding.ResolvedDestination != destination {
		t.Fatalf("incomplete finding evidence: %#v", finding)
	}
}

func TestRemovedFlagsAreNotAcceptedByScan(t *testing.T) {
	for _, flagName := range []string{"--authorized", "--scope-host", "--verbose"} {
		err := runScan([]string{"-d", "https://example.test", flagName})
		if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("expected %s to be removed, got %v", flagName, err)
		}
	}
}

func TestRemovedFlagsAreNotAcceptedByRequestCommand(t *testing.T) {
	for _, flagName := range []string{"--authorized", "--scope-host"} {
		err := runRequest([]string{flagName})
		if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("expected %s to be removed from request command, got %v", flagName, err)
		}
	}
}
