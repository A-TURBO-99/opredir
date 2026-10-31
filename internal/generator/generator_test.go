package generator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/A-TURBO-99/opredir/internal/model"
)

func TestBuildRequestURLReplacesDuplicateKeysAndPreservesOthers(t *testing.T) {
	got, encoded, count, mode, dropped, err := BuildRequestURL("https://target.example/path?x=1&next=old&next=older&y=2#frag", "next", "https://marker.example/a b", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || mode != "replace-all" || !dropped {
		t.Fatalf("unexpected metadata: count=%d mode=%s dropped=%v", count, mode, dropped)
	}
	if encoded != "https%3A%2F%2Fmarker.example%2Fa%20b" {
		t.Fatalf("unexpected encoding: %s", encoded)
	}
	if !strings.Contains(got, "x=1&next="+encoded+"&next="+encoded+"&y=2") {
		t.Fatalf("query not preserved/replaced: %s", got)
	}
	if strings.Contains(got, "#frag") {
		t.Fatalf("fragment must be omitted: %s", got)
	}
}

func TestBuildRequestURLAppendMissingKey(t *testing.T) {
	got, _, count, mode, _, err := BuildRequestURL("http://127.0.0.1:5000/redirect?keep=1", "url", "https://marker.invalid", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || mode != "append" || !strings.Contains(got, "keep=1&url=https%3A%2F%2Fmarker.invalid") {
		t.Fatalf("unexpected result: %s (%s, %d)", got, mode, count)
	}
}

func TestResolvePlaceholders(t *testing.T) {
	got, missing := ResolvePlaceholders("https://{{ATTACKER_HOST}}/{{MISSING}}", map[string]string{"ATTACKER_HOST": "marker.example"})
	if got != "https://marker.example/{{MISSING}}" || len(missing) != 1 || missing[0] != "MISSING" {
		t.Fatalf("got %q missing %#v", got, missing)
	}
}

func TestGenerateFromRecord(t *testing.T) {
	payload := model.PayloadRecord{ID: "P1", Payload: "https://evil.invalid", RuntimeValue: "https://{{ATTACKER_HOST}}", RecordType: "url_value_candidate", Families: []string{"direct"}}
	cases, stats, err := Generate([]string{"http://127.0.0.1:5000/redirect"}, []string{"url", "next"}, []model.PayloadRecord{payload}, map[string]string{"ATTACKER_HOST": "marker.invalid"}, "auto", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 || stats["generated"] != 2 {
		t.Fatalf("unexpected cases/stats: %d %#v", len(cases), stats)
	}
	if cases[0].PayloadID != "P1" || !strings.Contains(cases[0].RequestURL, "url=https%3A%2F%2Fmarker.invalid") {
		t.Fatalf("unexpected generated case: %#v", cases[0])
	}
}

func TestLoadRealCorpus(t *testing.T) {
	path := filepath.Join("..", "..", "data", "payloads", "url_value_candidates.json")
	if _, err := os.Stat(path); err != nil {
		t.Skip("project corpus unavailable in isolated test")
	}
	payloads, err := LoadPayloads(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 724 {
		t.Fatalf("expected 724 records, got %d", len(payloads))
	}
}
