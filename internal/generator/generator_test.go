package generator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/A-TURBO-99/opredir/internal/model"
)

func TestBuildRequestURLReplacesDuplicateKeysAndPreservesOthers(t *testing.T) {
	got, encoded, count, mode, dropped, err := BuildRequestURL("https://target.example/path?x=1&next=old&next=older&y=2#frag", "next", "https://marker.example/a b")
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
	got, _, count, mode, _, err := BuildRequestURL("http://127.0.0.1:5000/redirect?keep=1", "url", "https://marker.invalid")
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
	cases, stats, err := Generate([]string{"http://127.0.0.1:5000/redirect"}, []string{"url", "next"}, []model.PayloadRecord{payload}, map[string]string{"ATTACKER_HOST": "marker.invalid"})
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
	payloads, err := LoadPayloads(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 724 {
		t.Fatalf("expected 724 records, got %d", len(payloads))
	}
}

func TestLoadParameterSelectionAcceptsSingleName(t *testing.T) {
	got, err := LoadParameterSelection("inject", "missing-default-parameters.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "inject" {
		t.Fatalf("unexpected parameter selection: %#v", got)
	}
}

func TestLoadParameterSelectionAcceptsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "selected.txt")
	if err := os.WriteFile(path, []byte("inject\nnext\n# comment\ninject\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadParameterSelection(path, "missing-default-parameters.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "inject" || got[1] != "next" {
		t.Fatalf("unexpected parameter file contents: %#v", got)
	}
}

func TestLoadParameterSelectionUsesDefaultWhenOmitted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defaults.txt")
	if err := os.WriteFile(path, []byte("next\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadParameterSelection("", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "next" {
		t.Fatalf("unexpected default parameter selection: %#v", got)
	}
}

func TestSelectPayloadLevelsAreCumulative(t *testing.T) {
	payloads := make([]model.PayloadRecord, 724)
	for i := range payloads {
		payloads[i].ID = fmt.Sprintf("P-%03d", i+1)
	}
	cases := []struct {
		level int
		want  int
	}{{1, 242}, {2, 483}, {3, 724}}
	for _, tc := range cases {
		got, err := SelectPayloadLevel(payloads, tc.level)
		if err != nil {
			t.Fatalf("level %d: %v", tc.level, err)
		}
		if len(got) != tc.want {
			t.Fatalf("level %d: got %d payloads, want %d", tc.level, len(got), tc.want)
		}
		if len(got) > 0 && got[0].ID != "P-001" {
			t.Fatalf("level %d is not cumulative from the first payload", tc.level)
		}
	}
	if _, err := SelectPayloadLevel(payloads, 0); err == nil {
		t.Fatal("expected invalid level to be rejected")
	}
}
