package targets

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizeBareDomainAndExplicitURL(t *testing.T) {
	got, host, err := Normalize("api.example.test/path")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://api.example.test/path" || host != "api.example.test" {
		t.Fatalf("unexpected normalized target %q host %q", got, host)
	}
	got, host, err = Normalize("http://127.0.0.1:5000/redirect")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:5000/redirect" || host != "127.0.0.1" {
		t.Fatalf("unexpected explicit target %q host %q", got, host)
	}
}

func TestFromListSubdomainsAndEndpoints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := "# assets\napi.example.test\nhttps://www.example.test/login\napi.example.test\nhttp://127.0.0.1:5000/redirect\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	gotTargets, gotHosts, err := FromList(path)
	if err != nil {
		t.Fatal(err)
	}
	wantTargets := []string{"https://api.example.test/", "https://www.example.test/login", "http://127.0.0.1:5000/redirect"}
	wantHosts := []string{"api.example.test", "www.example.test", "127.0.0.1"}
	if !reflect.DeepEqual(gotTargets, wantTargets) || !reflect.DeepEqual(gotHosts, wantHosts) {
		t.Fatalf("targets=%#v hosts=%#v", gotTargets, gotHosts)
	}
}
