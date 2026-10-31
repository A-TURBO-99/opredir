// Package targets normalizes user-supplied domains, subdomains and endpoint lists.
package targets

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/A-TURBO-99/opredir/internal/generator"
)

const maxTargets = 2000

// Normalize converts a bare hostname or URL into an absolute HTTP(S) endpoint.
// Bare host/path entries default to HTTPS. To use HTTP or a non-default port,
// supply an explicit scheme, e.g. http://127.0.0.1:5000/redirect.
func Normalize(raw string) (string, string, error) {
	v := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if v == "" {
		return "", "", errors.New("empty target")
	}
	if strings.ContainsAny(v, "\r\n\t ") {
		return "", "", fmt.Errorf("target %q contains whitespace", raw)
	}
	if !strings.Contains(v, "://") {
		v = "https://" + v
	}
	u, err := generator.ValidateTargetURL(v)
	if err != nil {
		return "", "", err
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), nil
}

// FromDomain creates one target from -u. A URL can be supplied to include a
// path or explicit scheme/port; otherwise HTTPS is assumed.
func FromDomain(domain string) ([]string, []string, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, nil, errors.New("-u/--domain requires a domain or URL")
	}
	target, host, err := Normalize(domain)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid -u target: %w", err)
	}
	return []string{target}, []string{host}, nil
}

// FromList loads subdomains or full endpoint URLs, one per line. Bare
// subdomain names default to HTTPS; duplicates are removed without reordering.
func FromList(path string) ([]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open -l target list: %w", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	seenTargets := make(map[string]struct{})
	seenHosts := make(map[string]struct{})
	var targetList, scopeHosts []string
	line := 0
	for s.Scan() {
		line++
		entry := strings.TrimSpace(strings.TrimPrefix(s.Text(), "\ufeff"))
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		target, host, err := Normalize(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid target on -l line %d: %w", line, err)
		}
		if _, ok := seenTargets[target]; !ok {
			seenTargets[target] = struct{}{}
			targetList = append(targetList, target)
		}
		if _, ok := seenHosts[host]; !ok {
			seenHosts[host] = struct{}{}
			scopeHosts = append(scopeHosts, host)
		}
		if len(targetList) > maxTargets {
			return nil, nil, fmt.Errorf("target list exceeds the maximum of %d entries", maxTargets)
		}
	}
	if err := s.Err(); err != nil {
		return nil, nil, fmt.Errorf("read -l target list: %w", err)
	}
	if len(targetList) == 0 {
		return nil, nil, errors.New("-l target list contains no usable targets")
	}
	return targetList, scopeHosts, nil
}

// IsAbsoluteHTTPURL reports whether a line has an explicit HTTP(S) scheme.
func IsAbsoluteHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}
