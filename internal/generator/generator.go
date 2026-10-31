package generator

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/A-TURBO-99/opredir/internal/model"
)

var placeholderPattern = regexp.MustCompile(`\{\{([A-Z0-9_]+)\}\}`)

// LoadParameters reads one parameter name per line and removes exact duplicates.
func LoadParameters(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open parameter file: %w", err)
	}
	defer f.Close()
	seen := make(map[string]struct{})
	var values []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		v := strings.TrimSpace(strings.TrimPrefix(s.Text(), "\ufeff"))
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		values = append(values, v)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read parameter file: %w", err)
	}
	if len(values) == 0 {
		return nil, errors.New("parameter file contains no names")
	}
	return values, nil
}

// LoadPayloads reads only records eligible for Query-Parameter URL-value tests.
func LoadPayloads(path string, families map[string]bool) ([]model.PayloadRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read payload corpus: %w", err)
	}
	var corpus model.PayloadCorpus
	if err := json.Unmarshal(b, &corpus); err != nil {
		return nil, fmt.Errorf("decode payload corpus: %w", err)
	}
	var out []model.PayloadRecord
	for _, rec := range corpus.Records {
		if rec.RecordType != "url_value_candidate" {
			continue
		}
		if len(families) > 0 {
			matched := false
			for _, family := range rec.Families {
				if families[family] {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, errors.New("no eligible URL-value candidates matched selection")
	}
	return out, nil
}

// ResolvePlaceholders replaces {{NAME}} tokens and reports missing variables.
func ResolvePlaceholders(value string, variables map[string]string) (string, []string) {
	missingSet := make(map[string]struct{})
	resolved := placeholderPattern.ReplaceAllStringFunc(value, func(token string) string {
		match := placeholderPattern.FindStringSubmatch(token)
		if len(match) != 2 {
			return token
		}
		v, ok := variables[match[1]]
		if !ok || strings.TrimSpace(v) == "" {
			missingSet[match[1]] = struct{}{}
			return token
		}
		return v
	})
	missing := make([]string, 0, len(missingSet))
	for k := range missingSet {
		missing = append(missing, k)
	}
	// Stable ordering makes generated output reproducible.
	for i := 0; i < len(missing); i++ {
		for j := i + 1; j < len(missing); j++ {
			if missing[j] < missing[i] {
				missing[i], missing[j] = missing[j], missing[i]
			}
		}
	}
	return resolved, missing
}

func ValidateTargetURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", raw, err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("target must be an absolute HTTP(S) URL: %q", raw)
	}
	if u.User != nil {
		return nil, errors.New("target URL must not contain embedded credentials")
	}
	if strings.ContainsAny(u.Host, "\r\n\t ") {
		return nil, errors.New("target URL contains whitespace/control characters in authority")
	}
	return u, nil
}

// BuildRequestURL inserts a query parameter while preserving unrelated raw
// query segments and duplicate keys. The new value is encoded exactly once.
func BuildRequestURL(target, parameter, value, mode string) (string, string, int, string, bool, error) {
	u, err := ValidateTargetURL(target)
	if err != nil {
		return "", "", 0, "", false, err
	}
	segments := []string{}
	if u.RawQuery != "" {
		segments = strings.Split(u.RawQuery, "&")
	}
	var matches []int
	for i, segment := range segments {
		rawKey := strings.SplitN(segment, "=", 2)[0]
		decoded, decErr := url.QueryUnescape(rawKey)
		if decErr == nil && decoded == parameter {
			matches = append(matches, i)
		}
	}
	effective := mode
	if mode == "auto" {
		if len(matches) > 0 {
			effective = "replace-all"
		} else {
			effective = "append"
		}
	}
	key := encodeQueryComponent(parameter)
	encoded := encodeQueryComponent(value)
	switch effective {
	case "append":
		segments = append(segments, key+"="+encoded)
	case "replace-all":
		if len(matches) == 0 {
			segments = append(segments, key+"="+encoded)
		} else {
			for _, i := range matches {
				rawKey := strings.SplitN(segments[i], "=", 2)[0]
				segments[i] = rawKey + "=" + encoded
			}
		}
	case "replace-first":
		if len(matches) == 0 {
			segments = append(segments, key+"="+encoded)
		} else {
			i := matches[0]
			rawKey := strings.SplitN(segments[i], "=", 2)[0]
			segments[i] = rawKey + "=" + encoded
		}
	default:
		return "", "", 0, "", false, fmt.Errorf("unsupported placement mode %q", mode)
	}
	u.RawQuery = strings.Join(segments, "&")
	fragmentDropped := u.Fragment != "" || u.RawFragment != ""
	u.Fragment, u.RawFragment = "", ""
	return u.String(), encoded, len(matches), effective, fragmentDropped, nil
}

func encodeQueryComponent(value string) string {
	// QueryEscape is RFC 3986-compatible for this purpose except spaces use '+'.
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

// Generate builds JSONL-ready cases. maxCases <= 0 means no generated cases.
func Generate(targets, parameters []string, payloads []model.PayloadRecord, variables map[string]string, mode string, maxCases int) ([]model.TestCase, map[string]int, error) {
	stats := map[string]int{"generated": 0, "skipped_missing_placeholders": 0, "skipped_invalid_targets": 0}
	var out []model.TestCase
	for _, target := range targets {
		if _, err := ValidateTargetURL(target); err != nil {
			stats["skipped_invalid_targets"] += len(parameters) * len(payloads)
			continue
		}
		for _, payload := range payloads {
			raw := payload.RuntimeValue
			if raw == "" {
				raw = payload.TemplatedPayload
			}
			if raw == "" {
				raw = payload.Payload
			}
			resolved, missing := ResolvePlaceholders(raw, variables)
			if len(missing) > 0 {
				stats["skipped_missing_placeholders"] += len(parameters)
				continue
			}
			for _, parameter := range parameters {
				if maxCases > 0 && stats["generated"] >= maxCases {
					return out, stats, nil
				}
				requestURL, encoded, occurrences, placement, fragmentDropped, err := BuildRequestURL(target, parameter, resolved, mode)
				if err != nil {
					stats["skipped_invalid_targets"]++
					continue
				}
				caseID := fmt.Sprintf("OR-GEN-%07d", stats["generated"]+1)
				out = append(out, model.TestCase{
					CaseID: caseID, Method: "GET", TargetURL: target, RequestURL: requestURL,
					Parameter: parameter, ParameterLocation: "query", PayloadID: payload.ID,
					PayloadRaw: payload.Payload, PayloadTemplate: raw, PayloadResolved: resolved,
					PayloadFamilies: payload.Families, PayloadSources: payload.Sources,
					Transformation:   "none; query component percent-encoded once by request builder",
					EncodedValueOnce: encoded, PlacementMode: placement,
					ExistingParameterOccurrences: occurrences, FragmentDropped: fragmentDropped,
					Status: "generated_not_sent",
				})
				stats["generated"]++
			}
		}
	}
	return out, stats, nil
}
