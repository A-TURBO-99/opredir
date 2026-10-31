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

// LoadParameterSelection accepts either one literal parameter name or a path
// to a parameter file. An existing regular file is loaded as a wordlist;
// otherwise the value is treated as one parameter name. A missing path is
// inherently ambiguous with a literal parameter name, so only existing files
// are interpreted as wordlists.
func LoadParameterSelection(selection, defaultPath string) ([]string, error) {
	selection = strings.TrimSpace(selection)
	if selection == "" {
		return LoadParameters(defaultPath)
	}
	info, err := os.Stat(selection)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("parameter selection %q is not a regular file", selection)
		}
		return LoadParameters(selection)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect parameter selection %q: %w", selection, err)
	}
	if selection == "." || selection == ".." || strings.ContainsAny(selection, "\r\n\x00") {
		return nil, fmt.Errorf("invalid parameter name %q", selection)
	}
	return []string{selection}, nil
}

// LoadPayloads reads only records eligible for Query-Parameter URL-value tests.
func LoadPayloads(path string) ([]model.PayloadRecord, error) {
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
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, errors.New("no eligible URL-value candidates found")
	}
	return out, nil
}

// SelectPayloadLevel returns an ordered prefix of the corpus. Levels are
// cumulative: level 1 selects the first third, level 2 the first two thirds,
// and level 3 the complete corpus. Rounding is upward so every level includes
// its full requested fraction.
func SelectPayloadLevel(payloads []model.PayloadRecord, level int) ([]model.PayloadRecord, error) {
	if level < 1 || level > 3 {
		return nil, errors.New("level must be 1, 2, or 3")
	}
	count := (len(payloads)*level + 2) / 3
	if count > len(payloads) {
		count = len(payloads)
	}
	selected := make([]model.PayloadRecord, count)
	copy(selected, payloads[:count])
	return selected, nil
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
func BuildRequestURL(target, parameter, value string) (string, string, int, string, bool, error) {
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

	strategy := "append"
	key := encodeQueryComponent(parameter)
	encoded := encodeQueryComponent(value)
	if len(matches) == 0 {
		segments = append(segments, key+"="+encoded)
	} else {
		strategy = "replace-all"
		for _, i := range matches {
			rawKey := strings.SplitN(segments[i], "=", 2)[0]
			segments[i] = rawKey + "=" + encoded
		}
	}
	u.RawQuery = strings.Join(segments, "&")
	fragmentDropped := u.Fragment != "" || u.RawFragment != ""
	u.Fragment, u.RawFragment = "", ""
	return u.String(), encoded, len(matches), strategy, fragmentDropped, nil
}

func encodeQueryComponent(value string) string {
	// QueryEscape is RFC 3986-compatible for this purpose except spaces use '+'.
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

// Generate builds every eligible JSONL-ready test case for the supplied
// targets, parameters and payloads. Request-count selection is handled by
// payload levels before generation, not by an arbitrary case cap.
func Generate(targets, parameters []string, payloads []model.PayloadRecord, variables map[string]string) ([]model.TestCase, map[string]int, error) {
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
				requestURL, encoded, occurrences, strategy, fragmentDropped, err := BuildRequestURL(target, parameter, resolved)
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
					EncodedValueOnce: encoded, PlacementStrategy: strategy,
					ExistingParameterOccurrences: occurrences, FragmentDropped: fragmentDropped,
					Status: "generated_not_sent",
				})
				stats["generated"]++
			}
		}
	}
	return out, stats, nil
}
