// Package verifier classifies captured HTTP responses without following redirects.
package verifier

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/A-TURBO-99/opredir/internal/model"
)

// FindingClass is deliberately conservative: only a redirect whose destination
// matches the externally supplied test value is marked confirmed.
type FindingClass string

const (
	ConfirmedOpenRedirect       FindingClass = "confirmed_open_redirect"
	ConfirmedRefreshRedirect    FindingClass = "confirmed_refresh_redirect"
	SameOriginRedirect          FindingClass = "same_origin_redirect"
	SameHostRedirect            FindingClass = "same_host_redirect"
	ExternalRedirectUnconfirmed FindingClass = "external_redirect_unconfirmed"
	ClientSideCandidate         FindingClass = "client_side_redirect_candidate"
	ReflectedInputOnly          FindingClass = "reflected_input_only"
	NoRedirectObserved          FindingClass = "no_redirect_observed"
	RequestError                FindingClass = "request_error"
	InvalidLocation             FindingClass = "invalid_location"
	RedirectWithoutLocation     FindingClass = "redirect_without_location"
)

type Finding struct {
	CaseID              string       `json:"case_id"`
	Classification      FindingClass `json:"classification"`
	Confirmed           bool         `json:"confirmed"`
	Confidence          string       `json:"confidence"`
	EvidenceType        string       `json:"evidence_type,omitempty"`
	TargetURL           string       `json:"target_url"`
	RequestURL          string       `json:"request_url"`
	Parameter           string       `json:"parameter,omitempty"`
	PayloadID           string       `json:"payload_id,omitempty"`
	PayloadFamilies     []string     `json:"payload_families,omitempty"`
	PayloadResolved     string       `json:"payload_resolved,omitempty"`
	StatusCode          int          `json:"status_code,omitempty"`
	Location            string       `json:"location,omitempty"`
	ResolvedDestination string       `json:"resolved_destination,omitempty"`
	ExpectedDestination string       `json:"expected_destination,omitempty"`
	Reason              string       `json:"reason"`
	RedirectFollowed    bool         `json:"redirect_followed"`
}

// VerifyRecord evaluates one response. It resolves relative Location values
// against the request URL and only confirms a finding when the response
// destination's origin matches the external destination supplied in the test.
func VerifyRecord(rec model.ResponseRecord) Finding {
	f := Finding{
		CaseID: rec.CaseID, TargetURL: rec.TargetURL, RequestURL: rec.RequestURL,
		Parameter: rec.Parameter, PayloadID: rec.PayloadID,
		PayloadFamilies: rec.PayloadFamilies, PayloadResolved: rec.PayloadResolved, StatusCode: rec.StatusCode,
		Location: rec.Location, RedirectFollowed: rec.RedirectFollowed,
		Confidence: "none",
	}
	if rec.Error != "" {
		f.Classification, f.Reason = RequestError, "The HTTP request did not complete successfully: "+rec.Error
		return f
	}
	base, baseErr := url.Parse(rec.RequestURL)
	if baseErr != nil || base.Scheme == "" || base.Hostname() == "" {
		f.Classification, f.Reason = InvalidLocation, "The recorded request URL is not a valid absolute URL."
		return f
	}
	expected, expectedOK := expectedDestination(base, rec.PayloadResolved)
	if expectedOK {
		f.ExpectedDestination = expected.String()
	}

	if isRedirectStatus(rec.StatusCode) && strings.TrimSpace(rec.Location) != "" {
		loc, err := resolveDestination(base, rec.Location)
		if err != nil {
			f.Classification, f.Reason = InvalidLocation, "The response contains a Location value that could not be parsed: "+err.Error()
			return f
		}
		f.ResolvedDestination = loc.String()
		if sameOrigin(base, loc) {
			f.Classification, f.Reason = SameOriginRedirect, "The response redirects to the same origin; this response alone does not demonstrate an external redirect."
			return f
		}
		if sameHost(base, loc) {
			f.Classification, f.Reason = SameHostRedirect, "The destination uses the same hostname, although its scheme or port may differ. This is not treated as an external Open Redirect."
			return f
		}
		if expectedOK && sameHost(expected, loc) && !sameHost(base, expected) {
			f.Classification, f.Confirmed, f.Confidence = ConfirmedOpenRedirect, true, "high"
			f.EvidenceType = "location-header"
			f.Reason = "A 3xx Location destination matches the external origin supplied in the tested parameter."
			return f
		}
		f.Classification, f.Confidence = ExternalRedirectUnconfirmed, "low"
		f.EvidenceType = "location-header"
		f.Reason = "The response redirects to another origin, but the destination could not be correlated with the supplied test value. Review manually; this may be a fixed application redirect."
		return f
	}

	// Refresh is a browser-recognized navigation header. Treat a matching
	// external destination as a confirmed redirect mechanism, but distinguish it
	// from the conventional HTTP Location response.
	if refresh := headerValue(rec.Headers, "Refresh"); refresh != "" {
		if refreshURL, err := parseRefreshDestination(base, refresh); err == nil && !sameHost(base, refreshURL) {
			f.ResolvedDestination = refreshURL.String()
			if expectedOK && sameHost(expected, refreshURL) && !sameHost(base, expected) {
				f.Classification, f.Confirmed, f.Confidence = ConfirmedRefreshRedirect, true, "high"
				f.EvidenceType = "refresh-header"
				f.Reason = "The Refresh response header directs the browser to the external origin supplied in the tested parameter."
				return f
			}
			f.Classification, f.Confidence = ExternalRedirectUnconfirmed, "low"
			f.EvidenceType = "refresh-header"
			f.Reason = "The Refresh header references an external destination, but it does not match the supplied test destination."
			return f
		}
	}

	if isRedirectStatus(rec.StatusCode) && strings.TrimSpace(rec.Location) == "" {
		f.Classification, f.Reason = RedirectWithoutLocation, "The response uses a redirect status but provides no Location header; this is not sufficient evidence of an external redirect."
		return f
	}

	body := rec.BodyPreview
	if looksLikeClientNavigation(body, rec.PayloadResolved) {
		f.Classification, f.Confidence = ClientSideCandidate, "low"
		f.EvidenceType = "body-navigation-signal"
		f.Reason = "The response body contains the test destination and a possible navigation construct. Browser-based verification is required; this is not confirmed."
		return f
	}
	if rec.PayloadResolved != "" && strings.Contains(body, rec.PayloadResolved) {
		f.Classification, f.Confidence = ReflectedInputOnly, "info"
		f.Reason = "The tested value appears in the response body, but no external navigation was demonstrated. Reflection is not proof of Open Redirect."
		return f
	}
	f.Classification, f.Reason = NoRedirectObserved, "No external HTTP redirect was observed in the captured response. Client-side behavior may require a browser-based module."
	return f
}

func expectedDestination(base *url.URL, raw string) (*url.URL, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, false
	}
	resolved := base.ResolveReference(u)
	if resolved.Scheme == "" || resolved.Hostname() == "" || (resolved.Scheme != "http" && resolved.Scheme != "https") {
		return nil, false
	}
	return resolved, true
}

func resolveDestination(base *url.URL, raw string) (*url.URL, error) {
	loc, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	resolved := base.ResolveReference(loc)
	if resolved.Scheme == "" || resolved.Hostname() == "" || (resolved.Scheme != "http" && resolved.Scheme != "https") {
		return nil, errors.New("Location does not resolve to an absolute HTTP(S) URL")
	}
	return resolved, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && normalizeHost(a.Hostname()) == normalizeHost(b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func sameHost(a, b *url.URL) bool {
	return normalizeHost(a.Hostname()) == normalizeHost(b.Hostname())
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

func isRedirectStatus(code int) bool {
	switch code {
	case 300, 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

var refreshURLPattern = regexp.MustCompile(`(?i)^\s*\d+(?:\.\d+)?\s*;\s*url\s*=\s*['"]?([^'"]+)['"]?\s*$`)

func parseRefreshDestination(base *url.URL, raw string) (*url.URL, error) {
	m := refreshURLPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if len(m) != 2 {
		return nil, errors.New("unsupported Refresh header format")
	}
	return resolveDestination(base, strings.TrimSpace(m[1]))
}

func looksLikeClientNavigation(body, payload string) bool {
	if body == "" || payload == "" || !strings.Contains(body, payload) {
		return false
	}
	lower := strings.ToLower(body)
	markers := []string{"window.location", "location.href", "location.assign", "location.replace", "window.open", "http-equiv=\"refresh\"", "http-equiv='refresh'"}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
