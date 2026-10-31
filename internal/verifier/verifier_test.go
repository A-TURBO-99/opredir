package verifier

import (
	"testing"

	"github.com/A-TURBO-99/opredir/internal/model"
)

func TestConfirmsExternalLocationMatchingPayload(t *testing.T) {
	rec := model.ResponseRecord{CaseID: "c1", TargetURL: "https://app.example/redirect", RequestURL: "https://app.example/redirect?next=x", PayloadResolved: "https://marker.invalid/path", StatusCode: 302, Location: "https://marker.invalid/path"}
	got := VerifyRecord(rec)
	if !got.Confirmed || got.Classification != ConfirmedOpenRedirect || got.EvidenceType != "location-header" {
		t.Fatalf("unexpected finding: %#v", got)
	}
}

func TestRelativeLocationIsResolvedAndClassifiedSameOrigin(t *testing.T) {
	rec := model.ResponseRecord{TargetURL: "https://app.example/redirect", RequestURL: "https://app.example/redirect", PayloadResolved: "https://marker.invalid/", StatusCode: 302, Location: "/login"}
	got := VerifyRecord(rec)
	if got.Classification != SameOriginRedirect || got.ResolvedDestination != "https://app.example/login" {
		t.Fatalf("unexpected finding: %#v", got)
	}
}

func TestExternalButUncorrelatedLocationIsNotConfirmed(t *testing.T) {
	rec := model.ResponseRecord{TargetURL: "https://app.example/redirect", RequestURL: "https://app.example/redirect", PayloadResolved: "https://marker.invalid/", StatusCode: 302, Location: "https://identity.example.net/login"}
	got := VerifyRecord(rec)
	if got.Confirmed || got.Classification != ExternalRedirectUnconfirmed {
		t.Fatalf("unexpected finding: %#v", got)
	}
}

func TestRefreshHeaderMatchingPayload(t *testing.T) {
	rec := model.ResponseRecord{TargetURL: "https://app.example/redirect", RequestURL: "https://app.example/redirect", PayloadResolved: "https://marker.invalid/landing", StatusCode: 200, Headers: map[string]string{"Refresh": "0; url=https://marker.invalid/landing"}}
	got := VerifyRecord(rec)
	if !got.Confirmed || got.Classification != ConfirmedRefreshRedirect {
		t.Fatalf("unexpected finding: %#v", got)
	}
}

func TestReflectionIsNotConfirmed(t *testing.T) {
	rec := model.ResponseRecord{TargetURL: "https://app.example/redirect", RequestURL: "https://app.example/redirect", PayloadResolved: "https://marker.invalid/", StatusCode: 200, BodyPreview: "You supplied https://marker.invalid/"}
	got := VerifyRecord(rec)
	if got.Confirmed || got.Classification != ReflectedInputOnly {
		t.Fatalf("unexpected finding: %#v", got)
	}
}

func TestClientSideSignalRequiresBrowserVerification(t *testing.T) {
	rec := model.ResponseRecord{TargetURL: "https://app.example/redirect", RequestURL: "https://app.example/redirect", PayloadResolved: "https://marker.invalid/", StatusCode: 200, BodyPreview: `<script>window.location = "https://marker.invalid/";</script>`}
	got := VerifyRecord(rec)
	if got.Confirmed || got.Classification != ClientSideCandidate {
		t.Fatalf("unexpected finding: %#v", got)
	}
}

func TestRequestError(t *testing.T) {
	got := VerifyRecord(model.ResponseRecord{CaseID: "c1", Error: "timeout"})
	if got.Classification != RequestError {
		t.Fatalf("unexpected finding: %#v", got)
	}
}

func TestSameHostDifferentSchemeIsNotOpenRedirect(t *testing.T) {
	rec := model.ResponseRecord{TargetURL: "http://app.example/redirect", RequestURL: "http://app.example/redirect", PayloadResolved: "https://app.example/", StatusCode: 302, Location: "https://app.example/"}
	got := VerifyRecord(rec)
	if got.Confirmed || got.Classification != SameHostRedirect {
		t.Fatalf("unexpected finding: %#v", got)
	}
}

func TestRedirectStatusWithoutLocationIsNotConfirmed(t *testing.T) {
	rec := model.ResponseRecord{TargetURL: "https://app.example/", RequestURL: "https://app.example/", PayloadResolved: "https://marker.invalid/", StatusCode: 302}
	got := VerifyRecord(rec)
	if got.Confirmed || got.Classification != RedirectWithoutLocation {
		t.Fatalf("unexpected finding: %#v", got)
	}
}
