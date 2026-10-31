package model

// PayloadCorpus is the canonical cleaned URL-value corpus.
type PayloadCorpus struct {
	Name       string          `json:"name"`
	RecordType string          `json:"record_type"`
	Count      int             `json:"count"`
	Note       string          `json:"note"`
	Records    []PayloadRecord `json:"records"`
}

// PayloadRecord describes one candidate URL value. Candidates are unverified
// until a target-specific test proves otherwise.
type PayloadRecord struct {
	ID                   string   `json:"id"`
	Payload              string   `json:"payload"`
	Families             []string `json:"families"`
	Sources              []string `json:"sources"`
	TemplatedPayload     string   `json:"templated_payload"`
	RuntimeValue         string   `json:"runtime_value"`
	RecordType           string   `json:"record_type"`
	Status               string   `json:"status"`
	RequiredPlaceholders []string `json:"required_placeholders"`
}

// TestCase is one generated HTTP request candidate, serialized as JSONL.
type TestCase struct {
	CaseID                       string   `json:"case_id"`
	Method                       string   `json:"method"`
	TargetURL                    string   `json:"target_url"`
	RequestURL                   string   `json:"request_url"`
	Parameter                    string   `json:"parameter"`
	ParameterLocation            string   `json:"parameter_location"`
	PayloadID                    string   `json:"payload_id"`
	PayloadRaw                   string   `json:"payload_raw"`
	PayloadTemplate              string   `json:"payload_template"`
	PayloadResolved              string   `json:"payload_resolved"`
	PayloadFamilies              []string `json:"payload_families"`
	PayloadSources               []string `json:"payload_sources"`
	Transformation               string   `json:"transformation"`
	EncodedValueOnce             string   `json:"encoded_value_once"`
	PlacementMode                string   `json:"placement_mode"`
	ExistingParameterOccurrences int      `json:"existing_parameter_occurrences"`
	FragmentDropped              bool     `json:"fragment_dropped"`
	Status                       string   `json:"status"`
	RequestBody                  string   `json:"request_body,omitempty"`
}

// ResponseRecord contains bounded evidence from one HTTP response.
type ResponseRecord struct {
	CaseID           string            `json:"case_id"`
	Method           string            `json:"method"`
	RequestURL       string            `json:"request_url"`
	TargetURL        string            `json:"target_url,omitempty"`
	PayloadID        string            `json:"payload_id,omitempty"`
	Parameter        string            `json:"parameter,omitempty"`
	PayloadResolved  string            `json:"payload_resolved,omitempty"`
	PayloadFamilies  []string          `json:"payload_families,omitempty"`
	StatusCode       int               `json:"status_code,omitempty"`
	Status           string            `json:"status,omitempty"`
	Location         string            `json:"location,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	DurationMS       int64             `json:"duration_ms"`
	RemoteAddress    string            `json:"remote_address,omitempty"`
	BodyBytesRead    int64             `json:"body_bytes_read"`
	BodyTruncated    bool              `json:"body_truncated"`
	BodyPreview      string            `json:"body_preview,omitempty"`
	Error            string            `json:"error,omitempty"`
	RedirectFollowed bool              `json:"redirect_followed"`
}
