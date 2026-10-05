package app

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type resourceNumberBound struct {
	Kind    string `json:"kind"`
	Field   string `json:"field"`
	Min     int    `json:"min"`
	Max     int    `json:"max"`
	Integer bool   `json:"integer"`
}

type resourceNumberDecimal struct {
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	Field    string  `json:"field"`
	Value    float64 `json:"value"`
	Accepted bool    `json:"accepted"`
	Stored   int     `json:"stored"`
}

func resourceNumberFixture(t *testing.T) (bounds []resourceNumberBound, decimals []resourceNumberDecimal) {
	t.Helper()
	b, err := os.ReadFile("testdata/resource-number-bounds.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Bounds   []resourceNumberBound   `json:"bounds"`
		Decimals []resourceNumberDecimal `json:"decimals"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Bounds) == 0 || len(fixture.Decimals) == 0 {
		t.Fatal("empty resource number bounds fixture")
	}
	return fixture.Bounds, fixture.Decimals
}

// The numeric fields the two validators range-check, with every other field of
// the kind filled in so a rejection can only come from the number under test.
// The siblings are set to 1, which both tables accept, and scopes expires_at is
// kept in the future because validateScope also demands expires.After(time.Now())
// and a past instant would reject the map for a reason unrelated to the bounds.
func resourceNumberSubject(kind, field string, value any) (map[string]any, error) {
	siblings := map[string][]string{
		"scopes":   {"max_rps", "max_requests", "timeout_seconds"},
		"policies": {"max_rps", "max_concurrency", "max_requests", "timeout_seconds"},
	}[kind]
	m := map[string]any{}
	for _, k := range siblings {
		m[k] = 1
	}
	m[field] = value
	switch kind {
	case "scopes":
		m["service_id"] = "service-1"
		m["allowed_hosts"] = []any{"portal.internal:8443"}
		m["allowed_paths"] = []any{"/"}
		m["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
		return m, validateScope(m)
	case "policies":
		return m, validatePolicy(m)
	}
	return m, fmt.Errorf("unknown kind %q", kind)
}

// The accepted range of all seven fields is 1..max: the second column of the
// policy.go tables is the fallback number() uses for a missing or non-numeric
// value, not a floor, so the check `n < 1 || n > b.max` accepts anything from 1
// up. Deriving every probe from the fixture is what makes the shared min/max
// columns a statement about the server rather than a copy of the form - a min
// above 1 fails here because the server still accepts min-1, and a max off by
// one fails against the validator's own message.
func TestResourceNumberBoundsAreTheServerAcceptedRange(t *testing.T) {
	bounds, _ := resourceNumberFixture(t)
	for _, b := range bounds {
		t.Run(b.Kind+"/"+b.Field, func(t *testing.T) {
			if b.Min != 1 {
				t.Fatalf("the validators accept from 1, so the shared min must be 1, got %d", b.Min)
			}
			for _, accept := range []int{b.Min, b.Max} {
				m, err := resourceNumberSubject(b.Kind, b.Field, accept)
				if err != nil {
					t.Fatalf("%d is inside the shared range but the server refused it: %v", accept, err)
				}
				if got := m[b.Field]; got != accept {
					t.Fatalf("%d was stored as %v", accept, got)
				}
			}
			want := fmt.Sprintf("%s 값은 1~%d 범위입니다", b.Field, b.Max)
			for _, reject := range []int{b.Min - 1, b.Max + 1} {
				_, err := resourceNumberSubject(b.Kind, b.Field, reject)
				if err == nil {
					t.Fatalf("%d is outside the shared range but the server accepted it", reject)
				}
				if err.Error() != want {
					t.Fatalf("%d was refused for an unrelated reason: %v", reject, err)
				}
			}
		})
	}
}

// A JSON number reaches these validators as float64 because the resource write
// handler decodes with json.NewDecoder and no UseNumber, number() returns int(n)
// and both validators write that int back with m[b.k] = n. So a decimal the form
// used to allow is either stored as a different number than the operator typed
// or refused for a floor it never looked like it crossed.
func TestResourceNumberBoundsTruncateSubmittedDecimals(t *testing.T) {
	_, decimals := resourceNumberFixture(t)
	for _, d := range decimals {
		t.Run(d.Name, func(t *testing.T) {
			m, err := resourceNumberSubject(d.Kind, d.Field, d.Value)
			if d.Accepted {
				if err != nil {
					t.Fatalf("%v was expected to be accepted: %v", d.Value, err)
				}
				if got := m[d.Field]; got != d.Stored {
					t.Fatalf("%v was expected to be stored as %d, got %v", d.Value, d.Stored, got)
				}
				if float64(d.Stored) == d.Value {
					t.Fatalf("%v is not a decimal the server changes", d.Value)
				}
				return
			}
			if err == nil {
				t.Fatalf("%v was expected to be rejected after truncation", d.Value)
			}
			if !strings.HasPrefix(err.Error(), d.Field+" 값은 1~") {
				t.Fatalf("%v was refused for an unrelated reason: %v", d.Value, err)
			}
		})
	}
}
