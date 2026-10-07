package app

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

type resourceNumberBound struct {
	Kind    string `json:"kind"`
	Field   string `json:"field"`
	Min     int    `json:"min"`
	Max     int    `json:"max"`
	Integer bool   `json:"integer"`
	Reject  string `json:"reject"`
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

// The numeric fields these validators range-check, with every other field of
// the kind filled in so a rejection can only come from the number under test.
// The scopes and policies siblings are set to 1, which both tables accept, and
// scopes expires_at is kept in the future because validateScope also demands
// expires.After(time.Now()) and a past instant would reject the map for a reason
// unrelated to the bounds. findings is judged by validateContributionPoints
// alone: the rest of that branch in a.validateResource needs a database to
// resolve the service and the workflow setting, and none of it looks at the
// score.
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
	case "findings":
		return m, validateContributionPoints(m)
	case "schedules":
		m["service_id"] = "service-1"
		m["profile"] = "http-baseline"
		m["next_run_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
		return m, validateSchedule(m)
	}
	return m, fmt.Errorf("unknown kind %q", kind)
}

// Deriving every probe from the fixture is what makes the shared min/max
// columns a statement about the server rather than a copy of the form: a min
// one too high fails here because the server still accepts min-1, and a max off
// by one fails against the validator's own message. For scopes and policies the
// accepted range is 1..max - the second column of the policy.go tables is the
// fallback number() uses for a missing or non-numeric value, not a floor, so
// `n < 1 || n > b.max` accepts anything from 1 up - while findings accepts 0 up
// and schedules 5 up, which is why the floor is read from the fixture.
func TestResourceNumberBoundsAreTheServerAcceptedRange(t *testing.T) {
	bounds, _ := resourceNumberFixture(t)
	for _, b := range bounds {
		t.Run(b.Kind+"/"+b.Field, func(t *testing.T) {
			if b.Reject == "" {
				t.Fatal("the fixture row carries no rejection message to match")
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
			for _, reject := range []int{b.Min - 1, b.Max + 1} {
				_, err := resourceNumberSubject(b.Kind, b.Field, reject)
				if err == nil {
					t.Fatalf("%d is outside the shared range but the server accepted it", reject)
				}
				if err.Error() != b.Reject {
					t.Fatalf("%d was refused for an unrelated reason: %v", reject, err)
				}
			}
		})
	}
}

// What the write-back is for. A finding's score has two readers that never meet:
// internal/app/domain.go sums the contribution leaderboard with
// `if points := number(f, "contribution_points", 0); points > 0` and writes the
// CSV column with strconv.Itoa(number(...)), while web/src/pages.tsx is handed
// the stored JSON and filters and sums Number(r.contribution_points) - and
// openapi.json declares the field an integer to both. They agree only while the
// stored value is one: a stored 7.5 is 7 points in the export and 7.5 on the
// contribution page, and a stored 0.5 is on that page and off the leaderboard.
func TestContributionPointsStoredValueReadsTheSameEverywhere(t *testing.T) {
	_, decimals := resourceNumberFixture(t)
	for _, d := range decimals {
		if d.Kind != "findings" || !d.Accepted {
			continue
		}
		t.Run(d.Name, func(t *testing.T) {
			m := map[string]any{"contribution_points": d.Value}
			if err := validateContributionPoints(m); err != nil {
				t.Fatalf("%v was expected to be accepted: %v", d.Value, err)
			}
			raw, err := json.Marshal(m["contribution_points"])
			if err != nil {
				t.Fatal(err)
			}
			var browser float64
			if err := json.Unmarshal(raw, &browser); err != nil {
				t.Fatal(err)
			}
			server := number(m, "contribution_points", 0)
			if browser != float64(server) {
				t.Fatalf("the browser is handed %s while the leaderboard and the CSV read %d", raw, server)
			}
			if (browser > 0) != (server > 0) {
				t.Fatalf("%s counts on the contribution page but not on the leaderboard", raw)
			}
			if server != d.Stored {
				t.Fatalf("%v was expected to read as %d, got %d", d.Value, d.Stored, server)
			}
		})
	}
}

// A JSON number reaches these validators as float64 because the resource write
// handler decodes with json.NewDecoder and no UseNumber, number() returns int(n)
// and every one of them writes that int back into the resource data. So a
// decimal the form allows is either stored as a different number than the
// operator typed or refused for a floor it never looked like it crossed - and if
// a validator skipped the write-back the decimal would survive into storage,
// where the Go readers truncate it and web/src/pages.tsx does not.
func TestResourceNumberBoundsTruncateSubmittedDecimals(t *testing.T) {
	bounds, decimals := resourceNumberFixture(t)
	reject := map[string]string{}
	for _, b := range bounds {
		reject[b.Kind+"."+b.Field] = b.Reject
	}
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
			if want := reject[d.Kind+"."+d.Field]; err.Error() != want {
				t.Fatalf("%v was refused for an unrelated reason: %v", d.Value, err)
			}
		})
	}
}
