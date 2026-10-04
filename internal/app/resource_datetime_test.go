package app

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type resourceDateTimeVector struct {
	Name string `json:"name"`
	Form *struct {
		TZ    string `json:"tz"`
		Value string `json:"value"`
	} `json:"form"`
	Wire     string `json:"wire"`
	Accepted bool   `json:"accepted"`
	Future   bool   `json:"future"`
	Reason   string `json:"reason"`
}

func resourceDateTimeVectors(t *testing.T) []resourceDateTimeVector {
	t.Helper()
	b, err := os.ReadFile("testdata/resource-datetime.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases    []resourceDateTimeVector `json:"cases"`
		WireOnly []resourceDateTimeVector `json:"wireOnly"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 || len(fixture.WireOnly) == 0 {
		t.Fatal("empty resource datetime fixture")
	}
	return append(fixture.Cases, fixture.WireOnly...)
}

// Every server reader of the four datetime fields of the common resource form
// goes through time.Parse(time.RFC3339, s), whose layout takes exactly four year
// digits and no sign. Feeding the fixture "wire" column to the real validators
// here is what makes the shared "accepted" verdict a statement about the strings
// web/src/resources.tsx formBody actually submits - asserted against the form in
// web/tests/resource-form-state.test.mjs - rather than about strings nothing
// sends.
func TestResourceDateTimeSharedVectors(t *testing.T) {
	for _, v := range resourceDateTimeVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			if v.Reason != "ok" && v.Accepted {
				t.Fatalf("accepted vector reason = %q, want ok", v.Reason)
			}
			parsed, parseErr := time.Parse(time.RFC3339, v.Wire)
			if accepted := parseErr == nil; accepted != v.Accepted {
				t.Fatalf("time.Parse(RFC3339, %q) accepted = %v (err %v), want %v", v.Wire, accepted, parseErr, v.Accepted)
			}
			if parseErr == nil && parsed.After(time.Now()) != v.Future {
				t.Fatalf("time.Parse(RFC3339, %q) future = %v, want %v", v.Wire, parsed.After(time.Now()), v.Future)
			}

			// findings due_date. finding_ops.go validateFindingOpsResource is the
			// only write-time check, and it judges nothing but the format.
			dueErr := validateFindingOpsResource(map[string]any{"due_date": v.Wire})
			if accepted := dueErr == nil; accepted != v.Accepted {
				t.Fatalf("validateFindingOpsResource(due_date=%q) accepted = %v (err %v), want %v", v.Wire, accepted, dueErr, v.Accepted)
			}

			// schedules next_run_at. An empty value is substituted by
			// validateSchedule itself, so only a submitted string reaches this.
			scheduleErr := validateSchedule(map[string]any{"service_id": "svc-1", "next_run_at": v.Wire})
			if accepted := scheduleErr == nil; accepted != v.Accepted {
				t.Fatalf("validateSchedule(next_run_at=%q) accepted = %v (err %v), want %v", v.Wire, accepted, scheduleErr, v.Accepted)
			}

			// scopes expires_at. validateScope also requires the instant to be in
			// the future, so a past row would be rejected for that reason instead
			// of for its format and says nothing about the year shape.
			if v.Future {
				scopeErr := validateScope(map[string]any{
					"service_id":    "svc-1",
					"allowed_hosts": []any{"app.internal"},
					"allowed_paths": []any{"/"},
					"expires_at":    v.Wire,
				})
				if accepted := scopeErr == nil; accepted != v.Accepted {
					t.Fatalf("validateScope(expires_at=%q) accepted = %v (err %v), want %v", v.Wire, accepted, scopeErr, v.Accepted)
				}
			}

			// findings expires_at has no write-time validator. The stored string
			// is read back by the dashboard rollup in domain.go, which treats an
			// unparseable value as "not an active risk acceptance" and so leaves
			// the finding counted as open.
			acceptedActive := parseErr == nil && parsed.After(time.Now())
			if want := v.Accepted && v.Future; acceptedActive != want {
				t.Fatalf("rollup read of expires_at=%q active = %v, want %v", v.Wire, acceptedActive, want)
			}
		})
	}
}
