package app

import (
	"encoding/json"
	"os"
	"testing"
)

type findingBulkDueVector struct {
	Name string `json:"name"`
	Form *struct {
		TZ  string `json:"tz"`
		Due string `json:"due"`
	} `json:"form"`
	Wire     string `json:"wire"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason"`
}

func findingBulkDueVectors(t *testing.T) []findingBulkDueVector {
	t.Helper()
	b, err := os.ReadFile("testdata/finding-bulk-due-date.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases    []findingBulkDueVector `json:"cases"`
		WireOnly []findingBulkDueVector `json:"wireOnly"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 || len(fixture.WireOnly) == 0 {
		t.Fatal("empty bulk due date fixture")
	}
	return append(fixture.Cases, fixture.WireOnly...)
}

// validateFindingBulk routes due_date to validateFindingOpsResource, which reads
// it with time.Parse(time.RFC3339, s). That layout takes exactly four year digits
// and no sign, so every expanded year toISOString can emit is a 400 that rolls
// back the whole request. Feeding the fixture "wire" column here is what makes
// the shared "accepted" verdict a statement about the strings the bulk change
// form actually submits (asserted against the form in
// web/tests/finding-bulk.test.mjs) rather than about strings nothing sends.
func TestFindingBulkDueDateSharedVectors(t *testing.T) {
	for _, v := range findingBulkDueVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			in := findingBulkRequest{
				Items: []findingBulkItem{{ID: "f1", UpdatedAt: "2026-10-03T00:00:00Z"}},
				Patch: map[string]any{"due_date": v.Wire},
			}
			_, err := validateFindingBulk(&in)
			if accepted := err == nil; accepted != v.Accepted {
				t.Fatalf("validateFindingBulk(due_date=%q) accepted = %v (err %v), want %v", v.Wire, accepted, err, v.Accepted)
			}
			if v.Accepted {
				if v.Reason != "ok" {
					t.Fatalf("accepted vector reason = %q, want ok", v.Reason)
				}
				// The accepted wire string must survive validation unchanged, so the
				// stored due date is the instant the form computed.
				if got := in.Patch["due_date"]; got != v.Wire {
					t.Fatalf("validateFindingBulk rewrote due_date to %q, want %q", got, v.Wire)
				}
				return
			}
			if v.Reason != "expanded-year" {
				t.Fatalf("rejected vector reason = %q, want expanded-year", v.Reason)
			}
			// The rejection must be the 400 the bulk endpoint reports, because that
			// is what discards the assignee and status in the same patch.
			bulkErr, ok := err.(findingBulkError)
			if !ok {
				t.Fatalf("validateFindingBulk(due_date=%q) err type = %T, want findingBulkError", v.Wire, err)
			}
			if bulkErr.Status != 400 {
				t.Fatalf("validateFindingBulk(due_date=%q) status = %d, want 400", v.Wire, bulkErr.Status)
			}
		})
	}
}
