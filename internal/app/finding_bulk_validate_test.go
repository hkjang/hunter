package app

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type findingBulkAssigneeVector struct {
	Name     string `json:"name"`
	Assignee string `json:"assignee"`
	Wire     string `json:"wire"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason"`
}

func findingBulkAssigneeVectors(t *testing.T) []findingBulkAssigneeVector {
	t.Helper()
	b, err := os.ReadFile("testdata/finding-bulk-assignee.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []findingBulkAssigneeVector `json:"cases"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("empty bulk assignee fixture")
	}
	return fixture.Cases
}

// validateFindingBulk decides the 200 byte limit and the control character scan
// on the string it receives, which for the bulk change form is the trimmed name
// (the fixture "wire" column, asserted against the form in
// web/tests/finding-bulk.test.mjs). Feeding "wire" here is what makes the shared
// "accepted" verdict a statement about the form's own requests rather than about
// a string nothing submits.
func TestFindingBulkAssigneeSharedVectors(t *testing.T) {
	for _, v := range findingBulkAssigneeVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			in := findingBulkRequest{
				Items: []findingBulkItem{{ID: "f1", UpdatedAt: "2026-09-28T00:00:00Z"}},
				Patch: map[string]any{"assignee": v.Wire},
			}
			_, err := validateFindingBulk(&in)
			if accepted := err == nil; accepted != v.Accepted {
				t.Fatalf("validateFindingBulk(assignee=%q) accepted = %v (err %v), want %v (typed %q)", v.Wire, accepted, err, v.Accepted, v.Assignee)
			}
			if !v.Accepted {
				if v.Reason != "length" && v.Reason != "control" {
					t.Fatalf("rejected vector reason = %q, want length or control", v.Reason)
				}
				return
			}
			if v.Reason != "ok" {
				t.Fatalf("accepted vector reason = %q, want ok", v.Reason)
			}
			// Pins the fixture, not a disagreement between the two trims: "wire"
			// is what the form submits, so the server's trim is a no-op on it and
			// the stored value is "wire" verbatim. Go cannot observe the
			// disagreement from this side — the only codepoint Go trims and
			// JavaScript keeps is U+0085, and the control scan above rejects that
			// first (vector nel-u0085-control-before-go-only-trim). The other
			// direction, U+FEFF trimmed by JavaScript only, is what the
			// bom-u-feff-* vectors carry, and web/tests/finding-bulk.test.mjs
			// asserts assignee.trim() === wire on them.
			if in.Patch["assignee"] != v.Wire {
				t.Errorf("stored assignee = %q, want unchanged %q", in.Patch["assignee"], v.Wire)
			}
			if strings.TrimSpace(v.Wire) != v.Wire {
				t.Errorf("wire %q is not already trimmed by Go", v.Wire)
			}
		})
	}
}
