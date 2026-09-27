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
// on the raw submitted string and only afterwards trims the stored value. The
// bulk change form reads the same fixture (web/tests/finding-bulk.test.mjs) so
// it never submits an assignee this validation would answer with 400.
func TestFindingBulkAssigneeSharedVectors(t *testing.T) {
	for _, v := range findingBulkAssigneeVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			in := findingBulkRequest{
				Items: []findingBulkItem{{ID: "f1", UpdatedAt: "2026-09-28T00:00:00Z"}},
				Patch: map[string]any{"assignee": v.Assignee},
			}
			_, err := validateFindingBulk(&in)
			if accepted := err == nil; accepted != v.Accepted {
				t.Fatalf("validateFindingBulk(assignee=%q) accepted = %v (err %v), want %v", v.Assignee, accepted, err, v.Accepted)
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
			if want := strings.TrimSpace(v.Assignee); in.Patch["assignee"] != want {
				t.Errorf("stored assignee = %q, want trimmed %q", in.Patch["assignee"], want)
			}
		})
	}
}
