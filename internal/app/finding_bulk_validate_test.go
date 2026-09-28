package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
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

// This pins request validation and returned revisions, not authorization,
// database atomicity, or transitions from a finding's current state.
func TestFindingBulkValidationContract(t *testing.T) {
	baseRevision := time.Date(2026, time.September, 29, 1, 2, 3, 123456789, time.UTC)
	newRequest := func(count int) findingBulkRequest {
		in := findingBulkRequest{
			Items: make([]findingBulkItem, count),
			Patch: map[string]any{"status": "candidate"},
		}
		for i := range in.Items {
			in.Items[i] = findingBulkItem{
				ID:        fmt.Sprintf("finding-%03d", i),
				UpdatedAt: baseRevision.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano),
			}
		}
		return in
	}
	tests := []struct {
		name         string
		count        int
		change       func(*findingBulkRequest)
		reject       bool
		wantRevision time.Time
	}{
		{name: "nil_patch", count: 1, change: func(in *findingBulkRequest) { in.Patch = nil }, reject: true},
		{name: "empty_patch", count: 1, change: func(in *findingBulkRequest) { in.Patch = map[string]any{} }, reject: true},
		{name: "unsupported_title", count: 1, change: func(in *findingBulkRequest) { in.Patch = map[string]any{"title": "value"} }, reject: true},
		{name: "unsupported_owner_id", count: 1, change: func(in *findingBulkRequest) { in.Patch = map[string]any{"owner_id": "value"} }, reject: true},
		{name: "unsupported_service_id", count: 1, change: func(in *findingBulkRequest) { in.Patch = map[string]any{"service_id": "value"} }, reject: true},
		{name: "unsupported_evidence", count: 1, change: func(in *findingBulkRequest) { in.Patch = map[string]any{"evidence": "value"} }, reject: true},
		{name: "unsupported_verification", count: 1, change: func(in *findingBulkRequest) { in.Patch = map[string]any{"verification": "value"} }, reject: true},
		{name: "status_nil", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = nil }, reject: true},
		{name: "status_json_number", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = float64(1) }, reject: true},
		{name: "status_array", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = []any{"candidate"} }, reject: true},
		{name: "status_empty", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "" }, reject: true},
		{name: "status_resolved", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "resolved" }, reject: true},
		{name: "status_accepted", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "accepted" }, reject: true},
		{name: "status_false_positive", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "false_positive" }, reject: true},
		{name: "status_unknown", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "unknown" }, reject: true},
		{name: "status_candidate", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "candidate" }},
		{name: "status_confirmed", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "confirmed" }},
		{name: "status_in_progress", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "in_progress" }},
		{name: "status_retest", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "retest" }},
		{name: "status_inconclusive", count: 1, change: func(in *findingBulkRequest) { in.Patch["status"] = "inconclusive" }},
		{name: "nil_items", count: 1, change: func(in *findingBulkRequest) { in.Items = nil }, reject: true},
		{name: "empty_items", count: 0, reject: true},
		{name: "101_items", count: 101, reject: true},
		{name: "one_item", count: 1},
		{name: "100_items", count: 100},
		{name: "empty_id", count: 1, change: func(in *findingBulkRequest) { in.Items[0].ID = "" }, reject: true},
		{name: "ascii_id_200_bytes", count: 1, change: func(in *findingBulkRequest) { in.Items[0].ID = strings.Repeat("a", 200) }},
		{name: "ascii_id_201_bytes", count: 1, change: func(in *findingBulkRequest) { in.Items[0].ID = strings.Repeat("a", 201) }, reject: true},
		{name: "korean_id_200_bytes", count: 1, change: func(in *findingBulkRequest) { in.Items[0].ID = strings.Repeat("가", 66) + "ab" }},
		{name: "korean_id_201_bytes", count: 1, change: func(in *findingBulkRequest) { in.Items[0].ID = strings.Repeat("가", 67) }, reject: true},
		{name: "duplicate_id", count: 2, change: func(in *findingBulkRequest) { in.Items[1].ID = in.Items[0].ID }, reject: true},
		{name: "missing_revision", count: 1, change: func(in *findingBulkRequest) { in.Items[0].UpdatedAt = "" }, reject: true},
		{name: "invalid_revision", count: 1, change: func(in *findingBulkRequest) { in.Items[0].UpdatedAt = "not-a-time" }, reject: true},
		{name: "revision_without_timezone", count: 1, change: func(in *findingBulkRequest) { in.Items[0].UpdatedAt = "2026-09-29T01:02:03" }, reject: true},
		{name: "utc_revision", count: 1, change: func(in *findingBulkRequest) { in.Items[0].UpdatedAt = "2026-09-29T01:02:03Z" }, wantRevision: time.Date(2026, time.September, 29, 1, 2, 3, 0, time.UTC)},
		{name: "offset_revision", count: 1, change: func(in *findingBulkRequest) { in.Items[0].UpdatedAt = "2026-09-29T10:02:03+09:00" }, wantRevision: time.Date(2026, time.September, 29, 1, 2, 3, 0, time.UTC)},
		{name: "nanosecond_revision", count: 1, change: func(in *findingBulkRequest) { in.Items[0].UpdatedAt = "2026-09-29T10:02:03.123456789+09:00" }, wantRevision: baseRevision},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := newRequest(tt.count)
			if tt.change != nil {
				tt.change(&in)
			}
			revisions, err := validateFindingBulk(&in)
			if tt.reject {
				var bulkErr findingBulkError
				if !errors.As(err, &bulkErr) || bulkErr.Status != 400 {
					t.Fatalf("error = %v (%T), want findingBulkError with status 400", err, err)
				}
				if revisions != nil {
					t.Fatalf("revisions = %v, want nil on rejection", revisions)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateFindingBulk: %v", err)
			}
			if len(revisions) != len(in.Items) {
				t.Fatalf("revision count = %d, want %d", len(revisions), len(in.Items))
			}
			for i, item := range in.Items {
				want := baseRevision.Add(time.Duration(i) * time.Second)
				if !tt.wantRevision.IsZero() {
					want = tt.wantRevision
				}
				got, ok := revisions[item.ID]
				if !ok || !got.Equal(want) || got.Nanosecond() != want.Nanosecond() {
					t.Errorf("revision[%q] = %v (present %v), want %v with %d nanoseconds", item.ID, got, ok, want, want.Nanosecond())
				}
			}
		})
	}
}
