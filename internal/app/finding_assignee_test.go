package app

import (
	"context"
	"strings"
	"testing"
)

// The message validateFindingBulk has always reported for an out-of-rule
// assignee. Saving one finding has to answer with the same sentence, so the rule
// reads the same way whichever path the operator used.
const findingAssigneeMessage = "조치 담당자는 줄바꿈 없이 UTF-8 200바이트 이하로 입력하세요"

// len() counts bytes, so the limit is 200 UTF-8 bytes and not 200 runes. A
// Korean name costs three bytes per character, which is why the multibyte
// vectors below sit on the byte boundary rather than the rune boundary.
func TestFindingAssigneeRule(t *testing.T) {
	for _, c := range []struct {
		name   string
		in     any
		absent bool
		want   string // stored value when accepted
		reject bool
	}{
		{name: "absent assignee is not a change", absent: true},
		{name: "nil assignee is left alone", in: nil},
		{name: "empty assignee stays empty", in: "", want: ""},
		{name: "ordinary name is stored as typed", in: "김보안", want: "김보안"},
		{name: "exactly 200 bytes is accepted", in: strings.Repeat("a", 200), want: strings.Repeat("a", 200)},
		{name: "201 bytes is rejected", in: strings.Repeat("a", 201), reject: true},
		{name: "200 runes over 200 bytes is rejected", in: strings.Repeat("가", 200), reject: true},
		{name: "198 bytes plus one multibyte rune is rejected", in: strings.Repeat("a", 198) + "가", reject: true},
		{name: "newline is rejected", in: "김보안\n관리자", reject: true},
		{name: "tab is rejected", in: "김보안\t관리자", reject: true},
		{name: "NUL is rejected", in: "김보안\x00", reject: true},
		{name: "non-string is rejected", in: 42, reject: true},
		{name: "bool is rejected", in: true, reject: true},
		{name: "surrounding whitespace is trimmed, not rejected", in: "  김보안  ", want: "김보안"},
		{name: "whitespace only becomes the empty string", in: "   ", want: ""},
		{name: "trailing newline alone is still a control character", in: "김보안\n", reject: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]any{"title": "t"}
			if !c.absent {
				m["assignee"] = c.in
			}
			err := validateFindingAssignee(m, nil)
			if c.reject {
				if err == nil {
					t.Fatalf("validateFindingAssignee(%#v) accepted, want rejection", c.in)
				}
				if err.Error() != findingAssigneeMessage {
					t.Fatalf("validateFindingAssignee(%#v) message = %q, want %q", c.in, err.Error(), findingAssigneeMessage)
				}
				// The fixed sentence must not quote the submitted name back: audit
				// and error output are not places for the protected value.
				if name, ok := c.in.(string); ok && name != "" && strings.Contains(err.Error(), strings.TrimSpace(name)) {
					t.Fatalf("validateFindingAssignee echoed the submitted assignee into its message")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateFindingAssignee(%#v) = %v, want accepted", c.in, err)
			}
			if c.absent {
				if _, exists := m["assignee"]; exists {
					t.Fatal("validateFindingAssignee invented an assignee key that was never submitted")
				}
				return
			}
			if c.in == nil {
				if m["assignee"] != nil {
					t.Fatalf("validateFindingAssignee rewrote a nil assignee to %#v", m["assignee"])
				}
				return
			}
			// The write-back is what makes the stored value the one the queue SQL
			// counts: finding_ops.go reads btrim(data->>'assignee')='' as
			// unassigned, while the detail view, the CSV export and the recipient
			// match in notification_automation_recipients.go read the raw string.
			if got := m["assignee"]; got != c.want {
				t.Fatalf("validateFindingAssignee stored %#v, want %#v", got, c.want)
			}
		})
	}
}

// An assignee that predates the rule - stored through ITSM import or an older
// API - must not freeze every later edit of that finding. saveDomain hands the
// validator the merged data and the pre-merge copy, so a PUT that does not touch
// the field, or resubmits it unchanged, compares equal and is skipped.
func TestFindingAssigneeKeepsExistingValuesEditable(t *testing.T) {
	legacy := strings.Repeat("b", 300)
	for _, c := range []struct {
		name      string
		submitted any
		old       map[string]any
		reject    bool
	}{
		{name: "untouched legacy value passes", submitted: legacy, old: map[string]any{"assignee": legacy}},
		{name: "legacy value with a control character passes", submitted: "old\nname", old: map[string]any{"assignee": "old\nname"}},
		{name: "changing a legacy value to a valid one passes", submitted: "김보안", old: map[string]any{"assignee": legacy}},
		{name: "changing a legacy value to another illegal one is rejected", submitted: strings.Repeat("c", 300), old: map[string]any{"assignee": legacy}, reject: true},
		{name: "clearing a legacy value passes", submitted: "", old: map[string]any{"assignee": legacy}},
		{name: "a new illegal value on a clean row is rejected", submitted: strings.Repeat("c", 300), old: map[string]any{"assignee": "김보안"}, reject: true},
		{name: "a new illegal value on a row without the key is rejected", submitted: strings.Repeat("c", 300), old: map[string]any{}, reject: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]any{"assignee": c.submitted}
			err := validateFindingAssignee(m, c.old)
			if c.reject != (err != nil) {
				t.Fatalf("validateFindingAssignee(%q, old=%#v) err = %v, want rejection = %v", c.submitted, c.old["assignee"], err, c.reject)
			}
		})
	}
	// A resubmitted legacy value is stored exactly as it was: skipping the check
	// must skip the trim too, or the first save of an untouched field would
	// rewrite it and log a change in finding_ops_activity.go.
	m := map[string]any{"assignee": "  spaced  "}
	if err := validateFindingAssignee(m, map[string]any{"assignee": "  spaced  "}); err != nil {
		t.Fatal(err)
	}
	if m["assignee"] != "  spaced  " {
		t.Fatalf("an unchanged assignee was rewritten to %#v", m["assignee"])
	}
}

// The rule has to sit on the path the HTTP handler actually takes, not just in a
// helper a test can reach. validateResource is what POST /api/findings and
// PUT /api/findings/{id} call through saveDomain; with no service_id it touches
// no database, so the real wiring is observable without a DSN.
func TestFindingAssigneeIsWiredIntoResourceValidation(t *testing.T) {
	a := &App{}
	for _, update := range []bool{false, true} {
		v := domainResource{Kind: "findings", Data: map[string]any{
			"title":    "제목",
			"severity": "high",
			"assignee": strings.Repeat("a", 201),
		}}
		err := a.validateResource(context.Background(), User{}, &v, map[string]any{}, update)
		if err == nil || err.Error() != findingAssigneeMessage {
			t.Fatalf("validateResource(update=%v) err = %v, want %q", update, err, findingAssigneeMessage)
		}
	}
	// And the accepted value is trimmed by the time the handler stores it.
	v := domainResource{Kind: "findings", Data: map[string]any{
		"title":    "제목",
		"severity": "high",
		"assignee": "  김보안  ",
	}}
	// This call still fails on the missing service, which is checked after the
	// assignee: the point is that the write-back already happened.
	_ = a.validateResource(context.Background(), User{}, &v, map[string]any{}, false)
	if v.Data["assignee"] != "김보안" {
		t.Fatalf("validateResource stored assignee %#v, want %#v", v.Data["assignee"], "김보안")
	}
}

// Acceptance criterion 4: the bulk path reports the rule through the same
// helper, so there is one sentence and one set of conditions in the tree.
func TestFindingAssigneeBulkUsesTheSameRule(t *testing.T) {
	for _, c := range []struct {
		name   string
		in     any
		want   any
		reject bool
		msg    string // expected message, defaulting to the shared rule sentence
	}{
		{name: "exactly 200 bytes is accepted", in: strings.Repeat("a", 200), want: strings.Repeat("a", 200)},
		{name: "201 bytes is rejected", in: strings.Repeat("a", 201), reject: true},
		{name: "control character is rejected", in: "김보안\n", reject: true},
		{name: "non-string is rejected", in: 42, reject: true},
		{name: "surrounding whitespace is trimmed", in: "  김보안  ", want: "김보안"},
		// A bulk patch names the field it is changing, so a null there is not the
		// "field was not submitted" case the save path skips - it is a value the
		// column should never hold. This was a 400 before the rule moved into the
		// shared helper and has to stay one.
		{name: "null is rejected", in: nil, reject: true, msg: "조치 담당자에는 이름 또는 빈 문자열을 입력하세요"},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := findingBulkRequest{
				Items: []findingBulkItem{{ID: "f1", UpdatedAt: "2026-10-16T00:00:00Z"}},
				Patch: map[string]any{"assignee": c.in},
			}
			_, err := validateFindingBulk(&in)
			if c.reject {
				if err == nil {
					t.Fatalf("validateFindingBulk(assignee=%#v) accepted, want rejection", c.in)
				}
				bulkErr, ok := err.(findingBulkError)
				if !ok {
					t.Fatalf("validateFindingBulk err type = %T, want findingBulkError", err)
				}
				if bulkErr.Status != 400 {
					t.Fatalf("validateFindingBulk status = %d, want 400", bulkErr.Status)
				}
				want := c.msg
				if want == "" {
					want = findingAssigneeMessage
				}
				if bulkErr.Message != want {
					t.Fatalf("validateFindingBulk message = %q, want %q", bulkErr.Message, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateFindingBulk(assignee=%#v) = %v, want accepted", c.in, err)
			}
			if got := in.Patch["assignee"]; got != c.want {
				t.Fatalf("validateFindingBulk stored %#v, want %#v", got, c.want)
			}
		})
	}
}
