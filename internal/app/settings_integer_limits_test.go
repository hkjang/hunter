package app

import (
	"strconv"
	"strings"
	"testing"
)

// The integer limits of the ai·agents·security groups are read by every enforcer
// through asInt, so what the settings row stores has to be that same integer.
// A stored 40.9 freezes into the immutable run snapshot (agents.go) and the
// offline report then prints a limit that was never enforced.
var settingsIntegerLimitKeys = map[string][]string{
	"ai":       {"max_tokens", "context_window"},
	"agents":   {"max_iterations", "max_model_calls", "max_tool_calls", "timeout_minutes"},
	"security": {"session_hours", "key_max_days"},
}

func fractionalSettingsGroup(group string) map[string]any {
	v := defaultSettings()[group]
	for _, k := range settingsIntegerLimitKeys[group] {
		v[k] = float64(asInt(v[k])) + 0.9
	}
	return v
}

func TestSettingsStoreTheIntegerTheEnforcersRead(t *testing.T) {
	for group, keys := range settingsIntegerLimitKeys {
		t.Run(group, func(t *testing.T) {
			want := map[string]int{}
			v := fractionalSettingsGroup(group)
			for _, k := range keys {
				want[k] = asInt(v[k])
			}
			if e := validateSettings(group, v); e != nil {
				t.Fatalf("a fractional limit must keep being accepted, got %v", e)
			}
			for _, k := range keys {
				n, ok := v[k].(int)
				if !ok {
					t.Fatalf("%s.%s was stored as %[3]T(%[3]v), want the enforced int %d", group, k, v[k], want[k])
				}
				if n != want[k] {
					t.Fatalf("%s.%s was stored as %d, want the enforced %d", group, k, n, want[k])
				}
			}
		})
	}
}

// The report prints v.Limits as given, so the run snapshot built in agents.go
// from the validated settings must already carry the enforced integers.
func TestAgentReportPrintsTheEnforcedLimit(t *testing.T) {
	cfg := fractionalSettingsGroup("agents")
	ai := fractionalSettingsGroup("ai")
	want := map[string]int{}
	for _, k := range settingsIntegerLimitKeys["agents"] {
		want[k] = asInt(cfg[k])
	}
	for _, k := range settingsIntegerLimitKeys["ai"] {
		want[k] = asInt(ai[k])
	}
	if e := validateSettings("agents", cfg); e != nil {
		t.Fatal(e)
	}
	if e := validateSettings("ai", ai); e != nil {
		t.Fatal(e)
	}
	limits := cloneMap(cfg)
	limits["max_tokens"] = ai["max_tokens"]
	limits["context_window"] = ai["context_window"]

	doc := reportDocument("test", agentRun{ID: "run-1", Limits: limits}, nil)
	section := ""
	for _, s := range doc.Sections {
		if s.Title == "실행에 기록된 한도" {
			section = s.Text
		}
	}
	if section == "" {
		t.Fatal("the report has no recorded-limit section")
	}
	for k, n := range want {
		line := k + ": " + strconv.Itoa(n)
		if !containsLine(section, line) {
			t.Fatalf("the report prints a limit that is not the enforced one: want line %q in\n%s", line, section)
		}
	}
}

func containsLine(text, line string) bool {
	for _, l := range strings.Split(text, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

// The normalisation must not move a single boundary: these are the ranges the
// three groups accepted before it existed.
func TestSettingsIntegerBoundariesAreUnchanged(t *testing.T) {
	cases := []struct {
		group  string
		values map[string]any
		accept bool
	}{
		{"agents", map[string]any{"max_iterations": 6}, true},
		{"agents", map[string]any{"max_iterations": 5}, false},
		{"agents", map[string]any{"max_iterations": 100}, true},
		{"agents", map[string]any{"max_iterations": 101}, false},
		{"agents", map[string]any{"max_model_calls": 5}, true},
		{"agents", map[string]any{"max_model_calls": 4}, false},
		{"agents", map[string]any{"max_model_calls": 200}, true},
		{"agents", map[string]any{"max_model_calls": 201}, false},
		{"agents", map[string]any{"max_tool_calls": 1}, true},
		{"agents", map[string]any{"max_tool_calls": 0}, false},
		{"agents", map[string]any{"max_tool_calls": 200}, true},
		{"agents", map[string]any{"max_tool_calls": 201}, false},
		{"agents", map[string]any{"timeout_minutes": 1}, true},
		{"agents", map[string]any{"timeout_minutes": 0}, false},
		{"agents", map[string]any{"timeout_minutes": 60}, true},
		{"agents", map[string]any{"timeout_minutes": 61}, false},
		{"ai", map[string]any{"max_tokens": 1}, true},
		{"ai", map[string]any{"max_tokens": 0}, false},
		{"ai", map[string]any{"max_tokens": 262144, "context_window": 262144}, true},
		{"ai", map[string]any{"max_tokens": 262145, "context_window": 262144}, false},
		{"ai", map[string]any{"context_window": 1024, "max_tokens": 1024}, true},
		{"ai", map[string]any{"context_window": 1023, "max_tokens": 1023}, false},
		{"ai", map[string]any{"max_tokens": 8193, "context_window": 8192}, false},
		{"security", map[string]any{"session_hours": 1}, true},
		{"security", map[string]any{"session_hours": 0}, false},
		{"security", map[string]any{"session_hours": 168}, true},
		{"security", map[string]any{"session_hours": 169}, false},
		{"security", map[string]any{"key_max_days": 1}, true},
		{"security", map[string]any{"key_max_days": 0}, false},
		{"security", map[string]any{"key_max_days": 365}, true},
		{"security", map[string]any{"key_max_days": 366}, false},
	}
	for _, c := range cases {
		v := defaultSettings()[c.group]
		for k, val := range c.values {
			v[k] = val
		}
		e := validateSettings(c.group, v)
		if c.accept && e != nil {
			t.Errorf("%s %v was accepted before, now %v", c.group, c.values, e)
		}
		if !c.accept && e == nil {
			t.Errorf("%s %v was rejected before, now accepted", c.group, c.values)
		}
	}
}

// The three Korean messages are part of the contract the admin screen shows.
func TestSettingsIntegerRejectionMessages(t *testing.T) {
	for _, c := range []struct {
		group string
		key   string
		value any
		want  string
	}{
		{"ai", "max_tokens", 262145, "최대 토큰과 컨텍스트는 262144 이하이며 최대 토큰은 컨텍스트 이하여야 합니다"},
		{"agents", "max_tool_calls", 201, "max_tool_calls 값은 1~200 범위여야 합니다"},
		{"security", "session_hours", 169, "세션은 1~168시간, 키 유효기간은 1~365일로 입력해 주세요"},
	} {
		v := defaultSettings()[c.group]
		v[c.key] = c.value
		e := validateSettings(c.group, v)
		if e == nil || e.Error() != c.want {
			t.Errorf("%s.%s error = %v, want %q", c.group, c.key, e, c.want)
		}
	}
}
