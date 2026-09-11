package app

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMaskAgentTextStructuredSecrets(t *testing.T) {
	cases := []struct {
		name, input string
		secrets     []string
	}{
		{"plain", "정상 안내\npassword=plain-sensitive-value\n다음 안내\n", []string{"plain-sensitive-value"}},
		{"json", `{"password":"json-sensitive-value","normal":"일반 한국어 문장"}`, []string{"json-sensitive-value"}},
		{"JSON unicode key", `{"pa\u0073sword":"unicode-sensitive-value","normal":"보존"}`, []string{"unicode-sensitive-value"}},
		{"nested JSON unicode key", `{"evidence":"{\"pa\\u0073sword\":\"unicode-nested-sensitive-value\"}"}`, []string{"unicode-nested-sensitive-value"}},
		{"json escaped string", `{"evidence":"{\"password\":\"escaped-sensitive-value\"}"}`, []string{"escaped-sensitive-value"}},
		{"multiple JSON fields", `{"access_token":"access-sensitive-value","refresh_token":"refresh-sensitive-value","client_secret":"client-sensitive-value"}`, []string{"access-sensitive-value", "refresh-sensitive-value", "client-sensitive-value"}},
		{"header", "Authorization: Bearer bearer-sensitive-value\nCookie: session=cookie-first-value; token=cookie-second-value\n완료\n", []string{"bearer-sensitive-value", "cookie-first-value", "cookie-second-value"}},
		{"folded header", "Cookie: session=folded-first-value;\n another=folded-second-value\n완료\n", []string{"folded-first-value", "folded-second-value"}},
		{"cross line value", "{\n\"password\"\n :\n \"cross-line-sensitive-value\",\n\"normal\":\"보존\"\n}", []string{"cross-line-sensitive-value"}},
		{"multiline quoted", "token: \"first-sensitive-line\nsecond-sensitive-line\"\n정상\n", []string{"first-sensitive-line", "second-sensitive-line"}},
		{"incomplete quoted", `password: "unfinished-sensitive-value`, []string{"unfinished-sensitive-value"}},
		{"escaped quote inside value", `{"password":"first-sensitive\"still-sensitive","normal":"보존"}`, []string{"first-sensitive", "still-sensitive"}},
		{"object value", `{"token":{"value":"object-sensitive-value","other":"other-sensitive-value"},"normal":true}`, []string{"object-sensitive-value", "other-sensitive-value"}},
		{"dsn", "DSN=postgres://user:dsn-sensitive-value@db/service\n", []string{"dsn-sensitive-value"}},
		{"url", "연결 postgres://user:url-sensitive-value@db/service 정상\n", []string{"url-sensitive-value"}},
		{"JWT", "응답 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature_sensitive_value 완료\n", []string{"eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJ1c2VyIn0", "signature_sensitive_value"}},
		{"JWT spaced header", "응답 eyAiYWxnIjogIlJTMjU2IiB9.eyJzdWIiOiJ1c2VyIn0.other_signature_sensitive_value 완료\n", []string{"eyAiYWxnIjogIlJTMjU2IiB9", "other_signature_sensitive_value"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := maskAgentText(tc.input)
			for _, secret := range tc.secrets {
				if strings.Contains(got, secret) {
					t.Fatalf("secret survived: %q => %q", secret, got)
				}
			}
			if !strings.Contains(got, "[REDACTED") || !utf8.ValidString(got) {
				t.Fatalf("invalid redacted result: %q", got)
			}
			if json.Valid([]byte(tc.input)) && !json.Valid([]byte(got)) {
				t.Fatalf("valid JSON was damaged: %s", got)
			}
			// Every possible two-chunk boundary includes splits inside keys,
			// separators, escaped quotes, UTF-8, and the secret itself.
			for split := 0; split <= len(tc.input); split++ {
				var output strings.Builder
				r := newAgentStreamRedactor(func(s string) {
					if !utf8.ValidString(s) {
						t.Fatalf("invalid UTF-8 output at split %d", split)
					}
					output.WriteString(s)
				})
				r.Write(tc.input[:split])
				r.Write(tc.input[split:])
				r.Flush()
				for _, secret := range tc.secrets {
					if strings.Contains(output.String(), secret) {
						t.Fatalf("split %d leaked %q: %q", split, secret, output.String())
					}
				}
				if json.Valid([]byte(tc.input)) && !json.Valid([]byte(output.String())) {
					t.Fatalf("split %d damaged JSON: %s", split, output.String())
				}
			}
			var output strings.Builder
			r := newAgentStreamRedactor(func(s string) { output.WriteString(s) })
			for i := 0; i < len(tc.input); i++ {
				r.Write(tc.input[i : i+1])
			}
			r.Flush()
			for _, secret := range tc.secrets {
				if strings.Contains(output.String(), secret) {
					t.Fatalf("bytewise stream leaked %q: %q", secret, output.String())
				}
			}
		})
	}
}

func TestAgentStreamRedactorPreservesKoreanAndFinalFlush(t *testing.T) {
	input := "승인된 서비스를 확인합니다.\n발견 건을 검토합니다.\n최종 보고서입니다."
	var out strings.Builder
	r := newAgentStreamRedactor(func(s string) {
		if !utf8.ValidString(s) {
			t.Fatalf("invalid UTF-8: %q", s)
		}
		out.WriteString(s)
	})
	for i := 0; i < len(input); i++ {
		r.Write(input[i : i+1])
	}
	if out.String() != "승인된 서비스를 확인합니다.\n발견 건을 검토합니다.\n" {
		t.Fatalf("safe lines did not stream: %q", out.String())
	}
	r.Flush()
	r.Flush()
	r.Write("이미 닫힌 스트림")
	if out.String() != input {
		t.Fatalf("Flush duplicated or damaged text: %q", out.String())
	}
	if maskAgentText(input) != input {
		t.Fatal("normal Korean text changed")
	}
}

func TestAgentStreamRedactorHoldsIncompleteFieldAcrossLines(t *testing.T) {
	var out strings.Builder
	r := newAgentStreamRedactor(func(s string) { out.WriteString(s) })
	r.Write("정상 첫 줄\n\"password\"\n")
	r.Write(":\n")
	r.Write("\"do-not-emit-this-value")
	if strings.Contains(out.String(), "do-not-emit") {
		t.Fatal("unfinished secret emitted")
	}
	r.Write("\"\n정상 끝 줄\n")
	r.Flush()
	if strings.Contains(out.String(), "do-not-emit") || !strings.Contains(out.String(), "정상 끝 줄") {
		t.Fatalf("bad completed output: %q", out.String())
	}
}

func TestAgentStreamRedactorBoundsPendingSensitiveText(t *testing.T) {
	var out strings.Builder
	r := newAgentStreamRedactor(func(s string) { out.WriteString(s) })
	r.Write(`password: "`)
	block := strings.Repeat("hidden-fragment\n", 1024)
	for i := 0; i < 400; i++ {
		r.Write(block)
	}
	r.Flush()
	if len(r.pending) != 0 || strings.Contains(out.String(), "hidden-fragment") {
		t.Fatal("buffer limit exposed a pending secret")
	}
	if !strings.Contains(out.String(), "출력 길이 제한") || len(out.String()) > 200 {
		t.Fatalf("unbounded redactor output: %d", len(out.String()))
	}
}
