package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Agent text can contain JSON rendered inside another JSON string as well as
// HTTP headers. The quotes/backslashes around a key are therefore part of the
// syntax, rather than a reason to miss an otherwise sensitive field.
const agentSensitiveKey = `(?:proxy[-_ ]?authorization|authorization|set[-_ ]?cookie|cookie|bootstrap[-_ ]?admin[-_ ]?password|password|passwd|api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|client[-_ ]?secret|encryption[-_ ]?key|credential[-_ ]?key[-_ ]?id|connection[-_ ]?string|dsn|secret|token)`

var agentSecretHeader = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(` + agentSensitiveKey + `)([\\"']*)\s*[:=]\s*`)
var agentPossibleHeader = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])` + agentSensitiveKey + `[\\"']*\s*$`)
var agentEncodedHeader = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])((?:[a-z0-9_-]|[\\]+u[0-9a-f]{4}){1,200})([\\"']*)\s*[:=]\s*`)
var agentEncodedPossibleHeader = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])((?:[a-z0-9_-]|[\\]+u[0-9a-f]{4}){1,200})[\\"']*\s*$`)
var agentUnicodeEscape = regexp.MustCompile(`(?i)[\\]+u([0-9a-f]{4})`)
var agentKnownKey = regexp.MustCompile(`(?i)^` + agentSensitiveKey + `$`)
var agentJWTText = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*)*`)
var agentCompactJWT = regexp.MustCompile(`\b[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*`)
var agentURLPassword = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@/\s]+(@)`)

type agentSecretSpan struct {
	start, end int
	complete   bool
	composite  bool
}

// maskAgentText is deliberately not a size limiter: truncating plaintext before
// finding its closing delimiter can itself make a secret look like safe text.
// Callers enforce their own payload bounds after redaction.
func maskAgentText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	matches := agentTextHeaders(s)
	var out strings.Builder
	last := 0
	for _, match := range matches {
		if match[0] < last {
			continue
		}
		span := agentValueSpan(s, match, true)
		if span.start < last || span.end < span.start {
			continue
		}
		out.WriteString(s[last:span.start])
		if span.composite {
			out.WriteString(`"[REDACTED]"`)
		} else {
			out.WriteString("[REDACTED]")
		}
		last = span.end
	}
	out.WriteString(s[last:])
	clean := agentCompactJWT.ReplaceAllStringFunc(out.String(), func(token string) string {
		header, err := base64.RawURLEncoding.DecodeString(strings.SplitN(token, ".", 2)[0])
		if err != nil {
			return token
		}
		var fields map[string]any
		if json.Unmarshal(header, &fields) != nil || fields == nil {
			return token
		}
		return "[REDACTED JWT]"
	})
	clean = agentJWTText.ReplaceAllString(clean, "[REDACTED JWT]")
	return agentURLPassword.ReplaceAllString(clean, "${1}[REDACTED]${2}")
}

func agentDecodedKey(key string) bool {
	for i := 0; i < 3 && strings.Contains(strings.ToLower(key), `\u`); i++ {
		key = agentUnicodeEscape.ReplaceAllStringFunc(key, func(s string) string {
			v, e := strconv.ParseUint(s[len(s)-4:], 16, 16)
			if e != nil {
				return s
			}
			return string(rune(v))
		})
	}
	return agentKnownKey.MatchString(key)
}

func agentTextHeaders(s string) [][]int {
	out := agentSecretHeader.FindAllStringSubmatchIndex(s, -1)
	if !strings.Contains(strings.ToLower(s), `\u`) {
		return out
	}
	for _, m := range agentEncodedHeader.FindAllStringSubmatchIndex(s, -1) {
		if agentDecodedKey(s[m[2]:m[3]]) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// agentValueSpan returns only the value bytes, preserving a quoted value's
// opening/closing delimiters. Quoted strings may span lines or be JSON-escaped
// one or more times. An incomplete value remains pending during streaming.
func agentValueSpan(s string, match []int, final bool) agentSecretSpan {
	start := match[1]
	if start == len(s) {
		return agentSecretSpan{start: start, end: start, complete: final}
	}
	if strings.HasPrefix(s[start:], "[REDACTED]") {
		return agentSecretSpan{start: start, end: start + len("[REDACTED]"), complete: true}
	}
	quoteAt := start
	for quoteAt < len(s) && s[quoteAt] == '\\' {
		quoteAt++
	}
	if quoteAt < len(s) && (s[quoteAt] == '"' || s[quoteAt] == '\'') {
		quote, depth := s[quoteAt], quoteAt-start
		valueStart := quoteAt + 1
		backslashes := 0
		for i := valueStart; i < len(s); i++ {
			if s[i] == '\\' {
				backslashes++
				continue
			}
			if s[i] == quote && backslashes%(2*(depth+1)) == depth {
				return agentSecretSpan{start: valueStart, end: i - depth, complete: true}
			}
			backslashes = 0
		}
		return agentSecretSpan{start: valueStart, end: len(s), complete: final}
	}
	if s[start] == '{' || s[start] == '[' {
		depth, quote, escaped := 0, byte(0), false
		for i := start; i < len(s); i++ {
			c := s[i]
			if quote != 0 {
				if escaped {
					escaped = false
				} else if c == '\\' {
					escaped = true
				} else if c == quote {
					quote = 0
				}
				continue
			}
			switch c {
			case '"', '\'':
				quote = c
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return agentSecretSpan{start: start, end: i + 1, complete: true, composite: true}
				}
			}
		}
		return agentSecretSpan{start: start, end: len(s), complete: final, composite: true}
	}
	// JSON scalar values end at JSON punctuation. For plain headers, mask the
	// entire value line (including all cookie pairs) and folded continuations.
	jsonKey := match[4] >= 0 && match[5] > match[4]
	for i := start; i < len(s); i++ {
		if jsonKey && strings.ContainsRune(",}]", rune(s[i])) {
			return agentSecretSpan{start: start, end: i, complete: true}
		}
		if s[i] == '\n' || s[i] == '\r' {
			next := i
			for next < len(s) && (s[next] == '\n' || s[next] == '\r') {
				next++
			}
			if next == len(s) && !final {
				return agentSecretSpan{start: start, end: len(s), complete: false}
			}
			if next < len(s) && (s[next] == ' ' || s[next] == '\t') {
				continue
			}
			return agentSecretSpan{start: start, end: i, complete: true}
		}
	}
	return agentSecretSpan{start: start, end: len(s), complete: final}
}

const agentRedactionBufferLimit = 4 << 20

// agentStreamRedactor emits complete safe lines. It retains an incomplete
// sensitive field even when the key, separator, or value crosses line breaks.
// Flush is final and idempotent; writes after Flush are ignored. Normal writes
// must be serialized by the SSE reader, like the underlying emit callback.
type agentStreamRedactor struct {
	emit     func(string)
	pending  []byte
	nextScan int
	closed   bool
}

func newAgentStreamRedactor(emit func(string)) *agentStreamRedactor {
	return &agentStreamRedactor{emit: emit}
}

func (r *agentStreamRedactor) Write(chunk string) {
	if r.closed || chunk == "" {
		return
	}
	if len(chunk) > agentRedactionBufferLimit-len(r.pending) {
		r.pending = append(r.pending, chunk[:agentRedactionBufferLimit-len(r.pending)]...)
		r.Flush()
		r.output("\n[출력 길이 제한]")
		return
	}
	r.pending = append(r.pending, chunk...)
	if len(r.pending) < r.nextScan || !strings.ContainsAny(chunk, "\r\n") {
		return
	}
	cut := bytes.LastIndexByte(r.pending, '\n') + 1
	if cr := bytes.LastIndexByte(r.pending, '\r') + 1; cr > cut {
		cut = cr
	}
	if cut == 0 {
		return
	}
	s := string(r.pending)
	for _, match := range agentTextHeaders(s) {
		if match[0] >= cut {
			continue
		}
		span := agentValueSpan(s, match, false)
		if !span.complete || span.end > cut {
			cut = min(cut, match[0])
		}
	}
	if possible := agentPossibleHeader.FindStringIndex(s); possible != nil && possible[0] < cut {
		cut = possible[0]
	}
	if strings.Contains(strings.ToLower(s), `\u`) {
		if m := agentEncodedPossibleHeader.FindStringSubmatchIndex(s); m != nil && m[0] < cut && agentDecodedKey(s[m[2]:m[3]]) {
			cut = m[0]
		}
	}
	if cut == 0 {
		// Exponential retry spacing bounds rescanning for adversarial strings
		// with millions of newlines inside one unfinished quoted secret.
		r.nextScan = max(1024, len(r.pending)*2)
		return
	}
	r.output(maskAgentText(s[:cut]))
	copy(r.pending, r.pending[cut:])
	r.pending = r.pending[:len(r.pending)-cut]
	r.nextScan = 0
}

func (r *agentStreamRedactor) Flush() {
	if r.closed {
		return
	}
	r.closed = true
	if len(r.pending) != 0 {
		r.output(maskAgentText(string(r.pending)))
	}
	r.pending = nil
}

func (r *agentStreamRedactor) output(s string) {
	if r.emit != nil && s != "" {
		r.emit(s)
	}
}
