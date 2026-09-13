package app

import (
	"errors"
	"math"
	"unicode/utf8"

	"github.com/vektah/gqlparser/v2/ast"
)

const graphResponseMaxBytes = 4 << 20

// Charge response bytes while projecting, before JSON encoding can amplify a
// shared long string through aliases. The final encoder escapes HTML by default.
type graphResponseBudget struct {
	remaining int
}

func newGraphResponseBudget(limit int) graphResponseBudget {
	// The projected root object is wrapped by jsonResponse as {"data":...}\n.
	return graphResponseBudget{remaining: limit - len("{\"data\":}\n")}
}

func (b *graphResponseBudget) take(n int) error {
	if n < 0 || n > b.remaining {
		return &graphFault{400, "QUERY_LIMIT", "응답 크기 한도 4MiB를 초과했습니다. 조회 행이나 선택 필드를 줄이세요"}
	}
	b.remaining -= n
	return nil
}

// text counts encoding/json string escaping without allocating an encoded copy.
// Invalid UTF-8 bytes each become six-byte \ufffd escapes, not one replacement
// for the whole malformed sequence. U+2028/U+2029 and HTML characters also escape.
func (b *graphResponseBudget) text(s string) error {
	if e := b.take(2); e != nil { // Quotes.
		return e
	}
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		n := size
		switch {
		case r == utf8.RuneError && size == 1:
			n = 6
		case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
			n = 2
		case r < 0x20 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029':
			n = 6
		}
		if e := b.take(n); e != nil {
			return e
		}
		s = s[size:]
	}
	return nil
}

func (b *graphResponseBudget) scalar(v any) error {
	switch q := v.(type) {
	case nil:
		return b.take(4)
	case string:
		return b.text(q)
	case bool:
		if q {
			return b.take(4)
		}
		return b.take(5)
	case int, int64:
		return b.take(20) // Largest signed 64-bit integer, including its sign.
	case float64:
		if math.IsNaN(q) || math.IsInf(q, 0) {
			return errors.New("unsupported GraphQL number")
		}
		return b.take(32) // Conservative finite float64 JSON representation.
	case []string:
		if q == nil {
			return b.take(4)
		}
		if e := b.array(len(q)); e != nil {
			return e
		}
		for _, value := range q {
			if e := b.text(value); e != nil {
				return e
			}
		}
		return nil
	case []ast.DirectiveLocation:
		if q == nil {
			return b.take(4)
		}
		if e := b.array(len(q)); e != nil {
			return e
		}
		for _, value := range q {
			if e := b.text(string(value)); e != nil {
				return e
			}
		}
		return nil
	default:
		// Do not let a new resolver value bypass the budget through JSON marshaling.
		return errors.New("unsupported GraphQL scalar type")
	}
}

func (b *graphResponseBudget) array(length int) error {
	if e := b.take(2); e != nil {
		return e
	}
	if length > 0 {
		return b.take(length - 1)
	}
	return nil
}
