package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

func TestGraphQLResponseBudgetJSONEscapesAndScalars(t *testing.T) {
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	values := []any{
		nil, true, false, "", "한국어 😀", "<&>\"\\\b\f\n\r\t\x00\x1f\u2028\u2029", string(allBytes),
		"\xff\xc0\xaf\xef\xbf\xbd", int(0), int64(math.MinInt64), int64(math.MaxInt64),
		float64(0), math.MaxFloat64, math.SmallestNonzeroFloat64, -math.MaxFloat64,
		[]string(nil), []string{}, []string{"한글", "<&>\n"},
		[]ast.DirectiveLocation(nil), []ast.DirectiveLocation{ast.LocationField, ast.LocationQuery},
	}
	for i, value := range values {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			encoded, e := json.Marshal(value)
			if e != nil {
				t.Fatal(e)
			}
			b := graphResponseBudget{remaining: 10000}
			if e := b.scalar(value); e != nil {
				t.Fatal(e)
			}
			charged := 10000 - b.remaining
			if charged < len(encoded) {
				t.Fatalf("budget undercounts JSON: charged=%d actual=%d", charged, len(encoded))
			}
			// Even malformed UTF-8 or HTML escaping must fail before an encoded
			// value larger than the remaining budget can enter the response.
			b = graphResponseBudget{remaining: len(encoded) - 1}
			if e := b.scalar(value); e == nil {
				t.Fatal("accepted scalar larger than remaining budget")
			}
		})
	}
	for _, value := range []any{math.NaN(), math.Inf(1), map[string]any{"unchecked": true}} {
		b := graphResponseBudget{remaining: 1000}
		if e := b.scalar(value); e == nil {
			t.Fatal("unsupported value bypassed response accounting")
		}
	}
}

func TestGraphQLResponseBudgetProjectionAndAliasAmplification(t *testing.T) {
	doc, e := gqlparser.LoadQuery(hunterGraphQLSchema, `{agentRuns(first:2){items{__typename a:result b:result tasks{id title} scans{id}} total}}`)
	if e != nil {
		t.Fatal(e)
	}
	object := graphObject{Type: "AgentRunPage", Data: map[string]any{
		"total": 2,
		"items": []graphObject{
			{Type: "AgentRun", Data: map[string]any{"result": "<&> 한글\n", "tasks": []graphObject{{Type: "AgentTask", Data: map[string]any{"id": "x", "title": "작업"}}}, "scans": []graphObject{}}},
			{Type: "AgentRun", Data: map[string]any{"result": "둘째", "tasks": []graphObject{}, "scans": []graphObject{}}},
		},
	}}
	selection := doc.Operations[0].SelectionSet[0].(*ast.Field).SelectionSet
	x := &graphExecutor{r: httptest.NewRequest("GET", "/api/graphql", nil), doc: doc, budget: newGraphResponseBudget(4096)}
	data, err := x.project(object, selection)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(map[string]any{"data": data}); err != nil {
		t.Fatal(err)
	}
	charged := 4096 - x.budget.remaining
	if charged < encoded.Len() {
		t.Fatalf("projection missed JSON framing: charged=%d actual=%d", charged, encoded.Len())
	}
	for _, limit := range []int{charged, charged - 1} {
		x := &graphExecutor{r: httptest.NewRequest("GET", "/api/graphql", nil), doc: doc, budget: newGraphResponseBudget(limit)}
		_, err := x.project(object, selection)
		if (err == nil) != (limit == charged) {
			t.Fatalf("projection budget boundary limit=%d: %v", limit, err)
		}
	}

	var aliases strings.Builder
	for i := range 90 {
		fmt.Fprintf(&aliases, " a%d:result", i)
	}
	doc, e = gqlparser.LoadQuery(hunterGraphQLSchema, `{agentRuns(first:100){items{`+aliases.String()+`}}}`)
	if e != nil {
		t.Fatal(e)
	}
	items := make([]graphObject, 100)
	for i := range items {
		items[i] = graphObject{Type: "AgentRun", Data: map[string]any{"result": strings.Repeat("한", 128)}}
	}
	x = &graphExecutor{r: httptest.NewRequest("GET", "/api/graphql", nil), doc: doc, budget: newGraphResponseBudget(4096)}
	if cost := x.cost(doc.Operations[0].SelectionSet, "Query", 25); cost != 9002 {
		t.Fatalf("alias fixture should pass original complexity limit: %d", cost)
	}
	selection = doc.Operations[0].SelectionSet[0].(*ast.Field).SelectionSet
	data, err = x.project(graphObject{Type: "AgentRunPage", Data: map[string]any{"items": items}}, selection)
	var fault *graphFault
	if !errors.As(err, &fault) || fault.status != 400 || fault.code != "QUERY_LIMIT" || data != nil {
		t.Fatalf("amplified aliases must fail without partial response: %v", err)
	}
	if x.nodes >= 90 {
		t.Fatalf("projection should stop within the first small item, processed=%d", x.nodes)
	}
}

func TestGraphQLResponseBudgetHTTPRejectsAmplifiedResults(t *testing.T) {
	a, base, server, admin := reportTestApp(t)
	id, _ := reportFixture(t, a, base, admin, "completed")
	// One 30KB stored result is enough to exercise the real 4MiB limit;
	// no amplified response is encoded or transmitted by the test.
	result, e := a.encrypt(strings.Repeat("<", 30000))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := a.DB.Exec(context.Background(), `UPDATE agent_runs SET result=$2 WHERE id=$1`, id, result); e != nil {
		t.Fatal(e)
	}
	var fields strings.Builder
	for i := range 50 {
		fmt.Fprintf(&fields, " r%d:result", i)
	}
	query := fmt.Sprintf(`{agentRun(id:%q){%s}}`, id, fields.String())
	code, body, _ := request(t, server, "POST", "/api/graphql", map[string]any{"query": query}, admin, true)
	if code != 400 || len(body) > 1024 || !bytes.Contains(body, []byte(`"QUERY_LIMIT"`)) || !bytes.Contains(body, []byte(`"data":null`)) || bytes.Contains(body, []byte(`"r0"`)) {
		t.Fatalf("amplified query must return only a small limit error: status=%d bytes=%d", code, len(body))
	}
	code, body, _ = request(t, server, "POST", "/api/graphql", map[string]any{"query": fmt.Sprintf(`{agentRun(id:%q){result}}`, id)}, admin, true)
	if code != 200 || len(body) >= graphResponseMaxBytes || !bytes.Contains(body, []byte(`\u003c`)) {
		t.Fatalf("ordinary authorized result failed: status=%d bytes=%d", code, len(body))
	}
}
