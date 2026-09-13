package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestGraphQLQueriesAuthorizationAndLimits(t *testing.T) {
	a, base, s, admin := reportTestApp(t)
	id, sid := reportFixture(t, a, base, admin, "running")
	query := `query Read($n:Int!,$id:ID!){ a:services(first:$n){total hasMore items {...S}} b:service(id:$id){id ...S} agentRuns(first:1){total items{id title status result tasks{title status} scans{id status}}} __type(name:"Query"){name fields{name args{name defaultValue type{kind name ofType{kind name}}}}} } fragment S on Service { name id }`
	code, b, _ := request(t, s, "POST", "/api/graphql", map[string]any{"query": query, "variables": map[string]any{"n": 1, "id": sid}}, admin, true)
	if code != 200 {
		t.Fatalf("query failed %d: %s", code, b)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if got["errors"] != nil || !strings.Contains(string(b), id) || !strings.Contains(string(b), "한국어 보고서 서비스") || strings.Contains(string(b), "should-not-appear") {
		t.Fatalf("query content: %s", b)
	}
	code, b, _ = request(t, s, "GET", "/api/graphql?query="+url.QueryEscape(`{__schema{queryType{name} mutationType{name} types{name kind} directives{name locations}}}`), nil, admin, false)
	if code != 200 || !strings.Contains(string(b), `"mutationType":null`) {
		t.Fatalf("introspection: %d %s", code, b)
	}
	if code, _, _ := request(t, s, "GET", "/api/graphql/schema", nil, "", false); code != 401 {
		t.Fatal("unauthenticated introspection")
	}
	cases := []string{`mutation { services {total} }`, `subscription {services{total}}`, `{services(first:101){total}}`, `{services(offset:10001){total}}`, `{service(id:"x"){secret}}`, `{...A} fragment A on Query {...A}`, `query X($n:Int!){services(first:$n){total}}`, `{agentRuns(first:100){items{tasks{id title status} scans{id profile status}}}}`}
	for _, q := range cases {
		if code, _, _ := request(t, s, "POST", "/api/graphql", map[string]any{"query": q}, admin, true); code != 400 {
			t.Fatalf("invalid query accepted %d: %s", code, q)
		}
	}
	deep := `{__type(name:"Query"){fields{type{ofType{ofType{ofType{ofType{ofType{ofType{name}}}}}}}}}}`
	if code, _, _ := request(t, s, "POST", "/api/graphql", map[string]any{"query": deep}, admin, true); code != 400 {
		t.Fatal("deep query accepted")
	}
	for _, value := range []any{1.5, "1", float64(2147483648)} {
		if code, _, _ := request(t, s, "POST", "/api/graphql", map[string]any{"query": `query($n:Int!){services(first:$n){total}}`, "variables": map[string]any{"n": value}}, admin, true); code != 400 {
			t.Fatalf("invalid integer variable accepted: %v", value)
		}
	}
	key := workflowTestKey(t, base, admin, []string{"services:read"})
	if code, _, _ := request(t, s, "POST", "/api/graphql", map[string]any{"query": `{services{total} agentRuns{total}}`}, key, true); code != 403 {
		t.Fatal("admin key scope bypass")
	}
	if code, b, _ := request(t, s, "POST", "/api/graphql", map[string]any{"query": `{services{total items{id}}}`}, key, true); code != 200 || strings.Contains(string(b), "errors") {
		t.Fatal("scoped service query rejected")
	}
}
func TestGraphQLCurrentParentIsolationAndFragments(t *testing.T) {
	a, base, s, admin := reportTestApp(t)
	_, sid := reportFixture(t, a, base, admin, "failed")
	u := mustRequest(t, base, "POST", "/api/users", map[string]any{"username": "gql-owner", "name": "Owner", "role": "analyst", "team": "red", "password": "test-password-1234"}, admin, 201)
	credential := loginTest(t, base, "gql-owner", "test-password-1234")
	fid := newID()
	data, _ := json.Marshal(map[string]any{"title": "권한 없는 부모 발견", "service_id": sid, "severity": "high", "status": "candidate", "secret": "forbidden"})
	if _, e := a.DB.Exec(context.Background(), `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'findings',$2,$3)`, fid, str(u, "id"), data); e != nil {
		t.Fatal(e)
	}
	q := fmt.Sprintf(`{ findings {total items{id title}} finding(id:%q){id title} }`, fid)
	code, b, _ := request(t, s, "POST", "/api/graphql", map[string]any{"query": q}, credential, true)
	if code != 200 || strings.Contains(string(b), fid) || !strings.Contains(string(b), `"total":0`) {
		t.Fatalf("child owner bypassed current parent: %d %s", code, b)
	}
	if _, e := a.DB.Exec(context.Background(), `UPDATE resources SET owner_id=$2 WHERE id=$1`, sid, str(u, "id")); e != nil {
		t.Fatal(e)
	}
	code, b, _ = request(t, s, "POST", "/api/graphql", map[string]any{"query": q}, credential, true)
	if code != 200 || !strings.Contains(string(b), fid) {
		t.Fatal("parent permission change ignored")
	}
	q = `query A($skip:Boolean!){s:services{items{id ...F name @skip(if:$skip)}} s:services{total items{createdAt}}} fragment F on Service {__typename name @include(if:false)}`
	code, b, _ = request(t, s, "POST", "/api/graphql", map[string]any{"query": q, "variables": map[string]any{"skip": true}, "operationName": "A"}, credential, true)
	if code != 200 || strings.Contains(string(b), `"name"`) || !strings.Contains(string(b), `"createdAt"`) || !strings.Contains(string(b), `"__typename":"Service"`) {
		t.Fatalf("selection merge/directives: %d %s", code, b)
	}
}
