package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"
)

const hunterGraphQLSDL = `
"Authenticated, read-only Hunter API. Lists are bounded to 100 rows per page."
type Query {
 services(first: Int = 25, offset: Int = 0): ServicePage!
 service(id: ID!): Service
 findings(first: Int = 25, offset: Int = 0, serviceId: ID): FindingPage!
 finding(id: ID!): Finding
 scans(first: Int = 25, offset: Int = 0, serviceId: ID): ScanPage!
 scan(id: ID!): Scan
 agentRuns(first: Int = 25, offset: Int = 0, serviceId: ID): AgentRunPage!
 agentRun(id: ID!): AgentRun
}
type ServicePage { items: [Service!]!, total: Int!, offset: Int!, hasMore: Boolean! }
type FindingPage { items: [Finding!]!, total: Int!, offset: Int!, hasMore: Boolean! }
type ScanPage { items: [Scan!]!, total: Int!, offset: Int!, hasMore: Boolean! }
type AgentRunPage { items: [AgentRun!]!, total: Int!, offset: Int!, hasMore: Boolean! }
type Service { id: ID!, name: String!, team: String!, environment: String!, criticality: String!, createdAt: String!, updatedAt: String! }
type Finding { id: ID!, serviceId: ID!, title: String!, severity: String!, status: String!, component: String!, cve: String!, assignee: String!, dueDate: String!, createdAt: String!, updatedAt: String! }
type Scan { id: ID!, serviceId: ID!, profile: String!, status: String!, createdAt: String!, updatedAt: String! }
type AgentRun { id: ID!, serviceId: ID!, title: String!, status: String!, result: String!, modelCalls: Int!, toolCalls: Int!, inputTokens: Float!, outputTokens: Float!, createdAt: String!, updatedAt: String!, tasks: [AgentTask!]!, scans: [Scan!]! }
type AgentTask { id: String!, title: String!, status: String! }
`

var hunterGraphQLSchema = gqlparser.MustLoadSchema(&ast.Source{Name: "hunter.graphql", Input: hunterGraphQLSDL})

type graphFault struct {
	status        int
	code, message string
}

func (e *graphFault) Error() string { return e.message }
func graphFailure(w http.ResponseWriter, e error) {
	status, code, message := 500, "INTERNAL_ERROR", "자료를 조회하지 못했습니다"
	var f *graphFault
	if errors.As(e, &f) {
		status, code, message = f.status, f.code, f.message
	}
	jsonResponse(w, status, map[string]any{"data": nil, "errors": []any{map[string]any{"message": message, "extensions": map[string]any{"code": code}}}})
}
func (a *App) registerGraphQL(m *http.ServeMux) {
	m.HandleFunc("GET /api/graphql", a.protect("", a.graphQL))
	m.HandleFunc("POST /api/graphql", a.protect("", a.graphQL))
	m.HandleFunc("GET /api/graphql/schema", a.protect("", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/graphql; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(hunterGraphQLSDL))
	}))
}

type graphRequest struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
}
type graphExecutor struct {
	a        *App
	r        *http.Request
	u        User
	doc      *ast.QueryDocument
	vars     map[string]any
	nodes    int
	refs     []modelResourceRef
	required map[string]bool
	runIDs   []string
}

func (a *App) graphQL(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var in graphRequest
	if r.Method == "GET" {
		in.Query = r.URL.Query().Get("query")
		in.OperationName = r.URL.Query().Get("operationName")
		if len(r.URL.RawQuery) > 65536 {
			graphFailure(w, &graphFault{400, "QUERY_LIMIT", "조회 요청 크기 한도를 초과했습니다"})
			return
		}
		if raw := r.URL.Query().Get("variables"); raw != "" {
			if json.Unmarshal([]byte(raw), &in.Variables) != nil {
				graphFailure(w, &graphFault{400, "BAD_REQUEST", "변수 JSON 형식을 확인하세요"})
				return
			}
		}
	} else {
		b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
		if e != nil || len(b) > 65536 || json.Unmarshal(b, &in) != nil {
			graphFailure(w, &graphFault{400, "BAD_REQUEST", "하나의 GraphQL JSON 요청을 64KiB 이내로 전송하세요"})
			return
		}
	}
	if len(in.Query) == 0 || len(in.Query) > 32768 {
		graphFailure(w, &graphFault{400, "QUERY_LIMIT", "GraphQL 쿼리는 1~32,768바이트입니다"})
		return
	}
	doc, e := parser.ParseQueryWithTokenLimit(&ast.Source{Input: in.Query}, 5000)
	if e != nil {
		graphFailure(w, &graphFault{400, "BAD_QUERY", "GraphQL 문법 또는 토큰 한도를 확인하세요"})
		return
	}
	if len(doc.Operations) > 4 || len(doc.Fragments) > 32 {
		graphFailure(w, &graphFault{400, "QUERY_LIMIT", "작업·조각 수 한도를 초과했습니다"})
		return
	}
	for _, op := range doc.Operations {
		if op.Operation != ast.Query {
			graphFailure(w, &graphFault{400, "READ_ONLY", "조회 query만 지원합니다. mutation과 subscription은 지원하지 않습니다"})
			return
		}
		n := 0
		if e := graphBound(doc, op.SelectionSet, 1, &n, map[string]bool{}); e != nil {
			graphFailure(w, e)
			return
		}
	}
	if errs := validator.Validate(hunterGraphQLSchema, doc); len(errs) > 0 {
		graphFailure(w, &graphFault{400, "BAD_QUERY", "GraphQL 필드·인자·조각 정의를 확인하세요"})
		return
	}
	op := doc.Operations.ForName(in.OperationName)
	if op == nil || (in.OperationName == "" && len(doc.Operations) != 1) {
		graphFailure(w, &graphFault{400, "BAD_QUERY", "실행할 operationName을 지정하세요"})
		return
	}
	vars, e := validator.VariableValues(hunterGraphQLSchema, op, in.Variables)
	if e != nil {
		graphFailure(w, &graphFault{400, "BAD_VARIABLES", "GraphQL 변수 형식과 필수값을 확인하세요"})
		return
	}
	for _, def := range op.VariableDefinitions {
		if def.Type.NamedType == "Int" {
			if v, ok := vars[def.Variable]; ok && v != nil {
				valid := false
				switch n := v.(type) {
				case int64:
					valid = n >= -2147483648 && n <= 2147483647
				case int:
					valid = int64(n) >= -2147483648 && int64(n) <= 2147483647
				case float64:
					valid = n == math.Trunc(n) && n >= -2147483648 && n <= 2147483647
				}
				if !valid {
					graphFailure(w, &graphFault{400, "BAD_VARIABLES", "Int 변수는 32비트 정수여야 합니다"})
					return
				}
			}
		}
	}
	x := &graphExecutor{a: a, r: r, u: currentUser(r), doc: doc, vars: vars, required: map[string]bool{}}
	if x.cost(op.SelectionSet, "Query", 25) > 10000 {
		graphFailure(w, &graphFault{400, "QUERY_LIMIT", "예상 응답 복잡도 한도 10,000을 초과했습니다"})
		return
	}
	data, e := x.project(graphObject{Type: "Query"}, op.SelectionSet)
	if e != nil {
		graphFailure(w, e)
		return
	}
	if e = x.current(); e != nil {
		graphFailure(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, 200, map[string]any{"data": data})
}
func graphBound(doc *ast.QueryDocument, set ast.SelectionSet, depth int, n *int, trail map[string]bool) error {
	if len(set) == 0 {
		return nil
	}
	if depth > 8 {
		return &graphFault{400, "QUERY_LIMIT", "조회 깊이는 최대 8단계입니다"}
	}
	for _, sel := range set {
		*n++
		if *n > 500 {
			return &graphFault{400, "QUERY_LIMIT", "펼친 필드·조각 한도 500개를 초과했습니다"}
		}
		switch v := sel.(type) {
		case *ast.Field:
			if e := graphBound(doc, v.SelectionSet, depth+1, n, trail); e != nil {
				return e
			}
		case *ast.InlineFragment:
			if e := graphBound(doc, v.SelectionSet, depth, n, trail); e != nil {
				return e
			}
		case *ast.FragmentSpread:
			if trail[v.Name] {
				return &graphFault{400, "BAD_QUERY", "순환 조각은 지원하지 않습니다"}
			}
			f := doc.Fragments.ForName(v.Name)
			if f != nil {
				trail[v.Name] = true
				e := graphBound(doc, f.SelectionSet, depth, n, trail)
				delete(trail, v.Name)
				if e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func (x *graphExecutor) require(scopes ...string) error {
	for _, s := range scopes {
		if !hasString(x.u.Scopes, s) {
			return &graphFault{403, "FORBIDDEN", "이 자료의 현재 조회 권한이 없습니다"}
		}
		x.required[s] = true
	}
	return nil
}
func (x *graphExecutor) current() error {
	fresh, e := x.a.authenticate(x.r)
	if e != nil || fresh.ID != x.u.ID || fresh.Role != x.u.Role || fresh.Team != x.u.Team {
		return &graphFault{403, "FORBIDDEN", "조회 중 사용자 권한이 변경되었습니다"}
	}
	for s := range x.required {
		if !hasString(fresh.Scopes, s) {
			return &graphFault{403, "FORBIDDEN", "조회 중 키 또는 역할 권한이 변경되었습니다"}
		}
	}
	for _, ref := range x.refs {
		v, e := x.a.resource(x.r.Context(), ref.Kind, ref.ID)
		if e != nil || !x.a.canAccess(x.r.Context(), fresh, v) {
			return &graphFault{403, "FORBIDDEN", "조회 중 자료 접근 권한이 변경되었습니다"}
		}
		if p := str(v.Data, "service_id"); p != "" {
			s, e := x.a.resource(x.r.Context(), "services", p)
			if e != nil || !x.a.canAccess(x.r.Context(), fresh, s) {
				return &graphFault{403, "FORBIDDEN", "조회 중 부모 서비스 권한이 변경되었습니다"}
			}
		}
	}
	for _, id := range x.runIDs {
		v, e := x.a.agentRun(x.r.Context(), id)
		if e != nil || !x.a.canReadAgent(x.r.Context(), fresh, v) {
			return &graphFault{403, "FORBIDDEN", "조회 중 실행 접근 권한이 변경되었습니다"}
		}
	}
	return nil
}

type graphObject struct {
	Type       string
	Data       map[string]any
	Definition *ast.Definition
	TypeRef    *ast.Type
	Field      *ast.FieldDefinition
	Argument   *ast.ArgumentDefinition
	Enum       *ast.EnumValueDefinition
	Directive  *ast.DirectiveDefinition
}

func (x *graphExecutor) fields(set ast.SelectionSet, typ string) []*ast.Field {
	out := []*ast.Field{}
	positions := map[string]int{}
	var walk func(ast.SelectionSet)
	walk = func(ss ast.SelectionSet) {
		for _, sel := range ss {
			var dirs ast.DirectiveList
			switch f := sel.(type) {
			case *ast.Field:
				dirs = f.Directives
			case *ast.InlineFragment:
				dirs = f.Directives
			case *ast.FragmentSpread:
				dirs = f.Directives
			}
			skip := false
			for _, d := range dirs {
				v, _ := d.Arguments.ForName("if").Value.Value(x.vars)
				if d.Name == "skip" && v == true || d.Name == "include" && v == false {
					skip = true
				}
			}
			if skip {
				continue
			}
			switch f := sel.(type) {
			case *ast.Field:
				key := f.Alias
				if key == "" {
					key = f.Name
				}
				if pos, ok := positions[key]; ok {
					out[pos].SelectionSet = append(out[pos].SelectionSet, f.SelectionSet...)
				} else {
					copy := *f
					copy.SelectionSet = append(ast.SelectionSet{}, f.SelectionSet...)
					positions[key] = len(out)
					out = append(out, &copy)
				}
			case *ast.InlineFragment:
				if f.TypeCondition == "" || f.TypeCondition == typ {
					walk(f.SelectionSet)
				}
			case *ast.FragmentSpread:
				if f := x.doc.Fragments.ForName(f.Name); f != nil && f.TypeCondition == typ {
					walk(f.SelectionSet)
				}
			}
		}
	}
	walk(set)
	return out
}
func (x *graphExecutor) project(o graphObject, set ast.SelectionSet) (map[string]any, error) {
	out := map[string]any{}
	for _, f := range x.fields(set, o.Type) {
		x.nodes++
		if x.nodes > 10000 {
			return nil, &graphFault{400, "QUERY_LIMIT", "응답 복잡도 한도 10,000을 초과했습니다"}
		}
		if x.r.Context().Err() != nil {
			return nil, &graphFault{503, "TIMEOUT", "조회 제한 시간을 초과했습니다"}
		}
		key := f.Alias
		if key == "" {
			key = f.Name
		}
		if f.Name == "__typename" {
			out[key] = o.Type
			continue
		}
		v, e := x.resolve(o, f)
		if e != nil {
			return nil, e
		}
		switch q := v.(type) {
		case graphObject:
			b, e := x.project(q, f.SelectionSet)
			if e != nil {
				return nil, e
			}
			out[key] = b
		case []graphObject:
			items := []any{}
			for _, item := range q {
				b, e := x.project(item, f.SelectionSet)
				if e != nil {
					return nil, e
				}
				items = append(items, b)
			}
			out[key] = items
		default:
			out[key] = v
		}
	}
	return out, nil
}
func graphPageArgs(f *ast.Field, vars map[string]any) (int, int, string, error) {
	args := f.ArgumentMap(vars)
	first, offset := 25, 0
	if n, ok := args["first"]; ok && n != nil {
		first = graphInt(n)
	}
	if n, ok := args["offset"]; ok && n != nil {
		offset = graphInt(n)
	}
	if first < 1 || first > 100 || offset < 0 || offset > 10000 {
		return 0, 0, "", &graphFault{400, "PAGE_LIMIT", "first는 1~100, offset은 0~10,000입니다"}
	}
	sid, _ := args["serviceId"].(string)
	return first, offset, sid, nil
}
func graphResource(v domainResource) graphObject {
	typ := map[string]string{"services": "Service", "findings": "Finding", "scans": "Scan"}[v.Kind]
	data := map[string]any{"id": v.ID, "createdAt": v.CreatedAt.UTC().Format(time.RFC3339Nano), "updatedAt": v.UpdatedAt.UTC().Format(time.RFC3339Nano)}
	fields := map[string]string{"name": "name", "team": "team", "environment": "environment", "criticality": "criticality", "serviceId": "service_id", "title": "title", "severity": "severity", "status": "status", "component": "component", "cve": "cve", "assignee": "assignee", "dueDate": "due_date", "profile": "profile"}
	for to, from := range fields {
		data[to] = reportText(str(v.Data, from), 2000)
	}
	return graphObject{Type: typ, Data: data}
}
func (x *graphExecutor) resourceDetail(kind, id string) (any, error) {
	if e := x.require(kind + ":read"); e != nil {
		return nil, e
	}
	v, e := x.a.resource(x.r.Context(), kind, id)
	if e != nil || !x.a.canAccess(x.r.Context(), x.u, v) {
		return nil, nil
	}
	if p := str(v.Data, "service_id"); p != "" {
		s, e := x.a.resource(x.r.Context(), "services", p)
		if e != nil || !x.a.canAccess(x.r.Context(), x.u, s) {
			return nil, nil
		}
	}
	x.refs = append(x.refs, modelResourceRef{Kind: kind, ID: id})
	return graphResource(v), nil
}
func (x *graphExecutor) resources(kind string, f *ast.Field) (any, error) {
	if e := x.require(kind + ":read"); e != nil {
		return nil, e
	}
	first, offset, sid, e := graphPageArgs(f, x.vars)
	if e != nil {
		return nil, e
	}
	where := ` r.kind=$1 AND ($2 OR r.owner_id=$3 OR (r.kind='services' AND $4<>'' AND r.data->>'team'=$4) OR (s.id IS NOT NULL AND (s.owner_id=$3 OR ($4<>'' AND s.data->>'team'=$4)))) AND (r.kind='services' OR (s.id IS NOT NULL AND ($2 OR s.owner_id=$3 OR ($4<>'' AND s.data->>'team'=$4)))) AND ($5='' OR r.data->>'service_id'=$5)`
	args := []any{kind, elevated(x.u), x.u.ID, leadTeam(x.u), sid}
	var total int
	base := ` FROM resources r LEFT JOIN resources s ON s.id=r.data->>'service_id' AND s.kind='services' WHERE ` + where
	if e := x.a.DB.QueryRow(x.r.Context(), `SELECT count(*)`+base, args...).Scan(&total); e != nil {
		return nil, e
	}
	rows, e := x.a.DB.Query(x.r.Context(), `SELECT r.id,r.kind,r.owner_id,r.data,r.created_at,r.updated_at`+base+` ORDER BY r.created_at DESC,r.id LIMIT $6 OFFSET $7`, append(args, first, offset)...)
	if e != nil {
		return nil, e
	}
	items := []graphObject{}
	for rows.Next() {
		v, e := scanResource(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, graphResource(v))
		x.refs = append(x.refs, modelResourceRef{Kind: kind, ID: v.ID})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	return graphObject{Type: map[string]string{"services": "ServicePage", "findings": "FindingPage", "scans": "ScanPage"}[kind], Data: map[string]any{"items": items, "total": total, "offset": offset, "hasMore": offset+len(items) < total}}, nil
}
func (x *graphExecutor) agent(id string) (any, error) {
	if e := x.require("agents:read", "services:read", "findings:read", "scans:read"); e != nil {
		return nil, e
	}
	v, scans, e := x.a.reportRun(x.r.Context(), x.u, id)
	if e != nil {
		return nil, nil
	}
	x.runIDs = append(x.runIDs, id)
	tasks := []graphObject{}
	for i, t := range v.Tasks {
		if i == 100 {
			break
		}
		tasks = append(tasks, graphObject{Type: "AgentTask", Data: map[string]any{"id": reportText(t["id"], 80), "title": reportText(t["title"], 500), "status": reportText(t["status"], 80)}})
	}
	ss := []graphObject{}
	for i, s := range scans {
		if i == 100 {
			break
		}
		ss = append(ss, graphResource(s))
		x.refs = append(x.refs, modelResourceRef{Kind: "scans", ID: s.ID})
	}
	return graphObject{Type: "AgentRun", Data: map[string]any{"id": v.ID, "serviceId": v.ServiceID, "title": reportText(v.Title, 200), "status": v.Status, "result": reportText(v.Result, 30000), "modelCalls": v.ModelCalls, "toolCalls": v.ToolCalls, "inputTokens": v.InputTokens, "outputTokens": v.OutputTokens, "createdAt": v.CreatedAt.UTC().Format(time.RFC3339Nano), "updatedAt": v.UpdatedAt.UTC().Format(time.RFC3339Nano), "tasks": tasks, "scans": ss}}, nil
}
func (x *graphExecutor) agents(f *ast.Field) (any, error) {
	if e := x.require("agents:read", "services:read", "findings:read", "scans:read"); e != nil {
		return nil, e
	}
	first, offset, sid, e := graphPageArgs(f, x.vars)
	if e != nil {
		return nil, e
	}
	base := ` FROM agent_runs a JOIN resources s ON s.id=a.service_id AND s.kind='services' WHERE ($1 OR s.owner_id=$2 OR ($3<>'' AND s.data->>'team'=$3)) AND ($4='' OR a.service_id=$4)`
	args := []any{elevated(x.u), x.u.ID, leadTeam(x.u), sid}
	var total int
	if e := x.a.DB.QueryRow(x.r.Context(), `SELECT count(*)`+base, args...).Scan(&total); e != nil {
		return nil, e
	}
	rows, e := x.a.DB.Query(x.r.Context(), `SELECT a.id`+base+` ORDER BY a.created_at DESC,a.id LIMIT $5 OFFSET $6`, append(args, first, offset)...)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e := rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	items := []graphObject{}
	for _, id := range ids {
		v, e := x.agent(id)
		if e != nil {
			return nil, e
		}
		if o, ok := v.(graphObject); ok {
			items = append(items, o)
		}
	}
	return graphObject{Type: "AgentRunPage", Data: map[string]any{"items": items, "total": total, "offset": offset, "hasMore": offset+len(ids) < total}}, nil
}
func (x *graphExecutor) resolve(o graphObject, f *ast.Field) (any, error) {
	if o.Type == "Query" {
		args := f.ArgumentMap(x.vars)
		id, _ := args["id"].(string)
		switch f.Name {
		case "__schema":
			return graphObject{Type: "__Schema"}, nil
		case "__type":
			name, _ := args["name"].(string)
			if d := hunterGraphQLSchema.Types[name]; d != nil {
				return graphObject{Type: "__Type", Definition: d}, nil
			}
			return nil, nil
		case "services", "findings", "scans":
			return x.resources(f.Name, f)
		case "service":
			return x.resourceDetail("services", id)
		case "finding":
			return x.resourceDetail("findings", id)
		case "scan":
			return x.resourceDetail("scans", id)
		case "agentRuns":
			return x.agents(f)
		case "agentRun":
			return x.agent(id)
		}
	}
	if strings.HasPrefix(o.Type, "__") {
		return x.introspection(o, f)
	}
	return o.Data[f.Name], nil
}
func graphDefault(v *ast.Value) any {
	if v == nil {
		return nil
	}
	return v.String()
}
func graphDeprecated(d ast.DirectiveList) (bool, any) {
	if v := d.ForName("deprecated"); v != nil {
		if a := v.Arguments.ForName("reason"); a != nil {
			return true, a.Value.Raw
		}
		return true, "No longer supported"
	}
	return false, nil
}

// Reject multiplicative list expansion before issuing any resolver SQL.
func (x *graphExecutor) cost(set ast.SelectionSet, typ string, pageSize int) int {
	total := 0
	for _, f := range x.fields(set, typ) {
		if typ == "Query" && strings.HasPrefix(f.Name, "__") {
			continue
		}
		n := pageSize
		if typ == "Query" {
			if first, ok := f.ArgumentMap(x.vars)["first"]; ok && first != nil {
				n = graphInt(first)
			}
		}
		multiplier := 1
		if f.Definition != nil && f.Definition.Type.Elem != nil {
			multiplier = 100
			if f.Name == "items" {
				multiplier = n
			}
		}
		child := 0
		if f.Definition != nil && len(f.SelectionSet) > 0 {
			child = x.cost(f.SelectionSet, f.Definition.Type.Name(), n)
		}
		total += 1 + multiplier*child
		if total > 10000 {
			return total
		}
	}
	return total
}

func graphInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}
