package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func validateIntegration(m map[string]any) error {
	if !hasString([]string{"rest", "postgres", "webhook", "scanner-import"}, str(m, "type")) {
		return errors.New("연동 방식은 rest, postgres, webhook, scanner-import 입니다")
	}
	if containsNestedSecret(m["config"]) {
		return errors.New("config에는 비밀 값을 저장할 수 없습니다. 암호화되는 별도 secret 필드를 사용하세요")
	}
	if str(m, "type") == "rest" {
		u, err := parseTarget(str(m, "endpoint"))
		if err != nil {
			return err
		}
		for key := range u.Query() {
			if secretField(key) {
				return errors.New("URL에 비밀 값을 포함할 수 없습니다. secret 필드를 사용하세요")
			}
		}
	}
	if str(m, "type") == "postgres" {
		if strings.Contains(str(m, "endpoint"), "@") {
			return errors.New("DB 접속 DSN은 endpoint 대신 secret에 입력하세요")
		}
		if q := str(object(m["config"]), "query"); q != "" {
			if err := validateReadQuery(q); err != nil {
				return err
			}
		}
	}
	if _, ok := m["enabled"]; !ok {
		m["enabled"] = true
	}
	return nil
}
func secretField(key string) bool {
	k := strings.ToLower(key)
	for _, part := range []string{"secret", "password", "passwd", "token", "api_key", "apikey", "connection_string", "dsn", "authorization", "cookie"} {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}
func containsNestedSecret(v any) bool {
	switch m := v.(type) {
	case map[string]any:
		for key, value := range m {
			if secretField(key) || containsNestedSecret(value) {
				return true
			}
		}
	case []any:
		for _, value := range m {
			if containsNestedSecret(value) {
				return true
			}
		}
	}
	return false
}

func (a *App) integration(r *http.Request) (domainResource, error) {
	v, err := a.resource(r.Context(), "integrations", r.PathValue("id"))
	if err != nil || !a.canAccess(r.Context(), currentUser(r), v) {
		return v, errors.New("접근 가능한 연동 설정을 찾을 수 없습니다")
	}
	if !boolean(v.Data, "enabled") {
		return v, errors.New("비활성화된 연동입니다")
	}
	return v, nil
}

func (a *App) testIntegration(w http.ResponseWriter, r *http.Request) {
	v, err := a.integration(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	message := ""
	switch str(v.Data, "type") {
	case "rest":
		if str(object(v.Data["config"]), "direction") == "outbound" {
			err = validateIntegration(v.Data)
			message = "발신 설정 형식을 확인했습니다. 실제 연결은 개선 요청 발신 시 확인합니다."
		} else {
			_, err = a.fetchREST(ctx, v)
			message = "REST 응답 및 JSON 형식을 확인했습니다. 자산은 아직 수입하지 않았습니다."
		}
	case "postgres":
		var conn *pgx.Conn
		conn, err = a.integrationDB(ctx, v)
		if err == nil {
			defer conn.Close(context.Background())
			err = conn.Ping(ctx)
		}
		message = "PostgreSQL 연결을 확인했습니다. 동기화는 읽기 전용 트랜잭션으로 실행됩니다."
	case "webhook":
		message = "POST /api/integrations/" + v.ID + "/webhook 에 integrations:manage 권한의 개인 API 키를 Bearer로 전달하세요."
	case "scanner-import":
		message = "POST /api/imports에 findings:write 권한으로 JSON 결과를 수입하세요."
	}
	if err != nil {
		a.audit(r, "integration.test_failed", v.ID, map[string]any{"type": str(v.Data, "type")})
		fail(w, 400, "연동 테스트에 실패했습니다. 접속 주소·인증·인증서·응답 형식을 확인하세요")
		return
	}
	a.audit(r, "integration.test", v.ID, nil)
	jsonResponse(w, 200, map[string]any{"success": true, "message": message})
}

func (a *App) fetchREST(ctx context.Context, v domainResource) (any, error) {
	endpoint, err := parseTarget(str(v.Data, "endpoint"))
	if err != nil {
		return nil, err
	}
	client, err := a.outboundClient(ctx, 10*time.Second)
	if err != nil {
		return nil, err
	}
	// A connector secret must never follow a cross-origin redirect.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 || req.URL.Scheme != endpoint.Scheme || !strings.EqualFold(req.URL.Host, endpoint.Host) {
			return errors.New("연동 리다이렉트 범위가 다릅니다")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if secret := str(v.Data, "secret"); secret != "" {
		plain, err := a.decrypt(secret)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+plain)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (5<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 5<<20 {
		return nil, errors.New("연동 결과가 5 MiB 제한을 초과했습니다")
	}
	var payload any
	if err = json.Unmarshal(body, &payload); err != nil {
		return nil, errors.New("JSON 응답이 필요합니다")
	}
	return payload, nil
}

var unsafeSQL = regexp.MustCompile(`(?i)\b(insert|update|delete|merge|copy|call|do|create|alter|drop|grant|revoke|truncate|vacuum|execute|dblink|lo_export|lo_import|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_write_file|pg_terminate_backend|pg_cancel_backend)\b`)

func validateReadQuery(q string) error {
	trim := strings.TrimSpace(q)
	if len(trim) > 20000 || !strings.HasPrefix(strings.ToLower(trim), "select ") || strings.ContainsAny(trim, ";\x00") || strings.Contains(trim, "--") || strings.Contains(trim, "/*") || unsafeSQL.MatchString(trim) {
		return errors.New("DB 연동은 주석·다중 구문이 없는 SELECT 조회만 허용합니다")
	}
	return nil
}

func (a *App) integrationDB(ctx context.Context, v domainResource) (*pgx.Conn, error) {
	dsn, err := a.decrypt(str(v.Data, "secret"))
	if err != nil || dsn == "" {
		return nil, errors.New("secret에 PostgreSQL DSN을 설정하세요")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("DSN 형식이 올바르지 않습니다")
	}
	cfg.ConnectTimeout = 5 * time.Second
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = "5000"
	cfg.RuntimeParams["lock_timeout"] = "2000"
	return pgx.ConnectConfig(ctx, cfg)
}

func (a *App) fetchPostgres(ctx context.Context, v domainResource) (any, error) {
	q := str(object(v.Data["config"]), "query")
	if err := validateReadQuery(q); err != nil {
		return nil, err
	}
	conn, err := a.integrationDB(ctx, v)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	rows, err := tx.Query(ctx, "SELECT * FROM ("+q+") AS hunter_source LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []any{}
	fields := rows.FieldDescriptions()
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		item := map[string]any{}
		for i, value := range values {
			item[fields[i].Name] = value
		}
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func fieldPath(v any, path string) any {
	if path == "" {
		return v
	}
	for _, part := range strings.Split(path, ".") {
		v = object(v)[part]
	}
	return v
}
func connectorItems(payload any, config map[string]any) ([]any, error) {
	value := fieldPath(payload, str(config, "items_path"))
	if items, ok := value.([]any); ok {
		if len(items) > 5000 {
			return nil, errors.New("한 번에 최대 5,000개 자산 후보를 수입할 수 있습니다")
		}
		return items, nil
	}
	return nil, errors.New("자산 목록 배열을 찾을 수 없습니다. config.items_path를 설정하세요")
}

func (a *App) syncIntegration(w http.ResponseWriter, r *http.Request) {
	v, err := a.integration(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if str(object(v.Data["config"]), "direction") == "outbound" {
		fail(w, 400, "발신 연동은 자산 동기화를 지원하지 않습니다. 개선 요청 발신 기능을 사용하세요")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var payload any
	switch str(v.Data, "type") {
	case "rest":
		payload, err = a.fetchREST(ctx, v)
	case "postgres":
		payload, err = a.fetchPostgres(ctx, v)
	default:
		fail(w, 400, "REST 또는 PostgreSQL 연동만 동기화할 수 있습니다")
		return
	}
	if err != nil {
		a.audit(r, "integration.sync_failed", v.ID, nil)
		fail(w, 400, "동기화에 실패했습니다. 주소·인증·조회문·필드 매핑을 확인하세요")
		return
	}
	items, err := connectorItems(payload, object(v.Data["config"]))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	count, err := a.importDiscovery(ctx, currentUser(r), v, items)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	v.Data["last_sync_at"] = time.Now().UTC()
	v.Data["last_sync_count"] = count
	_ = a.persistResource(ctx, &v)
	a.audit(r, "integration.sync", v.ID, map[string]any{"candidates": count})
	jsonResponse(w, 200, map[string]any{"candidates": count, "message": "미승인 자산 후보로 수입했습니다. 자동 진단은 실행되지 않습니다."})
}

func (a *App) importDiscovery(ctx context.Context, u User, integration domainResource, items []any) (int, error) {
	config := object(integration.Data["config"])
	mapping := object(config["mapping"])
	count := 0
	for _, raw := range items {
		item := object(raw)
		m := map[string]any{"integration_id": integration.ID, "status": "candidate", "approved": false}
		for _, key := range []string{"name", "url", "team", "owner", "environment", "network", "criticality", "repository", "image", "description"} {
			source := str(mapping, key)
			if source == "" {
				source = key
			}
			value := fieldPath(item, source)
			if value != nil {
				m[key] = fmt.Sprint(value)
			}
		}
		if str(m, "name") == "" || str(m, "url") == "" {
			continue
		}
		if _, err := parseTarget(str(m, "url")); err != nil {
			continue
		}
		sum := sha256.Sum256([]byte(integration.ID + "\x00" + str(m, "url")))
		fingerprint := hex.EncodeToString(sum[:])
		m["fingerprint"] = fingerprint
		var exists bool
		if err := a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resources WHERE kind='discovery' AND data->>'fingerprint'=$1)`, fingerprint).Scan(&exists); err != nil {
			return count, err
		}
		if exists {
			continue
		}
		v := domainResource{ID: newID(), Kind: "discovery", OwnerID: u.ID, Data: m}
		if err := a.persistResource(ctx, &v); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (a *App) registerDiscovery(w http.ResponseWriter, r *http.Request) {
	v, err := a.resource(r.Context(), "discovery", r.PathValue("id"))
	if err != nil {
		fail(w, 404, "자산 후보를 찾을 수 없습니다")
		return
	}
	if str(v.Data, "registered_service_id") != "" {
		fail(w, 409, "이미 서비스로 등록한 후보입니다")
		return
	}
	data := map[string]any{}
	for _, key := range []string{"name", "url", "team", "owner", "environment", "network", "criticality", "repository", "image", "description"} {
		data[key] = v.Data[key]
	}
	if str(data, "environment") == "" {
		data["environment"] = "staging"
	}
	if str(data, "criticality") == "" {
		data["criticality"] = "tier3"
	}
	data["approved"] = false
	s := domainResource{ID: newID(), Kind: "services", OwnerID: currentUser(r).ID, Data: data}
	if err = a.validateResource(r.Context(), currentUser(r), &s, map[string]any{}, false); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err = a.persistResource(r.Context(), &s); err != nil {
		fail(w, 500, "서비스 등록 실패")
		return
	}
	v.Data["registered_service_id"] = s.ID
	v.Data["status"] = "registered"
	if err = a.persistResource(r.Context(), &v); err != nil {
		fail(w, 500, "서비스는 생성했으나 후보 상태 갱신에 실패했습니다")
		return
	}
	a.audit(r, "discovery.register", v.ID, map[string]any{"service_id": s.ID})
	jsonResponse(w, 201, a.resourceOutput(s))
}

func (a *App) webhookIntegration(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		fail(w, 401, "웹훅은 개인 API 키의 Bearer 인증이 필요합니다")
		return
	}
	v, err := a.integration(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if str(v.Data, "type") != "webhook" {
		fail(w, 400, "웹훅 유형의 연동이 아닙니다")
		return
	}
	raw, readErr := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if readErr != nil || len(raw) > 1<<20 {
		fail(w, 400, "웹훅 본문은 1 MiB 이하여야 합니다")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	m := map[string]any{}
	if decode(r, &m) != nil {
		fail(w, 400, "올바른 JSON 이벤트가 필요합니다")
		return
	}
	m["integration_id"] = v.ID
	if a.workflowChangeWebhook(w, r, v, m, raw) {
		return
	}
	if raw, exists := m["assets"]; exists {
		items, ok := raw.([]any)
		if !ok || len(items) > 5000 {
			fail(w, 400, "assets 배열은 최대 5,000개입니다")
			return
		}
		count, err := a.importDiscovery(r.Context(), currentUser(r), v, items)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		a.audit(r, "webhook.discovery", v.ID, map[string]any{"candidates": count})
		jsonResponse(w, 200, map[string]any{"candidates": count})
		return
	}
	// integrations:manage alone cannot elevate an API key to scans:write.
	if !hasString(currentUser(r).Scopes, "scans:write") {
		fail(w, 403, "진단 이벤트에는 scans:write 권한도 필요합니다")
		return
	}
	a.createEvent(w, r, m)
}

func (a *App) createEvent(w http.ResponseWriter, r *http.Request, input map[string]any) {
	typeName := firstString(input, "event_type", "type")
	if typeName == "" {
		typeName = "deploy"
	}
	if !hasString([]string{"push", "pull_request", "merge", "image", "harbor_push", "deploy", "api_change", "iam_change", "prompt_change", "manual"}, typeName) {
		fail(w, 400, "지원하지 않는 변경 이벤트 유형입니다")
		return
	}
	u := currentUser(r)
	s, err := a.resource(r.Context(), "services", str(input, "service_id"))
	if err != nil || !a.canAccess(r.Context(), u, s) {
		fail(w, 404, "이벤트 대상 서비스를 찾을 수 없습니다")
		return
	}
	// Caller-supplied request IDs make replayed deployment hooks idempotent.
	ref := firstString(input, "reference", "event_id")
	if ref != "" {
		var existing map[string]any
		if a.DB.QueryRow(r.Context(), `SELECT data FROM resources WHERE kind='events' AND data->>'service_id'=$1 AND data->>'reference'=$2 AND data->>'event_type'=$3 LIMIT 1`, s.ID, ref, typeName).Scan(&existing) == nil {
			jsonResponse(w, 200, map[string]any{"duplicate": true, "event": existing})
			return
		}
	}
	m := map[string]any{"name": str(s.Data, "name") + " 변경 이벤트", "service_id": s.ID, "event_type": typeName, "reference": ref, "integration_id": str(input, "integration_id"), "status": "received"}
	v := domainResource{ID: newID(), Kind: "events", OwnerID: u.ID, Data: m}
	// Reserve the event identity before scheduling. Concurrent webhook retries
	// cannot enqueue a second scan. An interrupted received event remains visible
	// for operator recovery instead of silently scheduling duplicate probes.
	encoded, _ := json.Marshal(m)
	err = a.DB.QueryRow(r.Context(), `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'events',$2,$3) ON CONFLICT DO NOTHING RETURNING created_at,updated_at`, v.ID, u.ID, encoded).Scan(&v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var existing map[string]any
		if e := a.DB.QueryRow(r.Context(), `SELECT data FROM resources WHERE kind='events' AND data->>'service_id'=$1 AND data->>'reference'=$2 AND data->>'event_type'=$3`, s.ID, ref, typeName).Scan(&existing); e != nil {
			fail(w, 500, "이벤트 중복 확인 실패")
			return
		}
		jsonResponse(w, 200, map[string]any{"duplicate": true, "event": existing})
		return
	}
	if err != nil {
		fail(w, 500, "이벤트 저장 실패")
		return
	}
	// Each event chooses a pre-registered profile. No shell commands, code,
	// arbitrary scanner templates, or AI-generated execution are accepted.
	request := map[string]any{"service_id": s.ID, "profile": str(input, "profile"), "scope_id": str(input, "scope_id"), "scenario_id": str(input, "scenario_id"), "finding_id": str(input, "finding_id")}
	scan, scanErr := a.RequestScan(r.Context(), u, request)
	if scanErr != nil {
		v.Data["status"] = "blocked"
		v.Data["reason"] = scanErr.Error()
	} else {
		v.Data["status"] = "scan_requested"
		v.Data["scan_id"] = str(scan, "id")
	}
	if err = a.persistResource(r.Context(), &v); err != nil {
		fail(w, 500, "이벤트 저장 실패")
		return
	}
	a.audit(r, "event.receive", v.ID, map[string]any{"event_type": typeName, "service_id": s.ID, "status": v.Data["status"]})
	jsonResponse(w, 201, a.resourceOutput(v))
}

// Explicit remediation dispatch lives in remediation.go; change automation only
// creates policy-checked Hunter scans and never executes caller-supplied commands.
