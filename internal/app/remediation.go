package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var templateVariable = regexp.MustCompile(`\{\{([a-z_]+)\.([a-z_]+)\}\}`)

func expandTemplate(v any, values map[string]map[string]any) (any, error) {
	switch x := v.(type) {
	case string:
		var missing string
		out := templateVariable.ReplaceAllStringFunc(x, func(m string) string {
			parts := templateVariable.FindStringSubmatch(m)
			value, ok := values[parts[1]][parts[2]]
			if !ok {
				missing = m
				return m
			}
			return fmt.Sprint(value)
		})
		if missing != "" {
			return nil, fmt.Errorf("알 수 없는 템플릿 변수: %s", missing)
		}
		return out, nil
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			n, e := expandTemplate(v, values)
			if e != nil {
				return nil, e
			}
			out[k] = n
		}
		return out, nil
	case []any:
		out := []any{}
		for _, v := range x {
			n, e := expandTemplate(v, values)
			if e != nil {
				return nil, e
			}
			out = append(out, n)
		}
		return out, nil
	default:
		return x, nil
	}
}
func (a *App) registerRemediation(m *http.ServeMux) {
	m.HandleFunc("POST /api/remediations/{id}/dispatch", a.protect("findings:write", a.dispatchRemediation))
}
func (a *App) dispatchRemediation(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rem, e := a.resource(ctx, "remediations", r.PathValue("id"))
	if e != nil || !a.canAccess(ctx, u, rem) {
		fail(w, 404, "접근 가능한 개선 요청이 없습니다")
		return
	}
	finding, e := a.resource(ctx, "findings", str(rem.Data, "finding_id"))
	if e != nil || !a.canAccess(ctx, u, finding) {
		fail(w, 400, "발견 건을 선택해 주세요")
		return
	}
	integration, e := a.resource(ctx, "integrations", str(rem.Data, "integration_id"))
	if e != nil || !boolean(integration.Data, "enabled") || str(integration.Data, "type") != "rest" {
		fail(w, 400, "활성 REST 연동을 선택해 주세요")
		return
	}
	cfg := object(integration.Data["config"])
	if str(cfg, "direction") != "outbound" {
		fail(w, 400, "관리자가 발신용으로 설정한 연동만 사용할 수 있습니다")
		return
	}
	if sid := str(cfg, "service_id"); sid != "" && sid != str(finding.Data, "service_id") {
		fail(w, 403, "이 서비스에는 해당 발신 연동을 사용할 수 없습니다")
		return
	}
	flow, e := a.setting(ctx, "workflow")
	if e != nil {
		fail(w, 500, "승인 설정 조회 실패")
		return
	}
	if asBool(flow["approval_enabled"]) && u.Role != "admin" && u.Role != "lead" {
		fail(w, 403, "검토 절차가 켜져 있어 팀장 또는 관리자가 발신해야 합니다")
		return
	}
	tpl := cfg["template"]
	if tpl == nil {
		tpl = map[string]any{"title": "{{finding.title}}", "description": "{{finding.description}}\n\n개선안\n{{finding.remediation}}", "external_id": "{{remediation.id}}"}
	}
	f := map[string]any{}
	for _, k := range []string{"title", "description", "remediation", "service_id", "severity", "cve", "component", "assignee"} {
		f[k] = str(finding.Data, k)
	}
	f["id"] = finding.ID
	values := map[string]map[string]any{"finding": f, "remediation": {"id": rem.ID, "name": str(rem.Data, "name"), "description": str(rem.Data, "description"), "patch": str(rem.Data, "patch")}}
	payload, e := expandTemplate(tpl, values)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	body, e := json.Marshal(payload)
	if e != nil || len(body) > 1<<20 {
		fail(w, 400, "발신 본문은 1 MiB 이하여야 합니다")
		return
	}
	endpoint := str(integration.Data, "endpoint")
	if _, e = parseTarget(endpoint); e != nil {
		fail(w, 400, "발신 주소를 확인해 주세요")
		return
	}
	client, e := a.outboundClient(ctx, 20*time.Second)
	if e != nil {
		fail(w, 400, "인증서 설정을 확인해 주세요")
		return
	}
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if e != nil {
		fail(w, 400, "발신 요청 생성 실패")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Idempotency-Key", "hunter-"+rem.ID)
	if secret := str(integration.Data, "secret"); secret != "" {
		plain, err := a.decrypt(secret)
		if err != nil {
			fail(w, 500, "발신 인증 정보를 읽을 수 없습니다")
			return
		}
		req.Header.Set("Authorization", "Bearer "+plain)
	}
	// Claim before sending. An ambiguous timeout remains uncertain until an operator
	// checks the destination; an automatic retry cannot create duplicate tickets.
	tag, e := a.DB.Exec(ctx, `UPDATE resources SET data=data||jsonb_build_object('dispatch_state','sending','dispatch_started_at',now()),updated_at=now() WHERE id=$1 AND kind='remediations' AND coalesce(data->>'dispatch_state','') NOT IN ('sending','sent','uncertain')`, rem.ID)
	if e != nil {
		fail(w, 500, "발신 상태 저장 실패")
		return
	}
	if tag.RowsAffected() != 1 {
		fail(w, 409, "이미 발신했거나 결과 확인이 필요한 요청입니다. 대상 시스템의 중복 여부를 먼저 확인해 주세요")
		return
	}
	resp, e := client.Do(req)
	state := "uncertain"
	statusCode := 0
	externalID, externalURL := "", ""
	if e == nil {
		defer resp.Body.Close()
		statusCode = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			state = "sent"
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			var data map[string]any
			if json.Unmarshal(raw, &data) == nil {
				externalID = fmt.Sprint(fieldPath(data, defaultString(str(cfg, "response_id_path"), "id")))
				externalURL = asString(fieldPath(data, defaultString(str(cfg, "response_url_path"), "url")))
				if externalID == "<nil>" {
					externalID = ""
				}
				if !strings.HasPrefix(externalURL, "https://") && !strings.HasPrefix(externalURL, "http://") {
					externalURL = ""
				}
			}
		} else {
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 408 && resp.StatusCode != 429 {
				state = "rejected"
			}
			e = errors.New("upstream rejected")
		}
	}
	persistCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	update := map[string]any{"dispatch_state": state, "dispatch_http_status": statusCode, "external_id": externalID, "external_url": externalURL}
	if state == "sent" {
		update["status"] = "sent"
		update["sent_at"] = time.Now().UTC()
	}
	raw, _ := json.Marshal(update)
	_, dbErr := a.DB.Exec(persistCtx, `UPDATE resources SET data=data||$2::jsonb,updated_at=now() WHERE id=$1`, rem.ID, raw)
	a.audit(r, "remediation.dispatch", rem.ID, map[string]any{"integration_id": integration.ID, "state": state, "http_status": statusCode})
	if dbErr != nil {
		fail(w, 502, "발신 후 상태 저장에 실패했습니다. 대상 시스템에서 요청 ID를 확인해 주세요")
		return
	}
	if e != nil {
		fail(w, 502, "개선 요청 발신에 실패했거나 결과가 불확실합니다. 연결·인증 및 대상 시스템의 요청 기록을 확인해 주세요")
		return
	}
	jsonResponse(w, 200, update)
}
func defaultString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
