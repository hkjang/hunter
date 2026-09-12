package app

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

func validateInventorySettings(v map[string]any) error {
	b, _ := json.Marshal(v["stale_after_days"])
	var n float64
	if json.Unmarshal(b, &n) != nil || n < 1 || n > 3650 || math.Trunc(n) != n {
		return fmt.Errorf("SBOM 갱신 기준은 1~3650일 정수로 입력하세요")
	}
	switch v["review_licenses"].(type) {
	case []string, []any:
	default:
		return fmt.Errorf("검토 라이선스는 문자열 목록이어야 합니다")
	}
	values := stringSlice(v["review_licenses"])
	if original, ok := v["review_licenses"].([]any); ok && len(original) != len(values) {
		return fmt.Errorf("검토 라이선스는 문자열 목록이어야 합니다")
	}
	if len(values) > 100 {
		return fmt.Errorf("검토 라이선스는 최대 100개입니다")
	}
	for _, s := range values {
		if strings.TrimSpace(s) == "" || !sbomSafeIdentifier(s, 100) {
			return fmt.Errorf("라이선스 식별자는 1~100바이트로 입력하세요")
		}
	}
	return nil
}
func (a *App) registerOperations(m *http.ServeMux) {
	m.HandleFunc("GET /api/operations", a.protect("admin:manage", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, err := a.Operations(ctx)
		if err != nil {
			fail(w, 503, "운영 상태를 확인할 수 없습니다. DB 연결과 서버 로그를 확인하세요")
			return
		}
		jsonResponse(w, 200, out)
	}))
}

// Operations checks only Hunter's own persisted state. Viewing this page never
// contacts an OIDC issuer, model provider, registered service or public feed.
func (a *App) Operations(ctx context.Context) (map[string]any, error) {
	if err := a.DB.Ping(ctx); err != nil {
		return nil, err
	}
	checks := []map[string]any{}
	add := func(id, title, status, detail string) {
		checks = append(checks, map[string]any{"id": id, "title": title, "status": status, "detail": detail})
	}
	add("database", "데이터베이스", "ok", "PostgreSQL 연결과 응답을 확인했습니다")
	counts := map[string]int{}
	var services, findings, staleWorkers, enabledWorkers int
	err := a.DB.QueryRow(ctx, `SELECT count(*) FILTER(WHERE kind='services'),count(*) FILTER(WHERE kind='findings'),count(*) FILTER(WHERE kind='workers' AND data->>'enabled'='true'),count(*) FILTER(WHERE kind='workers' AND data->>'enabled'='true' AND (hunter_finding_timestamp(data->>'last_seen') IS NULL OR hunter_finding_timestamp(data->>'last_seen')<now()-interval '2 minutes')) FROM resources`).Scan(&services, &findings, &enabledWorkers, &staleWorkers)
	if err != nil {
		return nil, err
	}
	counts["services"] = services
	counts["findings"] = findings
	counts["stale_workers"] = staleWorkers
	var queued, running, blocked, expired int
	err = a.DB.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status='ready'),count(*) FILTER(WHERE status='leased'),count(*) FILTER(WHERE status='blocked'),count(*) FILTER(WHERE status='leased' AND lease_until<now()) FROM scan_jobs`).Scan(&queued, &running, &blocked, &expired)
	if err != nil {
		return nil, err
	}
	counts["queued_jobs"] = queued
	counts["running_jobs"] = running
	counts["blocked_jobs"] = blocked
	status := "ok"
	if expired > 0 {
		status = "warning"
	}
	add("queue", "진단 대기열", status, fmt.Sprintf("대기 %d · 실행 %d · 승인 대기 %d · 임대 만료 %d", queued, running, blocked, expired))
	status = "ok"
	if staleWorkers > 0 || enabledWorkers == 0 {
		status = "warning"
	}
	add("workers", "워커 응답", status, fmt.Sprintf("활성 %d개 중 2분 이상 응답 없음 %d개. 망별 워커 설정과 프로세스를 확인하세요", enabledWorkers, staleWorkers))
	var emergency bool
	if err = a.DB.QueryRow(ctx, `SELECT emergency FROM domain_runtime WHERE id=1`).Scan(&emergency); err != nil {
		return nil, err
	}
	if emergency {
		add("emergency", "긴급 중지", "warning", "진단 요청과 실행이 중지된 상태입니다")
	} else {
		add("emergency", "긴급 중지", "ok", "긴급 중지가 해제되어 있으며 각 진단에는 대상·정책 검사가 적용됩니다")
	}
	for _, g := range []string{"oidc", "ai", "agents", "workflow"} {
		cfg, err := a.setting(ctx, g)
		if err != nil {
			return nil, err
		}
		enabled := boolean(cfg, "enabled")
		if g == "workflow" {
			enabled = boolean(cfg, "approval_enabled")
		}
		title := map[string]string{"oidc": "SSO 설정", "ai": "AI 설정", "agents": "에이전트 설정", "workflow": "검토·승인 설정"}[g]
		detail := "사용하지 않음"
		if enabled {
			detail = "사용 설정됨 · 이 점검은 외부 연결을 시험하지 않습니다"
		}
		add(g, title, "ok", detail)
	}
	risk, err := a.setting(ctx, "risk")
	if err != nil {
		return nil, err
	}
	rows, err := a.DB.Query(ctx, `SELECT format,source_date FROM finding_intel_datasets`)
	if err != nil {
		return nil, err
	}
	dates := map[string]time.Time{}
	for rows.Next() {
		var format string
		var date time.Time
		if err = rows.Scan(&format, &date); err != nil {
			rows.Close()
			return nil, err
		}
		dates[format] = date
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for _, format := range []string{"kev", "epss"} {
		d, ok := dates[format]
		if !ok {
			add(format, strings.ToUpper(format)+" 반입", "warning", "반입 자료 없음 · 해당 위험 신호는 정보 없음으로 표시됩니다")
			continue
		}
		status = "ok"
		date := d.Format("2006-01-02")
		if stale := findingDateStale(&date, number(risk, "stale_after_days", 30), time.Now()); stale != nil && *stale {
			status = "warning"
		}
		add(format, strings.ToUpper(format)+" 반입", status, "자료 기준일 "+d.Format("2006-01-02"))
	}
	inventory, err := a.setting(ctx, "inventory")
	if err != nil {
		return nil, err
	}
	var docs, covered, stale int
	err = a.DB.QueryRow(ctx, `SELECT count(*) FROM sbom_documents`).Scan(&docs)
	if err != nil {
		return nil, err
	}
	err = a.DB.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE latest<now()-make_interval(days=>$1)) FROM (SELECT max(created_at) AS latest FROM sbom_documents GROUP BY service_id) latest`, number(inventory, "stale_after_days", 30)).Scan(&covered, &stale)
	if err != nil {
		return nil, err
	}
	counts["sboms"] = docs
	counts["sbom_services"] = covered
	counts["stale_sboms"] = stale
	status = "ok"
	if covered < services || stale > 0 {
		status = "warning"
	}
	add("inventory", "소프트웨어 명세", status, fmt.Sprintf("서비스 %d개 중 명세 보유 %d개 · 갱신 기준 초과 %d개", services, covered, stale))
	return map[string]any{"as_of": time.Now().UTC(), "version": a.Version, "counts": counts, "checks": checks, "emergency": emergency}, nil
}
