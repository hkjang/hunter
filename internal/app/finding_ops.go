package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func findingOpsDefaultSettings() map[string]map[string]any {
	return map[string]map[string]any{
		"sla":  {"enabled": false, "critical_days": 7, "high_days": 30, "medium_days": 90, "low_days": 180, "info_days": 0, "due_soon_days": 7},
		"risk": {"kev_boost": 25, "epss_threshold": 0.1, "epss_boost": 10, "stale_after_days": 30},
	}
}

func findingOpsNumeric(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case json.Number:
		f, e := n.Float64()
		return f, e == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
}

func validateFindingOpsSettings(group string, values map[string]any) error {
	defaults, ok := findingOpsDefaultSettings()[group]
	if !ok {
		return errors.New("지원하지 않는 발견 운영 설정입니다")
	}
	for key := range defaults {
		if key == "enabled" {
			if _, ok := values[key].(bool); !ok {
				return errors.New("SLA 사용 여부는 참 또는 거짓이어야 합니다")
			}
			continue
		}
		n, ok := findingOpsNumeric(values[key])
		max, min := 3650.0, 0.0
		if group == "risk" {
			max = 100
			if key == "epss_threshold" {
				max = 1
			}
			if key == "stale_after_days" {
				min, max = 1, 3650
			}
		}
		if !ok || n < min || n > max || key != "epss_threshold" && n != math.Trunc(n) {
			return fmt.Errorf("%s 값은 %g~%g 범위%s로 입력하세요", key, min, max, map[bool]string{true: "", false: "의 정수"}[key == "epss_threshold"])
		}
	}
	return nil
}

// This hook only validates a caller-editable existing field. Calculated SLA and
// intelligence are never taken from arbitrary resource JSON.
func validateFindingOpsResource(values map[string]any) error {
	if value, ok := values["due_date"]; ok && value != nil {
		s, ok := value.(string)
		if !ok {
			return errors.New("조치 기한은 RFC3339 일시로 입력하세요")
		}
		if s != "" {
			if _, err := time.Parse(time.RFC3339, s); err != nil {
				return errors.New("조치 기한은 시간대가 포함된 RFC3339 일시로 입력하세요")
			}
		}
	}
	return nil
}

func (a *App) initFindingOps(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `
CREATE TABLE IF NOT EXISTS finding_intel_datasets (
 format text PRIMARY KEY CHECK(format IN ('kev','epss')), source_date date NOT NULL,
 imported_at timestamptz NOT NULL DEFAULT now(), sha256 text NOT NULL, entry_count integer NOT NULL CHECK(entry_count>=0));
CREATE TABLE IF NOT EXISTS finding_intel_entries (
 format text NOT NULL REFERENCES finding_intel_datasets(format) ON DELETE CASCADE,
 cve text NOT NULL, epss double precision CHECK(epss>=0 AND epss<=1), percentile double precision CHECK(percentile>=0 AND percentile<=1),
 metadata jsonb NOT NULL DEFAULT '{}', PRIMARY KEY(format,cve));
CREATE INDEX IF NOT EXISTS finding_intel_cve ON finding_intel_entries(cve);
CREATE TABLE IF NOT EXISTS finding_comments (
 id text PRIMARY KEY, finding_id text NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
 author_id text NOT NULL, author_name text NOT NULL, body_encrypted text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS finding_comments_parent_time ON finding_comments(finding_id,created_at,id);
CREATE INDEX IF NOT EXISTS audit_logs_target_time ON audit_logs(target,created_at);
CREATE OR REPLACE FUNCTION hunter_finding_timestamp(value text) RETURNS timestamptz LANGUAGE plpgsql STABLE AS $$
BEGIN
 IF value IS NULL OR value !~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$' THEN RETURN NULL; END IF;
 RETURN value::timestamptz;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END; $$;`)
	return err
}

func (a *App) registerFindingOps(m *http.ServeMux) {
	m.HandleFunc("GET /api/finding-queue", a.protect("findings:read", func(w http.ResponseWriter, r *http.Request) {
		if !hasString(currentUser(r).Scopes, "services:read") {
			fail(w, 403, "서비스 조회 권한이 필요합니다")
			return
		}
		a.findingQueue(w, r)
	}))
	m.HandleFunc("GET /api/findings/{id}/activity", a.protect("findings:read", a.findingActivity))
	m.HandleFunc("POST /api/findings/{id}/activity", a.protect("findings:write", a.addFindingComment))
	m.HandleFunc("GET /api/intelligence", a.protect("admin:manage", a.listFindingIntelligence))
	m.HandleFunc("POST /api/intelligence/import", a.protect("admin:manage", a.importFindingIntelligence))
}

func (a *App) findingOpsSettings(ctx context.Context, group string) (map[string]any, error) {
	v := findingOpsDefaultSettings()[group]
	stored, err := a.setting(ctx, group)
	if err != nil {
		return nil, err
	}
	for key := range v {
		if value, ok := stored[key]; ok {
			v[key] = value
		}
	}
	return v, validateFindingOpsSettings(group, v)
}

// All scope filtering, counting, sorting and pagination happen in PostgreSQL.
// No use of the generic 5,000-record list cap: old overdue findings remain visible.
const findingQueueSQL = `WITH scoped AS MATERIALIZED (
 SELECT r.*,s.data->>'name' AS service_name,s.data->>'team' AS team,s.data->>'criticality' AS criticality,
 CASE WHEN btrim(r.data->>'cve') ~* '^CVE-[0-9]{4}-[0-9]{4,}$' THEN upper(btrim(r.data->>'cve')) END AS canonical_cve,
 hunter_finding_timestamp(r.data->>'due_date') AS manual_due,
 coalesce(r.data->>'due_date','')<>'' AS has_manual_due
 FROM resources r JOIN resources s ON s.kind='services' AND s.id=r.data->>'service_id'
 WHERE r.kind='findings' AND ($1 OR r.owner_id=$2 OR s.owner_id=$2 OR ($3<>'' AND s.data->>'team'=$3))
 AND coalesce(r.data->>'status','candidate') NOT IN ('resolved','false_positive')
 AND NOT (coalesce(r.data->>'status','candidate')='accepted' AND coalesce(hunter_finding_timestamp(r.data->>'expires_at')>$4,false))
), enriched AS (
 SELECT scoped.*,kd.source_date AS kev_date,kd.imported_at AS kev_imported_at,ed.source_date AS epss_date,ed.imported_at AS epss_imported_at,
 CASE WHEN canonical_cve IS NOT NULL AND kd.format IS NOT NULL THEN ke.cve IS NOT NULL END AS kev,
 ee.epss,ee.percentile,
 CASE WHEN has_manual_due THEN manual_due WHEN ($5::jsonb->>'enabled')::boolean AND coalesce(($5::jsonb->>(coalesce(data->>'severity','info')||'_days'))::integer,0)>0
 THEN created_at+make_interval(days=>($5::jsonb->>(coalesce(data->>'severity','info')||'_days'))::integer) END AS effective_due,
 CASE WHEN has_manual_due THEN 'manual' WHEN ($5::jsonb->>'enabled')::boolean AND coalesce(($5::jsonb->>(coalesce(data->>'severity','info')||'_days'))::integer,0)>0 THEN 'policy' ELSE 'none' END AS due_source,
 CASE data->>'severity' WHEN 'critical' THEN 70 WHEN 'high' THEN 50 WHEN 'medium' THEN 30 WHEN 'low' THEN 10 ELSE 0 END AS severity_weight,
 CASE criticality WHEN 'tier1' THEN 15 WHEN 'tier2' THEN 10 WHEN 'tier3' THEN 5 ELSE 0 END AS asset_weight
 FROM scoped LEFT JOIN finding_intel_datasets kd ON kd.format='kev' LEFT JOIN finding_intel_datasets ed ON ed.format='epss'
 LEFT JOIN finding_intel_entries ke ON ke.format='kev' AND ke.cve=canonical_cve
 LEFT JOIN finding_intel_entries ee ON ee.format='epss' AND ee.cve=canonical_cve
), scored AS MATERIALIZED (
 SELECT enriched.*,
 LEAST(100,severity_weight+asset_weight+CASE WHEN kev THEN ($6::jsonb->>'kev_boost')::integer ELSE 0 END+
 CASE WHEN epss>=($6::jsonb->>'epss_threshold')::double precision AND epss_date>=($4::timestamptz AT TIME ZONE 'UTC')::date-($6::jsonb->>'stale_after_days')::integer THEN ($6::jsonb->>'epss_boost')::integer ELSE 0 END) AS score,
 CASE WHEN has_manual_due AND manual_due IS NULL THEN 'invalid' WHEN effective_due IS NULL THEN 'not_set'
 WHEN effective_due<$4 THEN 'overdue' WHEN effective_due<=$4+make_interval(days=>($5::jsonb->>'due_soon_days')::integer) THEN 'due_soon' ELSE 'on_track' END AS sla_state,
 CASE WHEN canonical_cve IS NOT NULL AND btrim(coalesce(data->>'component',''))<>'' THEN md5(canonical_cve||chr(31)||btrim(data->>'component')) END AS group_id
 FROM enriched
 WHERE NOT EXISTS(SELECT 1 FROM regexp_split_to_table(btrim($7::text),'\s+') term WHERE term<>'' AND strpos(lower(concat_ws(' ',data->>'title',data->>'cve',data->>'component',data->>'assignee',service_name,team)),lower(term))=0)
), matched AS MATERIALIZED (
 SELECT * FROM scored WHERE ($8='all' OR ($8='mine' AND owner_id=$2) OR ($8='overdue' AND sla_state='overdue') OR ($8='due_soon' AND sla_state='due_soon') OR ($8='unassigned' AND btrim(coalesce(data->>'assignee',''))=''))
 AND ($9='' OR group_id=$9)
), paged AS (
 SELECT * FROM matched ORDER BY score DESC,effective_due ASC NULLS LAST,created_at,id LIMIT $10 OFFSET $11
), grouped AS (
 SELECT group_id AS id,min(canonical_cve) AS cve,min(btrim(data->>'component')) AS component,count(*) AS finding_count,count(DISTINCT data->>'service_id') AS service_count,max(score) AS max_score
 FROM matched WHERE group_id IS NOT NULL GROUP BY group_id HAVING count(*)>1 ORDER BY count(*) DESC,group_id LIMIT 100
)
SELECT coalesce((SELECT jsonb_agg(to_jsonb(p) ORDER BY score DESC,effective_due ASC NULLS LAST,created_at,id) FROM paged p),'[]'::jsonb),
 (SELECT count(*) FROM matched),
 (SELECT jsonb_build_object('total',count(*),'mine',count(*) FILTER(WHERE owner_id=$2),'overdue',count(*) FILTER(WHERE sla_state='overdue'),'due_soon',count(*) FILTER(WHERE sla_state='due_soon'),'unassigned',count(*) FILTER(WHERE btrim(coalesce(data->>'assignee',''))=''),'critical',count(*) FILTER(WHERE score>=80),'kev',count(*) FILTER(WHERE kev),'invalid_due_date',count(*) FILTER(WHERE sla_state='invalid')) FROM scored),
 coalesce((SELECT jsonb_agg(to_jsonb(g)) FROM grouped g),'[]'::jsonb)`

type findingQueueRecord struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	OwnerID        string         `json:"owner_id"`
	Data           map[string]any `json:"data"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	ServiceName    *string        `json:"service_name"`
	Team           *string        `json:"team"`
	CanonicalCVE   *string        `json:"canonical_cve"`
	KEV            *bool          `json:"kev"`
	EPSS           *float64       `json:"epss"`
	Percentile     *float64       `json:"percentile"`
	KEVDate        *string        `json:"kev_date"`
	EPSSDate       *string        `json:"epss_date"`
	KEVImported    *time.Time     `json:"kev_imported_at"`
	EPSSImported   *time.Time     `json:"epss_imported_at"`
	EffectiveDue   *time.Time     `json:"effective_due"`
	DueSource      string         `json:"due_source"`
	SLAState       string         `json:"sla_state"`
	Score          int            `json:"score"`
	SeverityWeight int            `json:"severity_weight"`
	AssetWeight    int            `json:"asset_weight"`
	GroupID        *string        `json:"group_id"`
}

func findingDateStale(date *string, days int, now time.Time) *bool {
	if date == nil {
		return nil
	}
	t, e := time.Parse("2006-01-02", *date)
	if e != nil {
		return nil
	}
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	stale := t.Before(today.AddDate(0, 0, -days))
	return &stale
}

func (a *App) queueRecordOutput(v findingQueueRecord, risk map[string]any, now time.Time) map[string]any {
	m := a.resourceOutput(domainResource{ID: v.ID, Kind: v.Kind, OwnerID: v.OwnerID, Data: v.Data, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt})
	m["service_name"], m["team"], m["group_id"] = v.ServiceName, v.Team, v.GroupID
	level := "info"
	switch {
	case v.Score >= 80:
		level = "critical"
	case v.Score >= 55:
		level = "high"
	case v.Score >= 30:
		level = "medium"
	case v.Score > 0:
		level = "low"
	}
	reasons := []string{fmt.Sprintf("기술적 심각도 가중치 %d", v.SeverityWeight), fmt.Sprintf("서비스 중요도 가중치 %d", v.AssetWeight)}
	kevStale, epssStale := findingDateStale(v.KEVDate, number(risk, "stale_after_days", 30), now), findingDateStale(v.EPSSDate, number(risk, "stale_after_days", 30), now)
	if v.CanonicalCVE == nil {
		reasons = append(reasons, "유효한 CVE 식별자가 없어 위협 정보를 연결하지 않았습니다")
	} else {
		if v.KEV == nil {
			reasons = append(reasons, "KEV 자료가 반입되지 않았습니다")
		} else if *v.KEV {
			reasons = append(reasons, fmt.Sprintf("KEV 알려진 악용 목록 등재 +%d", number(risk, "kev_boost", 25)))
		}
		threshold, _ := findingOpsNumeric(risk["epss_threshold"])
		if v.EPSS == nil {
			reasons = append(reasons, "이 CVE의 EPSS 관측값이 없습니다")
		} else if epssStale != nil && *epssStale {
			reasons = append(reasons, "EPSS 기준일이 오래되어 점수 가산에서 제외했습니다")
		} else if *v.EPSS >= threshold {
			reasons = append(reasons, fmt.Sprintf("EPSS 기준 %.3f 이상 +%d", threshold, number(risk, "epss_boost", 10)))
		}
	}
	if kevStale != nil && *kevStale {
		reasons = append(reasons, "KEV 반입 자료의 기준일을 확인하세요")
	}
	m["priority"] = map[string]any{"score": v.Score, "level": level, "reasons": reasons, "method": "hunter-priority-v1"}
	var remaining *int
	if v.EffectiveDue != nil {
		n := int(math.Ceil(v.EffectiveDue.Sub(now).Hours() / 24))
		remaining = &n
	}
	m["sla"] = map[string]any{"due_date": v.EffectiveDue, "source": v.DueSource, "state": v.SLAState, "remaining_days": remaining}
	var stale *bool
	for _, flag := range []*bool{kevStale, epssStale} {
		if flag != nil {
			if stale == nil {
				f := false
				stale = &f
			}
			*stale = *stale || *flag
		}
	}
	var sourceDate *string
	for _, date := range []*string{v.KEVDate, v.EPSSDate} {
		if date != nil && (sourceDate == nil || *date < *sourceDate) {
			sourceDate = date
		}
	}
	m["intelligence"] = map[string]any{"kev": v.KEV, "epss": v.EPSS, "percentile": v.Percentile, "source_date": sourceDate, "stale": stale, "kev_source_date": v.KEVDate, "epss_source_date": v.EPSSDate, "kev_imported_at": v.KEVImported, "epss_imported_at": v.EPSSImported}
	return m
}

type FindingQueueOptions struct {
	View  string
	Query string
	Group string
	Page  int
	Size  int
}

type findingOpsInputError struct{ message string }

func (e findingOpsInputError) Error() string { return e.message }

func (a *App) FindingQueue(ctx context.Context, u User, options FindingQueueOptions) (map[string]any, error) {
	if !hasString(u.Scopes, "findings:read") || !hasString(u.Scopes, "services:read") {
		return nil, errors.New("발견 건과 서비스 조회 권한이 모두 필요합니다")
	}
	if options.View == "" {
		options.View = "all"
	}
	if options.Page == 0 {
		options.Page = 1
	}
	if options.Size == 0 {
		options.Size = 25
	}
	if !hasString([]string{"all", "mine", "overdue", "due_soon", "unassigned"}, options.View) {
		return nil, findingOpsInputError{"올바른 조치함 보기를 선택하세요"}
	}
	if options.Page < 1 || options.Page > 10000000 {
		return nil, findingOpsInputError{"페이지는 1~10000000 범위입니다"}
	}
	if !hasString([]string{"10", "25", "50", "100"}, strconv.Itoa(options.Size)) {
		return nil, findingOpsInputError{"표시 수는 10, 25, 50, 100 중 하나입니다"}
	}
	options.Query = strings.TrimSpace(options.Query)
	if len([]rune(options.Query)) > 500 {
		return nil, findingOpsInputError{"검색어는 500자 이하여야 합니다"}
	}
	if len(options.Group) > 64 {
		return nil, findingOpsInputError{"원인 그룹 식별자를 확인하세요"}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	sla, err := a.findingOpsSettings(ctx, "sla")
	if err != nil {
		return nil, err
	}
	risk, err := a.findingOpsSettings(ctx, "risk")
	if err != nil {
		return nil, err
	}
	slaJSON, _ := json.Marshal(sla)
	riskJSON, _ := json.Marshal(risk)
	now := time.Now().UTC()
	var itemsRaw, summaryRaw, groupsRaw []byte
	var total int64
	err = a.DB.QueryRow(ctx, findingQueueSQL, elevated(u), u.ID, leadTeam(u), now, slaJSON, riskJSON, options.Query, options.View, options.Group, options.Size, (options.Page-1)*options.Size).Scan(&itemsRaw, &total, &summaryRaw, &groupsRaw)
	if err != nil {
		return nil, fmt.Errorf("조치함 조회 실패: %w", err)
	}
	var records []findingQueueRecord
	var summary map[string]any
	var groups []map[string]any
	if json.Unmarshal(itemsRaw, &records) != nil || json.Unmarshal(summaryRaw, &summary) != nil || json.Unmarshal(groupsRaw, &groups) != nil {
		return nil, errors.New("조치함 결과를 읽을 수 없습니다")
	}
	items := make([]map[string]any, 0, len(records))
	for _, v := range records {
		items = append(items, a.queueRecordOutput(v, risk, now))
	}
	return map[string]any{"items": items, "total": total, "page": options.Page, "page_size": options.Size, "summary": summary, "as_of": now, "groups": groups, "groups_limit": 100, "summary_scope": "검색어에 일치하는 접근 가능한 전체 미조치 발견 건", "sla_policy": sla}, nil
}

func (a *App) findingQueue(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query()
	options := FindingQueueOptions{View: p.Get("view"), Query: p.Get("q"), Group: p.Get("group")}
	var err error
	if p.Get("page") != "" {
		options.Page, err = strconv.Atoi(p.Get("page"))
		if err != nil || options.Page < 1 {
			fail(w, 400, "페이지를 확인하세요")
			return
		}
	}
	if p.Get("size") != "" {
		options.Size, err = strconv.Atoi(p.Get("size"))
		if err != nil || options.Size < 1 {
			fail(w, 400, "표시 수를 확인하세요")
			return
		}
	}
	result, err := a.FindingQueue(r.Context(), currentUser(r), options)
	if err != nil {
		var inputError findingOpsInputError
		if errors.As(err, &inputError) {
			fail(w, 400, inputError.Error())
		} else {
			fail(w, 500, "조치함을 불러오지 못했습니다")
		}
		return
	}
	jsonResponse(w, 200, result)
}
