package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

var errCampaignNotFound = errors.New("캠페인을 찾을 수 없습니다")
var errCampaignPermission = errors.New("캠페인 권한이 없습니다")

type campaignTarget struct {
	ServiceID  string `json:"service_id"`
	Profile    string `json:"profile"`
	ScopeID    string `json:"scope_id,omitempty"`
	ScenarioID string `json:"scenario_id,omitempty"`
}

type campaignRecord struct {
	ID, OwnerID, Name, Description string
	Targets                        []campaignTarget
	CreatedAt                      time.Time
	StartedAt                      *time.Time
}

func (a *App) initCampaigns(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `
	CREATE TABLE IF NOT EXISTS campaigns (
	 id text PRIMARY KEY, owner_id text NOT NULL, name text NOT NULL, description text NOT NULL DEFAULT '',
	 targets jsonb NOT NULL CHECK(jsonb_typeof(targets)='array' AND jsonb_array_length(targets) BETWEEN 1 AND 20),
	 created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz);
	CREATE TABLE IF NOT EXISTS campaign_scans (
	 campaign_id text NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
	 target_index integer NOT NULL, scan_id text NOT NULL UNIQUE REFERENCES resources(id) ON DELETE RESTRICT,
	 PRIMARY KEY(campaign_id,target_index));
	CREATE TABLE IF NOT EXISTS scan_observations (
	 scan_id text PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
	 service_id text NOT NULL, profile text NOT NULL, scenario_id text NOT NULL DEFAULT '',
	 conditions_hash text NOT NULL, trusted boolean NOT NULL DEFAULT false,
	 import_format text NOT NULL DEFAULT '', findings jsonb NOT NULL CHECK(jsonb_typeof(findings)='array'),
	 recorded_at timestamptz NOT NULL DEFAULT now());`)
	return err
}

func campaignScopes(u User, write, compare bool) bool {
	for _, scope := range []string{"services:read", "scans:read"} {
		if !hasString(u.Scopes, scope) {
			return false
		}
	}
	return (!write || hasString(u.Scopes, "scans:write")) && (!compare || hasString(u.Scopes, "findings:read"))
}

func (a *App) registerCampaigns(mux *http.ServeMux) {
	wrap := func(write, compare bool, handler http.HandlerFunc) http.HandlerFunc {
		return a.protect("scans:read", func(w http.ResponseWriter, r *http.Request) {
			if !campaignScopes(currentUser(r), write, compare) {
				fail(w, http.StatusForbidden, errCampaignPermission.Error())
				return
			}
			handler(w, r)
		})
	}
	mux.HandleFunc("GET /api/campaigns", wrap(false, false, a.listCampaigns))
	mux.HandleFunc("POST /api/campaigns", wrap(true, false, a.createCampaign))
	mux.HandleFunc("GET /api/campaigns/{id}", wrap(false, false, a.getCampaign))
	mux.HandleFunc("POST /api/campaigns/{id}/start", wrap(true, false, a.startCampaign))
	mux.HandleFunc("GET /api/campaigns/{id}/compare", wrap(false, true, a.compareCampaign))
}

// A campaign has no creator bypass: all live parent services must be accessible.
// Requiring the service row even for administrators also hides deleted targets.
const campaignVisibilitySQL = `NOT EXISTS (
	SELECT 1 FROM jsonb_array_elements(c.targets) target
	WHERE NOT EXISTS (SELECT 1 FROM resources s WHERE s.kind='services' AND s.id=target->>'service_id'
	AND ($2 OR s.owner_id=$3 OR ($4<>'' AND s.data->>'team'=$4))))`

func scanCampaign(row pgx.Row) (campaignRecord, error) {
	var c campaignRecord
	var targets []byte
	err := row.Scan(&c.ID, &c.OwnerID, &c.Name, &c.Description, &targets, &c.CreatedAt, &c.StartedAt)
	if err == nil {
		err = json.Unmarshal(targets, &c.Targets)
	}
	return c, err
}

func campaignSelect(ctx context.Context, tx pgx.Tx, u User, id string, lock bool) (campaignRecord, error) {
	query := `SELECT c.id,c.owner_id,c.name,c.description,c.targets,c.created_at,c.started_at FROM campaigns c WHERE c.id=$1 AND ` + campaignVisibilitySQL
	if lock {
		query += ` FOR UPDATE OF c`
	}
	c, err := scanCampaign(tx.QueryRow(ctx, query, id, elevated(u), u.ID, leadTeam(u)))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, errCampaignNotFound
	}
	return c, err
}

func (a *App) campaignOutput(ctx context.Context, tx pgx.Tx, c campaignRecord) (map[string]any, error) {
	scans := []map[string]any{}
	counts := map[string]int{"total": len(c.Targets), "completed": 0, "pending": 0, "running": 0, "failed": 0}
	rows, err := tx.Query(ctx, `SELECT r.id,r.data,r.created_at FROM campaign_scans l JOIN resources r ON r.id=l.scan_id AND r.kind='scans' WHERE l.campaign_id=$1 ORDER BY l.target_index`, c.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	status := "draft"
	for rows.Next() {
		var id string
		var data map[string]any
		var created time.Time
		if err := rows.Scan(&id, &data, &created); err != nil {
			return nil, err
		}
		out := map[string]any{"id": id, "created_at": created}
		for _, k := range []string{"service_id", "service_name", "profile", "scope_id", "scenario_id", "status"} {
			out[k] = str(data, k)
		}
		scans = append(scans, out)
		switch str(data, "status") {
		case "completed":
			counts["completed"]++
		case "running":
			counts["running"]++
		case "queued", "pending_approval", "awaiting_import":
			counts["pending"]++
		default:
			counts["failed"]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if c.StartedAt != nil {
		switch {
		case counts["running"] > 0:
			status = "running"
		case counts["pending"] > 0:
			status = "queued"
			for _, s := range scans {
				if str(s, "status") == "pending_approval" {
					status = "pending_approval"
					break
				}
				if str(s, "status") == "awaiting_import" {
					status = "awaiting_import"
				}
			}
		case counts["completed"] == len(c.Targets):
			status = "completed"
		default:
			status = "inconclusive"
		}
	}
	return map[string]any{"id": c.ID, "name": c.Name, "description": c.Description, "targets": c.Targets, "scans": scans, "status": status, "created_at": c.CreatedAt, "started_at": c.StartedAt, "summary": counts}, nil
}

func (a *App) ListCampaigns(ctx context.Context, u User) (map[string]any, error) {
	if !campaignScopes(u, false, false) {
		return nil, errCampaignPermission
	}
	tx, err := a.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Keep a consistent authorization snapshot across the list and its summaries.
	rows, err := tx.Query(ctx, `SELECT c.id,c.owner_id,c.name,c.description,c.targets,c.created_at,c.started_at FROM campaigns c WHERE $1::text='' AND `+campaignVisibilitySQL+` ORDER BY c.created_at DESC,c.id DESC`, "", elevated(u), u.ID, leadTeam(u))
	if err != nil {
		return nil, err
	}
	campaigns := []campaignRecord{}
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		campaigns = append(campaigns, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	items := []map[string]any{}
	for _, c := range campaigns {
		out, err := a.campaignOutput(ctx, tx, c)
		if err != nil {
			return nil, err
		}
		items = append(items, out)
	}
	return map[string]any{"items": items, "total": len(items)}, nil
}

func (a *App) GetCampaign(ctx context.Context, u User, id string) (map[string]any, error) {
	if !campaignScopes(u, false, false) {
		return nil, errCampaignPermission
	}
	tx, err := a.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	c, err := campaignSelect(ctx, tx, u, id, false)
	if err != nil {
		return nil, err
	}
	return a.campaignOutput(ctx, tx, c)
}

func campaignHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errCampaignNotFound):
		fail(w, 404, errCampaignNotFound.Error())
	case errors.Is(err, errCampaignPermission):
		fail(w, 403, errCampaignPermission.Error())
	default:
		fail(w, 500, "캠페인 처리에 실패했습니다")
	}
}

func (a *App) listCampaigns(w http.ResponseWriter, r *http.Request) {
	out, err := a.ListCampaigns(r.Context(), currentUser(r))
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	jsonResponse(w, 200, out)
}

func (a *App) getCampaign(w http.ResponseWriter, r *http.Request) {
	out, err := a.GetCampaign(r.Context(), currentUser(r), r.PathValue("id"))
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	jsonResponse(w, 200, out)
}

func normalizeCampaignTargets(targets []campaignTarget) ([]campaignTarget, error) {
	if len(targets) < 1 || len(targets) > 20 {
		return nil, errors.New("캠페인에는 1~20개의 진단 대상을 등록할 수 있습니다")
	}
	seen := map[string]bool{}
	for i := range targets {
		t := &targets[i]
		if t.Profile == "" {
			t.Profile = "http-baseline"
		}
		if t.ServiceID == "" || len(t.ServiceID) > 128 || len(t.ScopeID) > 128 || len(t.ScenarioID) > 128 || !hasString([]string{"http-baseline", "authorization", "import-only"}, t.Profile) {
			return nil, errors.New("서비스와 지원하는 진단 프로파일을 선택하세요")
		}
		if t.Profile == "authorization" && t.ScenarioID == "" {
			return nil, errors.New("권한 진단에는 시나리오가 필요합니다")
		}
		if t.Profile != "authorization" && t.ScenarioID != "" {
			return nil, errors.New("권한 진단에서만 시나리오를 선택할 수 있습니다")
		}
		key := campaignTargetKey(*t)
		if seen[key] {
			return nil, errors.New("같은 서비스·프로파일·시나리오는 한 번만 등록할 수 있습니다")
		}
		seen[key] = true
	}
	return targets, nil
}

func campaignTargetKey(t campaignTarget) string {
	b, _ := json.Marshal([]string{t.ServiceID, t.Profile, t.ScenarioID})
	return string(b)
}

// Lock parent rows in a stable order so ownership cannot change mid-start.
func campaignParentAccess(ctx context.Context, tx pgx.Tx, u User, targets []campaignTarget) error {
	ids := []string{}
	for _, target := range targets {
		if !hasString(ids, target.ServiceID) {
			ids = append(ids, target.ServiceID)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		var owner, team string
		err := tx.QueryRow(ctx, `SELECT owner_id,COALESCE(data->>'team','') FROM resources WHERE kind='services' AND id=$1 FOR SHARE`, id).Scan(&owner, &team)
		if err != nil || !(elevated(u) || owner == u.ID || leadTeam(u) != "" && team == leadTeam(u)) {
			return errCampaignNotFound
		}
	}
	return nil
}

func (a *App) createCampaign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string           `json:"name"`
		Description string           `json:"description"`
		Targets     []campaignTarget `json:"targets"`
	}
	if decode(r, &in) != nil || strings.TrimSpace(in.Name) == "" || utf8.RuneCountInString(in.Name) > 200 || utf8.RuneCountInString(in.Description) > 4000 || strings.ContainsRune(in.Name+in.Description, '\x00') {
		fail(w, 400, "캠페인 이름(200자 이하)과 설명(4000자 이하)을 확인하세요")
		return
	}
	targets, err := normalizeCampaignTargets(in.Targets)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	u, ctx := currentUser(r), r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	if err = campaignParentAccess(ctx, tx, u, targets); err != nil {
		campaignHTTPError(w, err)
		return
	}
	b, _ := json.Marshal(targets)
	c, err := scanCampaign(tx.QueryRow(ctx, `INSERT INTO campaigns(id,owner_id,name,description,targets) VALUES($1,$2,$3,$4,$5) RETURNING id,owner_id,name,description,targets,created_at,started_at`, newID(), u.ID, strings.TrimSpace(in.Name), in.Description, b))
	if err == nil {
		err = campaignAudit(ctx, tx, u, "campaign.create", c.ID, map[string]any{"targets": len(targets)})
	}
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	out, err := a.campaignOutput(ctx, tx, c)
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	jsonResponse(w, 201, out)
}

func campaignAudit(ctx context.Context, tx pgx.Tx, u User, action, id string, detail map[string]any) error {
	b, _ := json.Marshal(detail)
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,$3,$4,$5,$6)`, newID(), u.ID, u.Username, action, id, b)
	return err
}

func (a *App) startCampaign(w http.ResponseWriter, r *http.Request) {
	ctx, u := r.Context(), currentUser(r)
	// Policy preparation reads from the pool. Finish it before acquiring a write
	// transaction so concurrent campaign row-lock waiters cannot exhaust the pool.
	before, err := a.GetCampaign(ctx, u, r.PathValue("id"))
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	if started, _ := before["started_at"].(*time.Time); started != nil {
		jsonResponse(w, 200, before)
		return
	}
	var targets []campaignTarget
	rawTargets, _ := json.Marshal(before["targets"])
	if err := json.Unmarshal(rawTargets, &targets); err != nil {
		campaignHTTPError(w, err)
		return
	}
	prepared := make([]*preparedScan, 0, len(targets))
	for i, target := range targets {
		input := map[string]any{"service_id": target.ServiceID, "profile": target.Profile, "scope_id": target.ScopeID, "scenario_id": target.ScenarioID}
		scan, err := a.prepareScan(ctx, u, input, "", "")
		if err != nil {
			fail(w, 400, fmt.Sprintf("대상 %d의 진단을 시작할 수 없습니다: %s", i+1, safeProbeError(err)))
			return
		}
		prepared = append(prepared, scan)
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	c, err := campaignSelect(ctx, tx, u, r.PathValue("id"), true)
	if err == nil {
		err = campaignParentAccess(ctx, tx, u, c.Targets)
	}
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	if c.StartedAt == nil {
		for i, ready := range prepared {
			scan, err := a.insertPreparedScan(ctx, tx, u, ready)
			if err != nil {
				fail(w, 400, fmt.Sprintf("대상 %d의 진단을 시작할 수 없습니다: %s", i+1, safeProbeError(err)))
				return
			}
			id := str(scan, "id")
			marked, markErr := tx.Exec(ctx, `UPDATE resources SET data=data||jsonb_build_object('campaign_id',$2::text) WHERE id=$1 AND kind='scans' AND owner_id=$3`, id, c.ID, u.ID)
			if markErr != nil || marked.RowsAffected() != 1 {
				fail(w, 500, "생성된 진단의 캠페인 연결을 확인할 수 없습니다")
				return
			}
			_, err = tx.Exec(ctx, `INSERT INTO campaign_scans(campaign_id,target_index,scan_id) VALUES($1,$2,$3)`, c.ID, i, id)
			if err != nil {
				campaignHTTPError(w, err)
				return
			}
		}
		now := time.Now().UTC()
		c.StartedAt = &now
		if _, err = tx.Exec(ctx, `UPDATE campaigns SET started_at=$2 WHERE id=$1`, c.ID, now); err == nil {
			err = campaignAudit(ctx, tx, u, "campaign.start", c.ID, map[string]any{"scans": len(c.Targets)})
		}
		if err != nil {
			campaignHTTPError(w, err)
			return
		}
	}
	out, err := a.campaignOutput(ctx, tx, c)
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	jsonResponse(w, 200, out)
}

type scanObservationContextKey struct{}
type scanObservationExecution struct{ PolicyFingerprint, EngineVersion string }

func withScanObservationContext(ctx context.Context, policyFingerprint, engineVersion string) context.Context {
	return context.WithValue(ctx, scanObservationContextKey{}, scanObservationExecution{policyFingerprint, engineVersion})
}

// recordScanObservations is called inside the finding-ingestion transaction,
// including an empty successful result. It deliberately excludes evidence,
// credentials and mutable finding lifecycle fields from the immutable record.
func (a *App) recordScanObservations(ctx context.Context, tx pgx.Tx, scanID, serviceID string, findings []map[string]any) error {
	if scanID == "" {
		return nil
	}
	if len(findings) > 5000 {
		return errors.New("비교용 진단 관찰 결과는 5000건 이하입니다")
	}
	var data map[string]any
	if err := tx.QueryRow(ctx, `SELECT data FROM resources WHERE kind='scans' AND id=$1 AND data->>'service_id'=$2`, scanID, serviceID).Scan(&data); err != nil {
		return errors.New("관찰 결과와 연결된 진단을 확인할 수 없습니다")
	}
	execution, trusted := ctx.Value(scanObservationContextKey{}).(scanObservationExecution)
	trusted = trusted && execution.PolicyFingerprint != "" && execution.EngineVersion != "" && hasString([]string{"http-baseline", "authorization"}, str(data, "profile"))
	conditions, _ := json.Marshal([]string{serviceID, str(data, "profile"), str(data, "scenario_id"), execution.PolicyFingerprint, execution.EngineVersion, str(data, "import_format")})
	hash := sha256.Sum256(conditions)
	conditionsHash := hex.EncodeToString(hash[:])
	byFingerprint := map[string]map[string]any{}
	for _, f := range findings {
		id, fingerprint := str(f, "id"), str(f, "fingerprint")
		if id == "" || fingerprint == "" {
			return errors.New("정규화된 발견 건 식별자와 fingerprint가 필요합니다")
		}
		item := map[string]any{"finding_id": id, "fingerprint": fingerprint, "service_id": serviceID, "scan_id": scanID}
		for _, k := range []string{"title", "severity", "source", "rule_id", "cve", "component", "location"} {
			item[k] = maskEvidence(str(f, k))
		}
		if previous, exists := byFingerprint[fingerprint]; exists {
			before, _ := json.Marshal(previous)
			after, _ := json.Marshal(item)
			if string(before) != string(after) {
				return errors.New("같은 fingerprint의 관찰 결과가 서로 다릅니다")
			}
		}
		byFingerprint[fingerprint] = item
	}
	keys := make([]string, 0, len(byFingerprint))
	for key := range byFingerprint {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := []map[string]any{}
	for _, key := range keys {
		items = append(items, byFingerprint[key])
	}
	b, err := json.Marshal(items)
	if err != nil {
		return err
	}
	ct, err := tx.Exec(ctx, `INSERT INTO scan_observations(scan_id,service_id,profile,scenario_id,conditions_hash,trusted,import_format,findings) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(scan_id) DO NOTHING`, scanID, serviceID, str(data, "profile"), str(data, "scenario_id"), conditionsHash, trusted, str(data, "import_format"), b)
	if err != nil || ct.RowsAffected() == 1 {
		return err
	}
	var identical bool
	err = tx.QueryRow(ctx, `SELECT service_id=$2 AND conditions_hash=$3 AND trusted=$4 AND findings=$5::jsonb FROM scan_observations WHERE scan_id=$1`, scanID, serviceID, conditionsHash, trusted, b).Scan(&identical)
	if err != nil {
		return err
	}
	if !identical {
		return errors.New("이미 보존된 진단 관찰 결과를 덮어쓸 수 없습니다")
	}
	return nil
}

type campaignSnapshot struct {
	Key, ConditionsHash string
	Findings            []map[string]any
}

func campaignSnapshots(ctx context.Context, tx pgx.Tx, c campaignRecord) (map[string]campaignSnapshot, []string, error) {
	out := map[string]campaignSnapshot{}
	reasons := []string{}
	if c.StartedAt == nil {
		return out, []string{"아직 시작하지 않은 캠페인은 비교할 수 없습니다"}, nil
	}
	for i, target := range c.Targets {
		var status string
		var snapshot []byte
		var hash *string
		var trusted *bool
		err := tx.QueryRow(ctx, `SELECT r.data->>'status',o.conditions_hash,o.trusted,o.findings FROM campaign_scans l JOIN resources r ON r.id=l.scan_id LEFT JOIN scan_observations o ON o.scan_id=l.scan_id AND o.service_id=$3 WHERE l.campaign_id=$1 AND l.target_index=$2`, c.ID, i, target.ServiceID).Scan(&status, &hash, &trusted, &snapshot)
		if errors.Is(err, pgx.ErrNoRows) {
			reasons = append(reasons, fmt.Sprintf("대상 %d의 연결된 진단이 없습니다", i+1))
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if status != "completed" {
			reasons = append(reasons, fmt.Sprintf("대상 %d의 진단이 완료되지 않았습니다", i+1))
			continue
		}
		if hash == nil || trusted == nil || !*trusted {
			reasons = append(reasons, fmt.Sprintf("대상 %d에 실행 조건과 완전성을 확인한 관측 기록이 없습니다. 이전 버전이나 외부 수입 결과는 비교할 수 없습니다", i+1))
			continue
		}
		var findings []map[string]any
		if err := json.Unmarshal(snapshot, &findings); err != nil {
			return nil, nil, err
		}
		key := campaignTargetKey(target)
		out[key] = campaignSnapshot{Key: key, ConditionsHash: *hash, Findings: findings}
	}
	return out, reasons, nil
}

func (a *App) CompareCampaigns(ctx context.Context, u User, currentID, baselineID string) (map[string]any, error) {
	if !campaignScopes(u, false, true) {
		return nil, errCampaignPermission
	}
	tx, err := a.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	current, err := campaignSelect(ctx, tx, u, currentID, false)
	if err != nil {
		return nil, err
	}
	baseline, err := campaignSelect(ctx, tx, u, baselineID, false)
	if err != nil {
		return nil, err
	}
	c, err := a.campaignOutput(ctx, tx, current)
	if err != nil {
		return nil, err
	}
	b, err := a.campaignOutput(ctx, tx, baseline)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"baseline": b, "current": c, "comparable": false, "reasons": []string{}, "added": []map[string]any{}, "persisting": []map[string]any{}, "not_seen": []map[string]any{}, "changed": []map[string]any{}}
	currentSets, currentReasons, err := campaignSnapshots(ctx, tx, current)
	if err != nil {
		return nil, err
	}
	baselineSets, baselineReasons, err := campaignSnapshots(ctx, tx, baseline)
	if err != nil {
		return nil, err
	}
	reasons := []string{}
	for _, reason := range baselineReasons {
		reasons = append(reasons, "기준 캠페인: "+reason)
	}
	for _, reason := range currentReasons {
		reasons = append(reasons, "현재 캠페인: "+reason)
	}
	if len(current.Targets) != len(baseline.Targets) {
		reasons = append(reasons, "두 캠페인의 서비스·진단 대상 구성이 다릅니다")
	}
	for _, target := range current.Targets {
		key := campaignTargetKey(target)
		base, exists := baselineSets[key]
		cur, ready := currentSets[key]
		if !exists || !ready {
			if len(reasons) == 0 {
				reasons = append(reasons, "두 캠페인의 서비스·프로파일·시나리오 구성이 다릅니다")
			}
			continue
		}
		if base.ConditionsHash != cur.ConditionsHash {
			reasons = append(reasons, "대상·진단 범위·정책·인증 조건 또는 엔진 버전이 달라 비교할 수 없습니다")
		}
	}
	if len(reasons) > 0 {
		out["reasons"] = reasons
		return out, nil
	}
	added, persisting, notSeen, changed := []map[string]any{}, []map[string]any{}, []map[string]any{}, []map[string]any{}
	for _, target := range current.Targets {
		key := campaignTargetKey(target)
		previous := map[string]map[string]any{}
		for _, finding := range baselineSets[key].Findings {
			previous[str(finding, "fingerprint")] = finding
		}
		for _, finding := range currentSets[key].Findings {
			fingerprint := str(finding, "fingerprint")
			before, exists := previous[fingerprint]
			if !exists {
				added = append(added, finding)
				continue
			}
			persisting = append(persisting, finding)
			for _, field := range []string{"title", "severity", "source", "rule_id", "cve", "component", "location"} {
				if str(before, field) != str(finding, field) {
					changed = append(changed, map[string]any{"before": before, "after": finding})
					break
				}
			}
			delete(previous, fingerprint)
		}
		missingKeys := []string{}
		for fingerprint := range previous {
			missingKeys = append(missingKeys, fingerprint)
		}
		sort.Strings(missingKeys)
		for _, fingerprint := range missingKeys {
			notSeen = append(notSeen, previous[fingerprint])
		}
	}
	out["comparable"], out["added"], out["persisting"], out["not_seen"], out["changed"] = true, added, persisting, notSeen, changed
	return out, nil
}

func (a *App) compareCampaign(w http.ResponseWriter, r *http.Request) {
	baseline := r.URL.Query().Get("baseline")
	if baseline == "" {
		fail(w, 400, "비교할 기준 캠페인을 선택하세요")
		return
	}
	out, err := a.CompareCampaigns(r.Context(), currentUser(r), r.PathValue("id"), baseline)
	if err != nil {
		campaignHTTPError(w, err)
		return
	}
	jsonResponse(w, 200, out)
}
