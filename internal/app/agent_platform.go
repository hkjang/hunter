package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
)

var platformGroups = []string{"search", "memory", "models", "execution", "observability"}

type platformConfigProblem struct {
	Status int
	Text   string
}

func (e *platformConfigProblem) Error() string { return e.Text }

func platformConfigError(w http.ResponseWriter, err error) {
	var problem *platformConfigProblem
	if errors.As(err, &problem) {
		fail(w, problem.Status, problem.Text)
		return
	}
	fail(w, 503, "연동 설정을 처리하지 못했습니다. 잠시 후 다시 시도하세요")
}

func (a *App) initAgentPlatform(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS agent_platform_config (
 group_name text PRIMARY KEY, config_encrypted text NOT NULL, updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
 CREATE TABLE IF NOT EXISTS agent_platform_health (
 group_name text NOT NULL REFERENCES agent_platform_config(group_name),provider_id text NOT NULL,
 revision timestamptz NOT NULL,failures integer NOT NULL DEFAULT 0,failure_threshold integer NOT NULL DEFAULT 3,
 cooldown_seconds integer NOT NULL DEFAULT 30,open_until timestamptz,probe_until timestamptz,
 last_state text NOT NULL DEFAULT 'unknown',last_code text NOT NULL DEFAULT '',last_elapsed_ms bigint NOT NULL DEFAULT 0,
 attempts bigint NOT NULL DEFAULT 0,last_checked_at timestamptz,PRIMARY KEY(group_name,provider_id));`)
	if err != nil {
		return err
	}
	cipher, err := a.encrypt(`{}`)
	if err != nil {
		return err
	}
	for _, group := range platformGroups {
		if _, err = a.DB.Exec(ctx, `INSERT INTO agent_platform_config(group_name,config_encrypted) VALUES($1,$2) ON CONFLICT DO NOTHING`, group, cipher); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) loadPlatformConfig(ctx context.Context, group string, dst any) (time.Time, error) {
	var revision time.Time
	if !hasString(platformGroups, group) {
		return revision, errors.New("unknown platform configuration")
	}
	var cipher string
	if err := a.DB.QueryRow(ctx, `SELECT config_encrypted,updated_at FROM agent_platform_config WHERE group_name=$1`, group).Scan(&cipher, &revision); err != nil {
		return revision, err
	}
	plain, err := a.decrypt(cipher)
	if err == nil {
		err = json.Unmarshal([]byte(plain), dst)
	}
	return revision, err
}

// build merges and validates against the locked current configuration. No
// remote request belongs in this callback: optional providers never hold DB locks.
func (a *App) mutatePlatformConfig(ctx context.Context, group, expected string, build func(json.RawMessage) (any, error)) (time.Time, error) {
	var revision time.Time
	if !hasString(platformGroups, group) {
		return revision, &platformConfigProblem{400, "알 수 없는 연동 설정입니다"}
	}
	wanted, err := time.Parse(time.RFC3339Nano, expected)
	if err != nil {
		return revision, &platformConfigProblem{400, "설정을 조회한 expected_updated_at이 필요합니다"}
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return revision, err
	}
	defer tx.Rollback(ctx)
	var cipher string
	if err = tx.QueryRow(ctx, `SELECT config_encrypted,updated_at FROM agent_platform_config WHERE group_name=$1 FOR UPDATE`, group).Scan(&cipher, &revision); err != nil {
		return revision, err
	}
	if !revision.Equal(wanted) {
		return revision, &platformConfigProblem{409, "연동 설정이 변경되었습니다. 입력을 보존한 채 최신 설정을 다시 확인하세요"}
	}
	plain, err := a.decrypt(cipher)
	if err != nil {
		return revision, err
	}
	value, err := build(json.RawMessage(plain))
	if err != nil {
		return revision, &platformConfigProblem{400, err.Error()}
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 1<<20 {
		return revision, &platformConfigProblem{400, "연동 설정은 1 MiB 이하의 JSON이어야 합니다"}
	}
	cipher, err = a.encrypt(string(raw))
	if err != nil {
		return revision, err
	}
	if err = tx.QueryRow(ctx, `UPDATE agent_platform_config SET config_encrypted=$2,updated_at=clock_timestamp() WHERE group_name=$1 RETURNING updated_at`, group, cipher).Scan(&revision); err != nil {
		return revision, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM agent_platform_health WHERE group_name=$1`, group); err != nil {
		return revision, err
	}
	return revision, tx.Commit(ctx)
}

type platformResilience struct {
	FailureThreshold int `json:"failure_threshold"`
	CooldownSeconds  int `json:"cooldown_seconds"`
}

func (p platformResilience) normalized() platformResilience {
	if p.FailureThreshold <= 0 {
		p.FailureThreshold = 3
	}
	if p.CooldownSeconds <= 0 {
		p.CooldownSeconds = 30
	}
	p.FailureThreshold = min(p.FailureThreshold, 20)
	p.CooldownSeconds = min(p.CooldownSeconds, 3600)
	return p
}

// Config then health is the lock order used by every operation. An expired
// open circuit admits one ordinary request, never a synthetic target probe.
func (a *App) platformPermit(ctx context.Context, group, providerID string, revision time.Time, policy platformResilience, timeout time.Duration) (bool, error) {
	if !hasString(platformGroups, group) || providerID == "" || len(providerID) > 100 {
		return false, errors.New("invalid provider identity")
	}
	policy = policy.normalized()
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 30 * time.Second
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var current time.Time
	if err = tx.QueryRow(ctx, `SELECT updated_at FROM agent_platform_config WHERE group_name=$1 FOR SHARE`, group).Scan(&current); err != nil {
		return false, err
	}
	if !current.Equal(revision) {
		return false, nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_platform_health(group_name,provider_id,revision,failure_threshold,cooldown_seconds) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, group, providerID, revision, policy.FailureThreshold, policy.CooldownSeconds)
	if err != nil {
		return false, err
	}
	var open, probe *time.Time
	if err = tx.QueryRow(ctx, `SELECT open_until,probe_until FROM agent_platform_health WHERE group_name=$1 AND provider_id=$2 FOR UPDATE`, group, providerID).Scan(&open, &probe); err != nil {
		return false, err
	}
	now := time.Now()
	if open != nil && now.Before(*open) || probe != nil && now.Before(*probe) {
		return false, nil
	}
	if open != nil {
		_, err = tx.Exec(ctx, `UPDATE agent_platform_health SET probe_until=$3,last_state='recovering' WHERE group_name=$1 AND provider_id=$2`, group, providerID, now.Add(timeout+time.Second))
		if err != nil {
			return false, err
		}
	}
	return true, tx.Commit(ctx)
}

var platformCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}$`)

func (a *App) platformOutcome(ctx context.Context, group, providerID string, revision time.Time, success bool, code string, elapsed time.Duration) error {
	if !platformCodePattern.MatchString(code) {
		code = "request_failed"
	}
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var current time.Time
	if err = tx.QueryRow(ctx, `SELECT updated_at FROM agent_platform_config WHERE group_name=$1 FOR SHARE`, group).Scan(&current); err != nil {
		return err
	}
	if !current.Equal(revision) {
		return nil
	}
	if success {
		_, err = tx.Exec(ctx, `UPDATE agent_platform_health SET failures=0,open_until=NULL,probe_until=NULL,last_state='healthy',last_code=$4,last_elapsed_ms=$5,attempts=attempts+1,last_checked_at=now() WHERE group_name=$1 AND provider_id=$2 AND revision=$3`, group, providerID, revision, code, max(int64(0), elapsed.Milliseconds()))
	} else {
		_, err = tx.Exec(ctx, `UPDATE agent_platform_health SET failures=failures+1,probe_until=NULL,
 open_until=CASE WHEN failures+1>=failure_threshold THEN now()+make_interval(secs=>cooldown_seconds) ELSE NULL END,
 last_state=CASE WHEN failures+1>=failure_threshold THEN 'open' ELSE 'degraded' END,
 last_code=$4,last_elapsed_ms=$5,attempts=attempts+1,last_checked_at=now()
 WHERE group_name=$1 AND provider_id=$2 AND revision=$3`, group, providerID, revision, code, max(int64(0), elapsed.Milliseconds()))
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a *App) platformStatus(ctx context.Context, group string) ([]map[string]any, error) {
	rows, err := a.DB.Query(ctx, `SELECT h.provider_id,h.failures,h.last_state,h.last_code,h.last_elapsed_ms,h.attempts,h.last_checked_at,h.open_until,h.probe_until FROM agent_platform_health h JOIN agent_platform_config c ON c.group_name=h.group_name AND c.updated_at=h.revision WHERE h.group_name=$1 ORDER BY h.provider_id LIMIT 200`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, state, code string
		var failures int
		var elapsed, attempts int64
		var checked, open, probe *time.Time
		if err = rows.Scan(&id, &failures, &state, &code, &elapsed, &attempts, &checked, &open, &probe); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"provider_id": id, "failures": failures, "state": state, "code": code, "elapsed_ms": elapsed, "attempts": attempts, "checked_at": checked, "open_until": open, "probe_until": probe})
	}
	return items, rows.Err()
}

// Connection tests are explicit administrator requests and return their actual
// result as data. A failed optional integration does not change app readiness.
func platformTestResult(ok bool, providerID, code, detail string, started time.Time) map[string]any {
	return map[string]any{"ok": ok, "provider_id": providerID, "code": code, "detail": detail, "elapsed_ms": time.Since(started).Milliseconds(), "checked_at": time.Now().UTC()}
}
