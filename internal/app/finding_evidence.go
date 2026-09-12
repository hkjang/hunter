package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

const legacyEvidencePredicate = `kind='findings' AND data ? 'evidence' AND jsonb_typeof(data->'evidence') IS DISTINCT FROM 'string'`

// New calls initDomain only after validating the encryption key against this
// database. Repair completes before starting the HTTP server or workers. Each
// batch commits independently, so restart resumes safely without one large lock.
func (a *App) repairLegacyFindingEvidence(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		count, err := a.repairLegacyEvidenceBatch(ctx)
		if err != nil {
			return errors.New("기존 증거 암호화 복구에 실패했습니다. DB 접근과 잠금을 확인한 뒤 다시 시작하세요")
		}
		if count > 0 {
			continue
		}
		var remains bool
		if err = a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resources WHERE `+legacyEvidencePredicate+`)`).Scan(&remains); err != nil {
			return errors.New("기존 증거 암호화 복구 상태를 확인하지 못했습니다")
		}
		if !remains {
			return nil
		}
		// SKIP LOCKED returning no rows does not mean all legacy data was repaired.
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("기존 증거 암호화 복구가 잠금 대기로 완료되지 않았습니다")
		case <-timer.C:
		}
	}
}

func (a *App) repairLegacyEvidenceBatch(ctx context.Context) (int, error) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// Only IDs are buffered. Large historical evidence is normalized one row at a
	// time using the same evidence length/redaction rules as current writes.
	rows, err := tx.Query(ctx, `SELECT id FROM resources WHERE `+legacyEvidencePredicate+` ORDER BY id LIMIT 50 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	for _, id := range ids {
		v, err := scanResource(tx.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE id=$1`, id))
		if err != nil {
			return 0, err
		}
		if err = a.sealDomainSecrets(&v, cloneMap(v.Data), map[string]any{}); err != nil {
			return 0, err
		}
		data, err := json.Marshal(v.Data)
		if err != nil {
			return 0, err
		}
		if _, err = tx.Exec(ctx, `UPDATE resources SET data=$2,updated_at=clock_timestamp() WHERE id=$1`, id, data); err != nil {
			return 0, err
		}
	}
	detail, _ := json.Marshal(map[string]any{"count": len(ids), "repair": "structured_evidence"})
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,'system','system','finding.evidence_repaired','findings',$2)`, newID(), detail); err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(ids), nil
}
