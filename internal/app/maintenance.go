package app

import (
	"context"
	"log/slog"
	"time"
)

func (a *App) ExpireRiskAcceptances(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `WITH reopened AS (
 UPDATE resources SET data=data||jsonb_build_object('status','candidate','acceptance_expired_at',now()),updated_at=now()
 WHERE kind='findings' AND data->>'status'='accepted' AND data->>'expires_at' IS NOT NULL AND (data->>'expires_at')::timestamptz<=now()
 RETURNING id,owner_id
 ) INSERT INTO audit_logs(id,user_id,username,action,target,detail)
 SELECT md5(random()::text||clock_timestamp()::text||id),owner_id,'system','finding.acceptance_expired',id,'{"reason":"위험 수용 기간 만료로 재검토"}'::jsonb FROM reopened`)
	return err
}
func (a *App) StartMaintenance(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		lastAuthCleanup := time.Time{}
		cleanup := func() {
			c, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := a.ExpireRiskAcceptances(c); err != nil && ctx.Err() == nil {
				slog.Error("expired risk acceptance reopen failed")
			}
			if time.Since(lastAuthCleanup) < time.Hour {
				return
			}
			for _, q := range []string{"DELETE FROM sessions WHERE expires_at<now()", "DELETE FROM oidc_states WHERE expires_at<now()", "DELETE FROM login_attempts WHERE window_start<now()-interval '1 day'"} {
				if _, e := a.DB.Exec(c, q); e != nil && ctx.Err() == nil {
					slog.Error("expired authentication data cleanup failed")
					return
				}
			}
			lastAuthCleanup = time.Now()
		}
		cleanup()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanup()
			}
		}
	}()
}
