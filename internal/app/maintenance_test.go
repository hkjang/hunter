package app

import (
	"context"
	"testing"
)

func TestExpiredRiskAcceptanceReopens(t *testing.T) {
	a, s := testApp(t)
	c := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "expiry test", "environment": "staging"}, c, 200)
	finding := mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "expired risk", "service_id": service["id"], "severity": "critical", "status": "candidate"}, c, 200)
	_, e := a.DB.Exec(context.Background(), `UPDATE resources SET data=data||jsonb_build_object('status','accepted','expires_at',now()-interval '1 minute') WHERE id=$1`, finding["id"])
	if e != nil {
		t.Fatal(e)
	}
	if e = a.ExpireRiskAcceptances(context.Background()); e != nil {
		t.Fatal(e)
	}
	f := mustRequest(t, s, "GET", "/api/findings/"+asString(finding["id"]), nil, c, 200)
	if f["status"] != "candidate" || f["acceptance_expired_at"] == nil {
		t.Fatal("expired risk remains accepted")
	}
	var count int
	a.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE action='finding.acceptance_expired' AND target=$1`, finding["id"]).Scan(&count)
	if count != 1 {
		t.Fatal("missing expiry audit")
	}
	a.ExpireRiskAcceptances(context.Background())
	a.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE action='finding.acceptance_expired' AND target=$1`, finding["id"]).Scan(&count)
	if count != 1 {
		t.Fatal("duplicate expiry event")
	}
}
