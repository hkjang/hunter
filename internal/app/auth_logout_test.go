package app

import (
	"context"
	"testing"
)

func TestLogoutFailurePreservesSessionUntilDeletionSucceeds(t *testing.T) {
	a, s := testApp(t)
	cookie := loginTest(t, s, "admin", "test-password-1234")
	_, e := a.DB.Exec(context.Background(), `CREATE FUNCTION reject_session_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic logout storage failure'; END $$;
 CREATE TRIGGER reject_session_delete BEFORE DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION reject_session_delete()`)
	if e != nil {
		t.Fatal(e)
	}
	status, _, headers := request(t, s, "POST", "/api/auth/logout", nil, cookie, true)
	if status != 503 {
		t.Fatalf("logout storage failure got %d", status)
	}
	if len(headers.Values("Set-Cookie")) != 0 {
		t.Fatal("failed logout changed session or suppression cookie")
	}
	mustRequest(t, s, "GET", "/api/auth/me", nil, cookie, 200)
	if _, e = a.DB.Exec(context.Background(), `DROP TRIGGER reject_session_delete ON sessions`); e != nil {
		t.Fatal(e)
	}
	mustRequest(t, s, "POST", "/api/auth/logout", nil, cookie, 200)
	mustRequest(t, s, "GET", "/api/auth/me", nil, cookie, 401)
}
