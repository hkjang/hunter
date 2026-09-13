package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Hold both requests in BEFORE INSERT after their DELETE saw the empty table.
// This reproduces the old DELETE/INSERT uniqueness race deterministically rather
// than relying on scheduler timing or hoping two pg_sleep calls overlap.
func TestTrackingConcurrentPreviewsReplaceAtomically(t *testing.T) {
	a, server := testApp(t)
	admin := loginTest(t, server, "admin", "test-password-1234")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	const lockNamespace int32 = 190071
	lockID := int32(binary.LittleEndian.Uint32(random[:]) & 0x7fffffff)
	ddl := fmt.Sprintf(`CREATE FUNCTION tracking_test_insert_gate() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM pg_advisory_xact_lock(%d,%d); RETURN NEW; END $$;
 CREATE TRIGGER tracking_test_insert_gate BEFORE INSERT ON visitor_tracking_previews
 FOR EACH ROW EXECUTE FUNCTION tracking_test_insert_gate();`, lockNamespace, lockID)
	if _, err := a.DB.Exec(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	gate, err := a.DB.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	locked := false
	release := func() {
		if locked {
			cleanupCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = gate.Exec(cleanupCtx, `SELECT pg_advisory_unlock($1::int,$2::int)`, lockNamespace, lockID)
			stop()
			locked = false
		}
	}
	defer gate.Release()
	defer release()
	if _, err = gate.Exec(ctx, `SELECT pg_advisory_lock($1::int,$2::int)`, lockNamespace, lockID); err != nil {
		t.Fatal(err)
	}
	locked = true
	var pending int
	if err = gate.QueryRow(ctx, `SELECT count(*) FROM visitor_tracking_previews`).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("expected an empty isolated preview table")
	}
	type result struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan result, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		payload, _ := json.Marshal(map[string]any{"enabled": false, "name": fmt.Sprintf("동시 초안 %d", i), "script": fmt.Sprintf(`window.syntheticConcurrentPreview=%d;`, i), "allowed_origins": []string{}, "revision": 0})
		go func(body []byte) {
			<-start
			req, e := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/admin/tracking/test", bytes.NewReader(body))
			if e != nil {
				done <- result{err: e}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Cookie", admin)
			req.Header.Set("X-Hunter-CSRF", "1")
			res, e := server.Client().Do(req)
			if e != nil {
				done <- result{err: e}
				return
			}
			output, e := io.ReadAll(io.LimitReader(res.Body, 16384))
			res.Body.Close()
			done <- result{res.StatusCode, output, e}
		}(payload)
	}
	close(start)
	deadline := time.Now().Add(8 * time.Second)
	for {
		var waiters int
		err = gate.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=$1::oid AND objid=$2::oid AND objsubid=2 AND NOT granted`, lockNamespace, lockID).Scan(&waiters)
		if err != nil {
			t.Fatal(err)
		}
		if waiters == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("both requests must reach INSERT before gate release; observed %d waiters", waiters)
		}
		time.Sleep(20 * time.Millisecond)
	}
	release()
	replies := make([]map[string]any, 0, 2)
	for i := 0; i < 2; i++ {
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.status != 200 {
			t.Fatalf("concurrent preview %d returned status %d, expected 200", i, r.status)
		}
		var body map[string]any
		if json.Unmarshal(r.body, &body) != nil || body["ok"] != true {
			t.Fatal("invalid successful preview response")
		}
		replies = append(replies, body)
	}
	if replies[0]["preview_token"] == replies[1]["preview_token"] {
		t.Fatal("concurrent previews reused a token")
	}
	var cipher, tokenHash string
	if err = a.DB.QueryRow(ctx, `SELECT count(*) FROM visitor_tracking_previews`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("expected exactly one pending preview, got %d", pending)
	}
	if err = a.DB.QueryRow(ctx, `SELECT token_hash,config_encrypted FROM visitor_tracking_previews`).Scan(&tokenHash, &cipher); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cipher, "enc:v1:") || strings.Contains(cipher, "syntheticConcurrentPreview") || strings.Contains(cipher, "동시 초안") {
		t.Fatal("preview payload was stored in plaintext")
	}
	plain, err := a.decrypt(cipher)
	if err != nil {
		t.Fatal("persisted preview cannot be decrypted")
	}
	var stored trackingConfig
	if json.Unmarshal([]byte(plain), &stored) != nil || !strings.Contains(stored.Script, "syntheticConcurrentPreview") {
		t.Fatal("encrypted preview does not contain one complete draft")
	}
	valid := 0
	for _, reply := range replies {
		endpoint := asString(reply["preview_url"])
		status, body, _ := request(t, server, "GET", endpoint, nil, admin, true)
		if digest(asString(reply["preview_token"])) == tokenHash {
			if status != 200 || !bytes.Contains(body, []byte("syntheticConcurrentPreview")) {
				t.Fatal("latest preview unavailable")
			}
			valid++
			mustRequest(t, server, "GET", endpoint, nil, admin, 404)
		} else if status != 404 {
			t.Fatalf("superseded preview returned %d", status)
		}
	}
	if valid != 1 {
		t.Fatal("expected exactly one usable preview token")
	}
	if err = a.DB.QueryRow(ctx, `SELECT count(*) FROM visitor_tracking_previews`).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("preview was not consumed once")
	}
	live := mustRequest(t, server, "GET", "/api/admin/tracking", nil, admin, 200)
	if live["revision"] != float64(0) || live["enabled"] != false || live["script"] != "" {
		t.Fatal("concurrent preview changed live tracking configuration")
	}
	var audit string
	if err = a.DB.QueryRow(ctx, `SELECT coalesce(string_agg(detail::text,''),'') FROM audit_logs WHERE action='tracking.test'`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, "syntheticConcurrentPreview") || strings.Contains(audit, "동시 초안") {
		t.Fatal("preview code leaked to audit")
	}
}
