package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type executionMock struct {
	server                     *httptest.Server
	config                     agentExecutionServer
	mu                         sync.Mutex
	name, scanID, image, state string
	probe                      executionProbeInput
	result                     map[string]any
	created, started, killed   atomic.Int32
	deleteFailures             atomic.Int32
	mode                       string
	cancel                     context.CancelFunc
}

func newExecutionMock(t *testing.T, mode string) *executionMock {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(180), Subject: pkix.Name{CommonName: "Hunter synthetic Docker"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"probe.internal"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, _ := tls.X509KeyPair(certPEM, keyPEM)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	m := &executionMock{mode: mode}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("missing mTLS peer")
		}
		if mode == "preflight_fail" {
			http.Error(w, "unavailable", 503)
			return
		}
		path := r.URL.Path
		switch {
		case path == "/version":
			jsonResponse(w, 200, map[string]any{"ApiVersion": "1.47", "Os": "linux"})
		case strings.Contains(path, "/networks/"):
			jsonResponse(w, 200, map[string]any{"Name": m.config.Network, "Driver": "bridge"})
		case strings.Contains(path, "/images/"):
			jsonResponse(w, 200, map[string]any{"Id": "sha256:" + strings.Repeat("a", 64), "RepoDigests": []string{"hunter@sha256:" + strings.Repeat("a", 64)}, "Config": map[string]any{"Labels": map[string]string{"org.opencontainers.image.title": "hunter"}, "Env": []string{"PATH=/usr/local/bin:/usr/bin"}}})
		case strings.HasSuffix(path, "/containers/create"):
			var input map[string]any
			if decode(r, &input) != nil {
				t.Error("invalid create JSON")
			}
			host := object(input["HostConfig"])
			if str(input, "User") != "10001:10001" || !asBool(host["ReadonlyRootfs"]) || asBool(host["Privileged"]) || !hasString(stringList(host["CapDrop"]), "ALL") || len(object(input["Volumes"])) > 0 || len(stringList(host["Binds"])) > 0 || str(host, "NetworkMode") != m.config.Network {
				t.Error("container hardening violated")
			}
			if len(stringList(input["Entrypoint"])) != 1 || stringList(input["Entrypoint"])[0] != "/usr/local/bin/hunter" {
				t.Error("arbitrary entrypoint")
			}
			cmd := stringList(input["Cmd"])
			if len(cmd) != 2 || cmd[0] != "--execution-probe" {
				t.Error("arbitrary command")
			}
			raw, _ := base64.StdEncoding.DecodeString(cmd[1])
			var probe executionProbeInput
			_ = json.Unmarshal(raw, &probe)
			m.mu.Lock()
			m.name = r.URL.Query().Get("name")
			m.scanID = str(object(input["Labels"]), "hunter.scan_id")
			m.image = str(input, "Image")
			m.probe = probe
			m.state = "created"
			m.mu.Unlock()
			m.created.Add(1)
			if mode == "create_lost" {
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			jsonResponse(w, 201, map[string]any{"Id": "synthetic-container"})
		case strings.HasSuffix(path, "/start"):
			m.started.Add(1)
			m.mu.Lock()
			m.state = "running"
			probe := m.probe
			ctx, cancel := context.WithCancel(context.Background())
			m.cancel = cancel
			m.mu.Unlock()
			go func() {
				result := runExecutionProbe(ctx, probe)
				m.mu.Lock()
				if m.state != "removed" {
					m.result = result
					m.state = "exited"
				}
				m.mu.Unlock()
			}()
			w.WriteHeader(204)
		case strings.HasSuffix(path, "/kill"):
			m.killed.Add(1)
			m.mu.Lock()
			if m.cancel != nil {
				m.cancel()
			}
			m.state = "exited"
			m.mu.Unlock()
			w.WriteHeader(204)
		case strings.HasSuffix(path, "/logs"):
			m.mu.Lock()
			raw, _ := json.Marshal(m.result)
			m.mu.Unlock()
			frame := make([]byte, 8)
			frame[0] = 1
			binary.BigEndian.PutUint32(frame[4:], uint32(len(raw)))
			w.Write(append(frame, raw...))
		case strings.HasSuffix(path, "/json") && strings.Contains(path, "/containers/"):
			m.mu.Lock()
			state, name, scanID, image := m.state, m.name, m.scanID, m.image
			m.mu.Unlock()
			if state == "" || state == "removed" || !strings.Contains(path, name) {
				http.NotFound(w, r)
				return
			}
			jsonResponse(w, 200, map[string]any{"Id": "synthetic-container", "Image": image, "Config": map[string]any{"Labels": map[string]string{"hunter.scan_id": scanID, "hunter.execution": "fixed-probe-v1"}}, "State": map[string]any{"Status": state, "Running": state == "running", "ExitCode": 0}})
		case r.Method == "DELETE" && strings.Contains(path, "/containers/"):
			if m.deleteFailures.Load() > 0 {
				m.deleteFailures.Add(-1)
				http.Error(w, "synthetic cleanup unavailable", 503)
				return
			}
			m.mu.Lock()
			if m.cancel != nil {
				m.cancel()
			}
			m.state = "removed"
			m.mu.Unlock()
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	})
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	m.server = s
	m.config = agentExecutionServer{ID: "docker-" + mode, Name: "합성 Docker", Enabled: true, Endpoint: s.URL, CAPEM: string(certPEM), CertPEM: string(certPEM), KeyPEM: string(keyPEM), Network: "probe-net", TimeoutSeconds: 5, platformResilience: platformResilience{FailureThreshold: 1, CooldownSeconds: 30}}
	t.Cleanup(func() {
		m.mu.Lock()
		if m.cancel != nil {
			m.cancel()
		}
		m.mu.Unlock()
		s.Close()
	})
	return m
}

func executionFixture(t *testing.T, a *App, s *httptest.Server, admin, target string, c agentExecutionConfig) (domainResource, probePolicy) {
	t.Helper()
	ctx := context.Background()
	if e := a.initAgentExecution(ctx); e != nil {
		t.Fatal(e)
	}
	rev := knowledgeSave(t, a, "execution", c)
	_ = rev
	u := User{Role: "admin", Scopes: a.roleScopes(ctx, "admin")}
	if e := a.DB.QueryRow(ctx, `SELECT id FROM users WHERE username='admin'`).Scan(&u.ID); e != nil {
		t.Fatal(e)
	}
	svc := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "격리 합성 서비스", "url": target, "environment": "staging", "network": executionServiceNetwork(c.Servers[0]), "approved": true}, admin, 200)
	uri, _ := url.Parse(target)
	scope := mustRequest(t, s, "POST", "/api/scopes", map[string]any{"name": "격리 승인 범위", "service_id": svc["id"], "allowed_hosts": []string{uri.Host}, "allowed_paths": []string{"/"}, "approved": true, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)}, admin, 200)
	input := map[string]any{"service_id": svc["id"], "scope_id": scope["id"], "execution_profile_id": "headers"}
	service, _, p, e := a.scanPolicy(ctx, input)
	if e != nil {
		t.Fatal(e)
	}
	meta, e := a.prepareIsolatedScan(ctx, u, input, service, p)
	if e != nil {
		t.Fatal(e)
	}
	_ = meta
	input["profile"] = "isolated"
	out := mustRequest(t, s, "POST", "/api/scans", input, admin, 201)
	domainEnableWorker(t, a, "execution-worker", executionServiceNetwork(c.Servers[0]))
	id, e := a.claimScan(ctx, "execution-worker")
	if e != nil || id != str(out, "id") {
		t.Fatal("isolated scan not claimed")
	}
	scan, e := a.resource(ctx, "scans", id)
	if e != nil {
		t.Fatal(e)
	}
	return scan, p
}
func executionConfigFor(servers ...agentExecutionServer) agentExecutionConfig {
	c := defaultAgentExecution()
	c.Enabled = true
	c.Servers = servers
	ids := []string{}
	for _, s := range servers {
		ids = append(ids, s.ID)
	}
	c.Profiles = []agentExecutionProfile{{ID: "headers", Name: "고정 헤더", Enabled: true, Kind: "http_headers", Image: "hunter@sha256:" + strings.Repeat("a", 64), ServerIDs: ids}}
	return c
}
func TestAgentExecutionMTLSHardeningFailoverAndNoDuplicate(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	bad := newExecutionMock(t, "preflight_fail")
	good := newExecutionMock(t, "normal")
	bad.config.Priority = 0
	good.config.Priority = 1
	var requests atomic.Int32
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "HEAD" {
			t.Error("non-HEAD target request")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Set-Cookie", "session=must-not-export")
		w.WriteHeader(200)
	}))
	defer closeTarget()
	scan, p := executionFixture(t, a, s, admin, target, executionConfigFor(bad.config, good.config))
	result, e := a.executeIsolatedScan(context.Background(), scan, p, func() error { return nil })
	if e != nil || str(result, "status") != "completed" || good.created.Load() != 1 || bad.created.Load() != 0 || requests.Load() != 1 {
		t.Fatalf("isolated execution failed status=%s code=%s error=%v", str(result, "status"), str(result, "code"), e)
	}
	raw, _ := json.Marshal(result)
	if bytes.Contains(raw, []byte("must-not-export")) {
		t.Fatal("cookie exported")
	}
	result, e = a.executeIsolatedScan(context.Background(), scan, p, func() error { return nil })
	if e != nil || str(result, "status") != "completed" || good.created.Load() != 1 || requests.Load() != 1 {
		t.Fatal("restart replay repeated target probe")
	}
	var cipher string
	if e = a.DB.QueryRow(context.Background(), `SELECT server_encrypted FROM agent_execution_jobs WHERE scan_id=$1`, scan.ID).Scan(&cipher); e != nil || strings.Contains(cipher, "PRIVATE KEY") {
		t.Fatal("daemon private key plaintext persisted")
	}
}
func TestAgentExecutionUnknownCreateNeverFailsOver(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	lost := newExecutionMock(t, "create_lost")
	other := newExecutionMock(t, "other")
	other.config.Priority = 2
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unknown create must not contact target") }))
	defer closeTarget()
	scan, p := executionFixture(t, a, s, admin, target, executionConfigFor(lost.config, other.config))
	result, e := a.executeIsolatedScan(context.Background(), scan, p, func() error { return nil })
	if e != nil || !asBool(result["degraded"]) || lost.created.Load() != 1 || lost.started.Load() != 0 || other.created.Load() != 0 {
		t.Fatal("unknown create duplicated on fallback")
	}
	_, _ = a.executeIsolatedScan(context.Background(), scan, p, func() error { return nil })
	if lost.created.Load() != 1 || other.created.Load() != 0 {
		t.Fatal("unknown result repeated create")
	}
}

func TestAgentExecutionCompletedCleanupSurvivesTemporaryFailure(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	remote := newExecutionMock(t, "cleanup")
	remote.deleteFailures.Store(1)
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer closeTarget()
	scan, p := executionFixture(t, a, s, admin, target, executionConfigFor(remote.config))
	result, e := a.executeIsolatedScan(context.Background(), scan, p, func() error { return nil })
	if e != nil || str(result, "status") != "completed" {
		t.Fatal("completed observation was lost on cleanup failure")
	}
	var pending bool
	if e = a.DB.QueryRow(context.Background(), `SELECT cleanup_at IS NULL FROM agent_execution_jobs WHERE scan_id=$1`, scan.ID).Scan(&pending); e != nil || !pending {
		t.Fatal("failed cleanup did not remain pending")
	}
	if e = a.executionMaintenance(context.Background()); e != nil {
		t.Fatal(e)
	}
	var state string
	if e = a.DB.QueryRow(context.Background(), `SELECT status,cleanup_at IS NULL FROM agent_execution_jobs WHERE scan_id=$1`, scan.ID).Scan(&state, &pending); e != nil || state != "completed" || pending {
		t.Fatal("cleanup did not preserve completed observation and mark removal")
	}
	remote.mu.Lock()
	removed := remote.state == "removed"
	remote.mu.Unlock()
	if !removed || remote.created.Load() != 1 {
		t.Fatal("cleanup retried execution instead of removing same container")
	}
}

func TestAgentExecutionKoreanServiceNetworkIsSeparateFromDockerNetwork(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	remote := newExecutionMock(t, "korean-network")
	remote.config.Network = "hunter-sandbox"
	remote.config.ServiceNetwork = "업무망"
	cfg := executionConfigFor(remote.config)
	if e := validateAgentExecution(&cfg, defaultAgentExecution()); e != nil {
		t.Fatal(e)
	}
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer closeTarget()
	scan, p := executionFixture(t, a, s, admin, target, cfg)
	visible := mustRequest(t, s, "GET", "/api/execution-profiles?service_id="+str(scan.Data, "service_id"), nil, admin, 200)
	items := visible["items"].([]any)
	if len(items) != 1 || str(object(items[0]), "network") != "업무망" {
		t.Fatal("Korean service network did not expose its profile")
	}
	other := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "다른 망", "url": target, "network": "개발망", "environment": "staging", "approved": true}, admin, 200)
	hidden := mustRequest(t, s, "GET", "/api/execution-profiles?service_id="+str(other, "id"), nil, admin, 200)
	if len(hidden["items"].([]any)) != 0 {
		t.Fatal("profile crossed service network boundary")
	}
	service, _, _, e := a.scanPolicy(context.Background(), scan.Data)
	if e != nil {
		t.Fatal(e)
	}
	service.Data["network"] = "개발망"
	u := User{Role: "admin", Scopes: a.roleScopes(context.Background(), "admin")}
	if _, e = a.prepareIsolatedScan(context.Background(), u, scan.Data, service, p); e == nil {
		t.Fatal("mismatched service network was approved")
	}
	result, e := a.executeIsolatedScan(context.Background(), scan, p, func() error { return nil })
	if e != nil || str(result, "status") != "completed" || remote.created.Load() != 1 {
		t.Fatal("Korean service mapped to ASCII Docker network did not execute")
	}
	var stored agentExecutionConfig
	if _, e = a.loadPlatformConfig(context.Background(), "execution", &stored); e != nil || stored.Servers[0].ServiceNetwork != "업무망" {
		t.Fatal("service network was not persisted")
	}
}
func TestAgentExecutionProbeBoundsAndTLS(t *testing.T) {
	if e := RunExecutionProbe(context.Background(), strings.Repeat("A", executionMaxEncodedProbe+1), io.Discard); e == nil {
		t.Fatal("oversized argv accepted")
	}
	if _, e := encodeExecutionProbe(executionProbeInput{CAPEM: strings.Repeat("A", 65537)}); e == nil {
		t.Fatal("oversized target CA accepted")
	}
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://127.0.0.1/blocked")
		w.WriteHeader(302)
	}))
	defer closeTarget()
	u, _ := url.Parse(target)
	in := executionProbeInput{Kind: "http_headers", Target: target, IP: u.Hostname(), TimeoutSeconds: 2, Deadline: time.Now().Add(2 * time.Second)}
	result := runExecutionProbe(context.Background(), in)
	if str(result, "status") != "completed" || asInt(result["http_status"]) != 302 {
		t.Fatal("HEAD redirect handling failed")
	}
	in.Kind = "tcp_connect"
	if !asBool(runExecutionProbe(context.Background(), in)["connected"]) {
		t.Fatal("fixed TCP connect failed")
	}
	in.IP = "127.0.0.1"
	if str(runExecutionProbe(context.Background(), in), "code") != "invalid_probe_input" {
		t.Fatal("loopback probe allowed")
	}
	in.IP = u.Hostname()
	in.Kind = "shell"
	if str(runExecutionProbe(context.Background(), in), "code") != "invalid_probe_input" {
		t.Fatal("arbitrary profile accepted")
	}
	in.Kind = "tls_certificate"
	if str(runExecutionProbe(context.Background(), in), "code") != "https_required" {
		t.Fatal("TLS profile accepted HTTP")
	}
	m := newExecutionMock(t, "tls-probe")
	pair, e := tls.X509KeyPair([]byte(m.config.CertPEM), []byte(m.config.KeyPEM))
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("TLS certificate profile sent HTTP") }))
	server.Listener.Close()
	server.Listener = ln
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	in.Target = "https://probe.internal:" + port
	in.CAPEM = m.config.CAPEM
	in.Deadline = time.Now().Add(2 * time.Second)
	result = runExecutionProbe(context.Background(), in)
	if str(result, "status") != "completed" || !asBool(object(result["certificate"])["verified"]) {
		t.Fatalf("actual TLS verification failed: %v", result["code"])
	}
}

func TestAgentExecutionCancellationStopsRemoteAndKeepsApproval(t *testing.T) {
	a, s, admin := knowledgeTestServer(t)
	good := newExecutionMock(t, "cancel")
	target, closeTarget := domainTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer closeTarget()
	scan, _ := executionFixture(t, a, s, admin, target, executionConfigFor(good.config))
	done := make(chan struct{})
	go func() { a.executeScan(context.Background(), "execution-worker", scan.ID); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for good.started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if good.started.Load() == 0 {
		t.Fatal("remote probe not started")
	}
	mustRequest(t, s, "POST", "/api/scans/"+scan.ID+"/cancel", nil, admin, 200)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not stop remote observer")
	}
	if good.killed.Load() == 0 {
		t.Fatal("cancel did not reach actual remote container")
	}
	current := mustRequest(t, s, "GET", "/api/scans/"+scan.ID, nil, admin, 200)
	if str(current, "status") != "cancelled" {
		t.Fatal("cancelled scan overwritten")
	}
	mustRequest(t, s, "PUT", "/api/settings/workflow", map[string]any{"approval_enabled": true}, admin, 200)
	pending := mustRequest(t, s, "POST", "/api/scans", map[string]any{"service_id": scan.Data["service_id"], "scope_id": scan.Data["scope_id"], "profile": "isolated", "execution_profile_id": "headers"}, admin, 201)
	if str(pending, "status") != "pending_approval" {
		t.Fatal("optional approval bypassed")
	}
	if id, e := a.claimScan(context.Background(), "execution-worker"); e != nil || id != "" {
		t.Fatal("unapproved isolated scan claimed")
	}
}
