package app

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNotificationTransportValidation(t *testing.T) {
	a := &App{}
	smtpChannel := func() NotificationChannel {
		return NotificationChannel{Type: "smtp", Config: map[string]any{"host": "relay.corp.local", "port": 587, "security": "starttls", "from": "Hunter <hunter@corp.local>"}}
	}
	for _, mutate := range []func(*NotificationChannel){
		func(c *NotificationChannel) { c.Config["port"] = 25.5 },
		func(c *NotificationChannel) { c.Config["port"] = 65536 },
		func(c *NotificationChannel) { c.Config["host"] = "smtp://corp.local" },
		func(c *NotificationChannel) { c.Config["security"] = "automatic" },
		func(c *NotificationChannel) { c.Config["from"] = "hunter@corp.local\r\nBcc: victim@corp.local" },
		func(c *NotificationChannel) { c.Config["security"] = "none"; c.Secret = "password" },
		func(c *NotificationChannel) { c.Config["timeout_seconds"] = 31 },
		func(c *NotificationChannel) { c.Config["skip_tls_verify"] = true },
	} {
		c := smtpChannel()
		mutate(&c)
		if a.validateNotificationTransport(c) == nil {
			t.Error("invalid SMTP configuration accepted")
		}
	}
	if err := a.validateNotificationTransport(smtpChannel()); err != nil {
		t.Fatal(err)
	}
	apiChannel := func() NotificationChannel {
		return NotificationChannel{Type: "webhook", Config: map[string]any{"endpoint": "http://gateway.corp.local/send"}}
	}
	for _, mutate := range []func(*NotificationChannel){
		func(c *NotificationChannel) { c.Config["method"] = "GET" },
		func(c *NotificationChannel) { c.Config["endpoint"] = "https://user:pass@gateway.corp.local" },
		func(c *NotificationChannel) { c.Config["endpoint"] = "http://{{event.type}}.corp.local" },
		func(c *NotificationChannel) {
			c.Config["body_template"] = map[string]any{"text": "{{finding.evidence}}"}
		},
		func(c *NotificationChannel) { c.Config["headers"] = map[string]string{"Authorization": "secret"} },
		func(c *NotificationChannel) { c.Config["auth"] = "headers"; c.Secret = `{"Host":"evil"}` },
		func(c *NotificationChannel) { c.Config["auth"] = "headers"; c.Secret = `{"X-Key":"a","x-key":"b"}` },
		func(c *NotificationChannel) { c.Config["auth"] = "header"; c.Config["auth_header"] = "X-Key\r\n" },
		func(c *NotificationChannel) { c.Config["idempotency_supported"] = true },
		func(c *NotificationChannel) { c.Config["success_path"] = "result[0].ok" },
		func(c *NotificationChannel) {
			c.Config["format"] = "form"
			c.Config["body_template"] = map[string]any{"nested": map[string]any{"a": "b"}}
		},
	} {
		c := apiChannel()
		mutate(&c)
		if a.validateNotificationTransport(c) == nil {
			t.Error("invalid HTTP configuration accepted")
		}
	}
	for kind, raw := range map[string]string{"smtp": "a@corp.local,b@corp.local", "sms": "123", "kakao": "010-hello-9999", "webhook": "a\nsecret"} {
		if _, err := validateNotificationRecipient(kind, raw); err == nil {
			t.Errorf("invalid %s recipient accepted", kind)
		}
	}
	if got, err := validateNotificationRecipient("sms", " +82 (10) 0000-0000 "); err != nil || got != "+821000000000" {
		t.Fatal("phone normalization failed")
	}
}

func TestNotificationPayloadEscaping(t *testing.T) {
	message := notificationTransportSample()
	message.Subject = "한글 \"제목\""
	message.Body = "문자열 {{unknown.secret}}\n& = +"
	message.Variables["finding.title"] = "안전한 제목"
	input := map[string]any{"messages": []any{map[string]any{"title": "{{finding.title}}", "text": "{{message.subject}}\n{{message.body}}"}}, "boolean": true}
	value, err := renderNotificationPayload(input, message)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil || !json.Valid(raw) {
		t.Fatal("JSON escaping failed")
	}
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	text := decoded["messages"].([]any)[0].(map[string]any)["text"]
	if text != message.Subject+"\n"+message.Body {
		t.Fatal("message content was rewritten or recursively evaluated")
	}
	for _, bad := range []any{"{{unknown.secret}}", "{{message.body", map[string]any{"{{message.id}}": "value"}} {
		if _, err := renderNotificationPayload(bad, message); err == nil {
			t.Fatal("invalid template accepted")
		}
	}
}

func TestNotificationHTTPTransport(t *testing.T) {
	a, _ := testApp(t)
	message := notificationTransportSample()
	message.DeliveryID = newID()
	message.Recipient = "01000000000"
	message.Subject = "한글 알림"
	message.Body = "테스트 \"본문\" & +\n둘째 줄"
	var inspect func(*http.Request)
	var behavior string
	var mockMu sync.RWMutex
	setInspect := func(fn func(*http.Request)) { mockMu.Lock(); inspect = fn; mockMu.Unlock() }
	setBehavior := func(value string) { mockMu.Lock(); behavior = value; mockMu.Unlock() }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockMu.RLock()
		inspectNow, behaviorNow := inspect, behavior
		mockMu.RUnlock()
		if inspectNow != nil {
			inspectNow(r)
		}
		switch behaviorNow {
		case "429":
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
		case "500":
			w.WriteHeader(500)
			_, _ = io.WriteString(w, "secret response must never appear")
		case "401":
			w.WriteHeader(401)
		case "redirect":
			w.Header().Set("Location", "/must-not-follow")
			w.WriteHeader(302)
		case "disconnect":
			h, ok := w.(http.Hijacker)
			if !ok {
				t.Error("hijack unavailable")
				return
			}
			conn, _, _ := h.Hijack()
			_ = conn.Close()
		case "invalid":
			_, _ = io.WriteString(w, "<html>private gateway error</html>")
		case "missing":
			_, _ = io.WriteString(w, `{"unrelated":true}`)
		case "secret-id":
			_, _ = io.WriteString(w, `{"header":{"ok":true},"messages":[{"id":"test-secret"}]}`)
		case "rejected":
			_, _ = io.WriteString(w, `{"header":{"ok":false}}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"header":{"ok":true},"messages":[{"id":"receipt-001"}]}`)
		}
	}))
	defer server.Close()
	base := func() NotificationChannel {
		return NotificationChannel{Type: "sms", Config: map[string]any{"endpoint": server.URL + "/send?tenant=example", "success_path": "header.ok", "success_value": "true", "id_path": "messages.0.id", "timeout_seconds": 3}}
	}
	for _, auth := range []string{"none", "bearer", "basic", "header", "headers", "ncp"} {
		t.Run(auth, func(t *testing.T) {
			c := base()
			c.Config["auth"] = auth
			c.Config["username"] = "access-example"
			c.Config["auth_header"] = "X-Corp-Key"
			c.Secret = "test-secret"
			if auth == "none" {
				c.Secret = ""
			}
			if auth == "headers" {
				c.Secret = `{"X-Corp-Key":"test-secret","X-Client-Secret":"second-secret"}`
			}
			setInspect(func(r *http.Request) {
				if r.URL.Path != "/send" {
					t.Error("redirect followed")
				}
				switch auth {
				case "bearer":
					if r.Header.Get("Authorization") != "Bearer test-secret" {
						t.Error("bearer missing")
					}
				case "basic":
					u, p, ok := r.BasicAuth()
					if !ok || u != "access-example" || p != "test-secret" {
						t.Error("basic auth missing")
					}
				case "header", "headers":
					if r.Header.Get("X-Corp-Key") != "test-secret" {
						t.Error("custom auth missing")
					}
				case "ncp":
					mac := hmac.New(sha256.New, []byte("test-secret"))
					_, _ = io.WriteString(mac, r.Method+" "+r.URL.RequestURI()+"\n"+r.Header.Get("x-ncp-apigw-timestamp")+"\naccess-example")
					if r.Header.Get("x-ncp-apigw-signature-v2") != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
						t.Error("NCP signature mismatch")
					}
				}
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil || body["message"] != message.Body || body["to"] != message.Recipient {
					t.Error("JSON message changed")
				}
			})
			result := a.sendNotification(context.Background(), c, message)
			if result.State != "sent" || result.ProviderID != "receipt-001" {
				t.Fatalf("send: %+v", result)
			}
		})
	}
	setInspect(nil)
	for _, test := range []struct {
		behavior   string
		idempotent bool
		state      string
	}{{"429", false, "retryable"}, {"500", false, "uncertain"}, {"500", true, "retryable"}, {"401", false, "failed"}, {"redirect", false, "failed"}, {"disconnect", false, "uncertain"}, {"disconnect", true, "retryable"}, {"invalid", false, "uncertain"}, {"missing", false, "uncertain"}, {"rejected", false, "failed"}} {
		setBehavior(test.behavior)
		c := base()
		c.Config["idempotency_header"] = "Idempotency-Key"
		c.Config["idempotency_supported"] = test.idempotent
		result := a.sendNotification(context.Background(), c, message)
		if result.State != test.state {
			t.Errorf("%s/idempotent=%t: %+v", test.behavior, test.idempotent, result)
		}
		if strings.Contains(result.Detail, "secret") || strings.Contains(result.Detail, "private") {
			t.Error("provider body leaked")
		}
		if test.behavior == "429" && result.RetryAfter != 120*time.Second {
			t.Error("Retry-After ignored")
		}
	}
	setBehavior("secret-id")
	secretChannel := base()
	secretChannel.Config["auth"] = "bearer"
	secretChannel.Secret = "test-secret"
	if result := a.sendNotification(context.Background(), secretChannel, message); result.State != "sent" || result.ProviderID != "" {
		t.Fatal("provider echo of credentials escaped receipt redaction")
	}
	setBehavior("")
	c := base()
	c.Config["format"] = "form"
	c.Config["body_template"] = map[string]any{"to": "{{message.recipient}}", "text": "{{message.body}}"}
	c.Config["idempotency_header"] = "X-Request-ID"
	c.Config["idempotency_supported"] = true
	setInspect(func(r *http.Request) {
		if r.ParseForm() != nil || r.Form.Get("text") != message.Body || r.Header.Get("X-Request-ID") != "hunter-"+message.DeliveryID {
			t.Error("form encoding or immutable idempotency key mismatch")
		}
	})
	for range 2 {
		if result := a.sendNotification(context.Background(), c, message); result.State != "sent" {
			t.Fatal(result)
		}
	}
}

type notificationSMTPMock struct {
	address  string
	certPEM  string
	messages chan string
	accepted chan string
	listener net.Listener
	wg       sync.WaitGroup
}

func newNotificationSMTPMock(t *testing.T, security, behavior string) *notificationSMTPMock {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Hunter test relay"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if security == "tls" {
		listener = tls.NewListener(listener, tlsConfig)
	}
	s := &notificationSMTPMock{address: listener.Addr().String(), certPEM: string(certPEM), messages: make(chan string, 8), accepted: make(chan string, 8), listener: listener}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func(conn net.Conn) {
				defer s.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				write := func(value string) { _, _ = io.WriteString(conn, value) }
				write("220 hunter test relay\r\n")
				authStep := 0
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if authStep > 0 {
						decoded, _ := base64.StdEncoding.DecodeString(line)
						if authStep == 1 {
							if string(decoded) != "test-user" {
								write("535 authentication failed\r\n")
								continue
							}
							authStep = 2
							write("334 UGFzc3dvcmQ6\r\n")
						} else {
							if string(decoded) != "test-password" {
								write("535 authentication failed\r\n")
							} else {
								write("235 authenticated\r\n")
							}
							authStep = 0
						}
						continue
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if security == "starttls" {
							write("250-hunter\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")
						} else {
							write("250-hunter\r\n250 AUTH PLAIN LOGIN\r\n")
						}
					case line == "STARTTLS":
						write("220 ready\r\n")
						secured := tls.Server(conn, tlsConfig)
						if secured.Handshake() != nil {
							return
						}
						conn = secured
						reader = bufio.NewReader(conn)
					case strings.HasPrefix(line, "AUTH PLAIN "):
						decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
						if string(decoded) != "\x00test-user\x00test-password" {
							write("535 denied\r\n")
						} else {
							write("235 authenticated\r\n")
						}
					case line == "AUTH LOGIN":
						authStep = 1
						write("334 VXNlcm5hbWU6\r\n")
					case strings.HasPrefix(line, "MAIL FROM:"):
						write("250 sender accepted\r\n")
					case strings.HasPrefix(line, "RCPT TO:"):
						if behavior == "rcpt451" {
							write("451 retry later\r\n")
						} else if behavior == "rcpt550" {
							write("550 refused\r\n")
						} else {
							write("250 recipient accepted\r\n")
						}
					case line == "DATA":
						write("354 send message\r\n")
						raw, err := io.ReadAll(textproto.NewReader(reader).DotReader())
						if err != nil {
							return
						}
						s.messages <- string(raw)
						if behavior == "drop-data" {
							return
						}
						write("250 queued\r\n")
						s.accepted <- "250"
					case line == "QUIT":
						if behavior == "drop-quit" {
							return
						}
						write("221 goodbye\r\n")
						return
					default:
						write("500 unknown\r\n")
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); s.wg.Wait() })
	return s
}

func TestNotificationSMTPTransport(t *testing.T) {
	a, _ := testApp(t)
	for _, test := range []struct {
		security, auth, behavior, want string
		trust                          bool
	}{
		{"none", "", "", "sent", false}, {"none", "", "drop-quit", "sent", false}, {"none", "", "rcpt451", "retryable", false}, {"none", "", "rcpt550", "failed", false}, {"none", "", "drop-data", "uncertain", false}, {"tls", "plain", "", "sent", true}, {"starttls", "login", "", "sent", true}, {"tls", "plain", "", "failed", false},
	} {
		t.Run(test.security+test.auth+test.behavior+strconv.FormatBool(test.trust), func(t *testing.T) {
			server := newNotificationSMTPMock(t, test.security, test.behavior)
			host, portString, _ := net.SplitHostPort(server.address)
			port, _ := strconv.Atoi(portString)
			ca := ""
			if test.trust {
				ca = server.certPEM
			}
			securityJSON, _ := json.Marshal(map[string]any{"trusted_ca_pem": ca})
			if _, err := a.DB.Exec(context.Background(), `INSERT INTO settings(key,value) VALUES('security',$1) ON CONFLICT(key) DO UPDATE SET value=$1`, securityJSON); err != nil {
				t.Fatal(err)
			}
			c := NotificationChannel{Type: "smtp", Config: map[string]any{"host": host, "port": port, "from": "헌터 <hunter@corp.local>", "security": test.security, "timeout_seconds": 3}}
			if test.auth != "" {
				c.Config["auth"] = test.auth
				c.Config["username"] = "test-user"
				c.Secret = "test-password"
			}
			message := notificationTransportSample()
			message.Recipient = "receiver@corp.local"
			message.Subject = "헌터 보안 알림"
			message.Body = "한글 본문\n.두 번째 줄\n{{literal.body}}"
			result := a.sendNotification(context.Background(), c, message)
			if result.State != test.want {
				t.Fatalf("SMTP: %+v", result)
			}
			if test.want == "sent" {
				select {
				case raw := <-server.messages:
					mailMessage, err := mail.ReadMessage(strings.NewReader(raw))
					if err != nil {
						t.Fatal(err)
					}
					subject, err := new(mime.WordDecoder).DecodeHeader(mailMessage.Header.Get("Subject"))
					if err != nil || subject != message.Subject {
						t.Fatal("Korean subject changed")
					}
					body, err := io.ReadAll(quotedprintable.NewReader(mailMessage.Body))
					if err != nil || strings.ReplaceAll(string(body), "\r\n", "\n") != message.Body+"\n" {
						t.Fatalf("Korean body changed: %q", body)
					}
					if mailMessage.Header.Get("Bcc") != "" || !strings.Contains(mailMessage.Header.Get("Message-ID"), "@hunter.local") {
						t.Fatal("invalid MIME headers")
					}
				case <-time.After(time.Second):
					t.Fatal("mail not received")
				}
			}
		})
	}
	server := newNotificationSMTPMock(t, "none", "")
	host, portString, _ := net.SplitHostPort(server.address)
	port, _ := strconv.Atoi(portString)
	channel := NotificationChannel{Type: "smtp", Config: map[string]any{"host": host, "port": port, "from": "hunter@corp.local", "security": "starttls"}}
	message := notificationTransportSample()
	message.Recipient = "receiver@corp.local"
	if result := a.sendNotification(context.Background(), channel, message); result.State != "failed" || result.Code != "starttls_required" {
		t.Fatal("STARTTLS silently downgraded", result)
	}
}

func TestNotificationRetryAndResponseParsing(t *testing.T) {
	if notificationRetryAfter("99999999") != time.Hour || notificationRetryAfter("invalid") != time.Second {
		t.Fatal("Retry-After bounds failed")
	}
	var value any
	_ = json.Unmarshal([]byte(`{"items":[{"ok":false,"id":123}],"null":null}`), &value)
	if got, ok := notificationResponseValue(value, "items.0.ok"); !ok || got != false {
		t.Fatal("false lost")
	}
	for _, path := range []string{"items.-1.id", "items.4.id", "null", "items", "missing"} {
		if _, ok := notificationResponseValue(value, path); ok {
			t.Errorf("invalid scalar path %s accepted", path)
		}
	}
	// Form templates encode phone numbers as values, never as syntax.
	form := url.Values{"to": {"+821000000000"}, "message": {"a&b=한글"}}
	decoded, err := url.ParseQuery(form.Encode())
	if err != nil || decoded.Get("to") != "+821000000000" {
		t.Fatal("form recipient changed")
	}
}
