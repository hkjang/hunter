package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

type executionProbeInput struct {
	Kind           string    `json:"kind"`
	Target         string    `json:"target"`
	IP             string    `json:"ip"`
	TimeoutSeconds int       `json:"timeout_seconds"`
	CAPEM          string    `json:"ca_pem,omitempty"`
	Deadline       time.Time `json:"deadline"`
}

// Keep a single argv element comfortably below Linux MAX_ARG_STRLEN (128 KiB).
const executionMaxEncodedProbe = 96 * 1024

func encodeExecutionProbe(in executionProbeInput) (string, error) {
	if len(in.CAPEM) > 65536 || len(in.Target) > 8192 {
		return "", errors.New("probe input too large")
	}
	raw, e := json.Marshal(in)
	if e != nil {
		return "", e
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	if len(encoded) > executionMaxEncodedProbe {
		return "", errors.New("probe input too large")
	}
	return encoded, nil
}

// RunExecutionProbe is the only process entrypoint used in isolated containers.
// It never loads application credentials, spawns a shell, resolves DNS, follows
// redirects, or reads an HTTP response body. Its single socket is pinned by IP.
func RunExecutionProbe(parent context.Context, encoded string, out io.Writer) error {
	if len(encoded) > executionMaxEncodedProbe {
		return errors.New("probe input too large")
	}
	raw, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil {
		return errors.New("invalid probe input")
	}
	var in executionProbeInput
	if json.Unmarshal(raw, &in) != nil {
		return errors.New("invalid probe input")
	}
	result := runExecutionProbe(parent, in)
	return json.NewEncoder(out).Encode(result)
}
func runExecutionProbe(parent context.Context, in executionProbeInput) map[string]any {
	result := map[string]any{"status": "inconclusive", "kind": in.Kind, "request_count": 0}
	u, e := url.Parse(in.Target)
	ip, ipErr := netip.ParseAddr(in.IP)
	if e != nil || ipErr != nil || validateProbeIP(ip, nil) != nil || len(in.CAPEM) > 65536 || len(in.Target) > 8192 || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || !hasString([]string{"http_headers", "tls_certificate", "tcp_connect"}, in.Kind) || in.TimeoutSeconds < 1 || in.TimeoutSeconds > 120 || !in.Deadline.After(time.Now()) || time.Until(in.Deadline) > 121*time.Second {
		result["code"] = "invalid_probe_input"
		return result
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	number, e := strconv.Atoi(port)
	if e != nil || number < 1 || number > 65535 {
		result["code"] = "invalid_port"
		return result
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()
	ctx, deadlineCancel := context.WithDeadline(ctx, in.Deadline)
	defer deadlineCancel()
	address := net.JoinHostPort(ip.String(), port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if in.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(in.CAPEM)) {
		result["code"] = "invalid_target_ca"
		return result
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: roots}
	result["request_count"] = 1
	switch in.Kind {
	case "tcp_connect":
		conn, e := dialer.DialContext(ctx, "tcp", address)
		if e != nil {
			result["code"] = "connection_failed"
			return result
		}
		_ = conn.Close()
		result["connected"] = true
	case "tls_certificate":
		if u.Scheme != "https" {
			result["code"] = "https_required"
			return result
		}
		conn, e := (&tls.Dialer{NetDialer: dialer, Config: tlsCfg}).DialContext(ctx, "tcp", address)
		if e != nil {
			result["code"] = "tls_verification_failed"
			return result
		}
		defer conn.Close()
		state := conn.(*tls.Conn).ConnectionState()
		if len(state.PeerCertificates) == 0 {
			result["code"] = "certificate_missing"
			return result
		}
		cert := state.PeerCertificates[0]
		fingerprint := sha256.Sum256(cert.Raw)
		result["certificate"] = map[string]any{"subject": knowledgeText(cert.Subject.String(), 1000), "issuer": knowledgeText(cert.Issuer.String(), 1000), "not_before": cert.NotBefore, "not_after": cert.NotAfter, "sha256": hex.EncodeToString(fingerprint[:]), "tls_version": state.Version, "verified": true}
	case "http_headers":
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: tlsCfg, MaxResponseHeaderBytes: 32768, DialContext: func(c context.Context, _, _ string) (net.Conn, error) { return dialer.DialContext(c, "tcp", address) }}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if e != nil {
			result["code"] = "invalid_target"
			return result
		}
		res, e := client.Do(req)
		if e != nil {
			result["code"] = "http_connection_failed"
			return result
		}
		defer res.Body.Close()
		result["http_status"] = res.StatusCode
		headers := map[string]string{}
		for _, name := range []string{"Content-Type", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
			if value := res.Header.Get(name); value != "" {
				headers[name] = knowledgeText(value, 1500)
			}
		}
		result["headers"] = headers
		if res.StatusCode == 429 || res.StatusCode >= 500 {
			result["code"] = "target_safety_stop"
			return result
		}
	}
	result["status"] = "completed"
	result["code"] = "ok"
	return result
}
