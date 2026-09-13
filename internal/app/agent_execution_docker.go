package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func executionDockerRequest(ctx context.Context, s agentExecutionServer, method, path string, body any) ([]byte, int, string) {
	tlsConfig, e := executionTLS(s)
	if e != nil {
		return nil, 0, "invalid_mtls"
	}
	var data []byte
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return nil, 0, "invalid_payload"
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.Endpoint, "/")+path, bytes.NewReader(data))
	if e != nil {
		return nil, 0, "invalid_endpoint"
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: time.Duration(s.TimeoutSeconds) * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, MaxResponseHeaderBytes: 16384}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	res, e := client.Do(req)
	if e != nil {
		return nil, 0, "connection_failed"
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 262145))
	if e != nil || len(raw) > 262144 {
		return nil, res.StatusCode, "invalid_response"
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, res.StatusCode, fmt.Sprintf("http_%d", res.StatusCode)
	}
	return raw, res.StatusCode, "ok"
}
func (a *App) executionPreflight(ctx context.Context, s agentExecutionServer, image string, rev time.Time) (string, []map[string]any, string) {
	start := time.Now()
	checks := []map[string]any{}
	if image != "" && !executionImage.MatchString(image) {
		return "", checks, "invalid_image"
	}
	ok, e := a.platformPermit(ctx, "execution", s.ID, rev, s.platformResilience, time.Duration(s.TimeoutSeconds)*time.Second)
	if e != nil || !ok {
		return "", checks, "cooldown"
	}
	code := "ok"
	defer func() { a.knowledgeOutcome(ctx, "execution", s.ID, rev, code == "ok", code, start) }()
	raw, _, status := executionDockerRequest(ctx, s, "GET", "/version", nil)
	code = status
	checks = append(checks, map[string]any{"name": "mtls", "ok": code == "ok", "code": code})
	if code != "ok" {
		return "", checks, code
	}
	var version struct {
		APIVersion string `json:"ApiVersion"`
		OS         string `json:"Os"`
	}
	if json.Unmarshal(raw, &version) != nil || version.APIVersion == "" || version.OS != "linux" {
		code = "unsupported_daemon"
		return "", checks, code
	}
	raw, _, code = executionDockerRequest(ctx, s, "GET", "/v1.43/networks/"+url.PathEscape(s.Network), nil)
	if code != "ok" {
		return "", checks, code
	}
	var network struct {
		Name   string
		Driver string
	}
	if json.Unmarshal(raw, &network) != nil || network.Name != s.Network || !hasString([]string{"bridge", "overlay"}, network.Driver) {
		code = "unsafe_network"
		return "", checks, code
	}
	checks = append(checks, map[string]any{"name": "network", "ok": true, "code": "ok"})
	if image == "" {
		return "", checks, "ok"
	}
	raw, httpStatus, code := executionDockerRequest(ctx, s, "GET", "/v1.43/images/"+url.PathEscape(image)+"/json", nil)
	digestPart := "sha256:" + strings.Split(image, "@sha256:")[1]
	if httpStatus == 404 {
		raw, _, code = executionDockerRequest(ctx, s, "GET", "/v1.43/images/"+url.PathEscape(digestPart)+"/json", nil)
	}
	if code != "ok" {
		return "", checks, code
	}
	var meta struct {
		ID          string `json:"Id"`
		RepoDigests []string
		Config      struct {
			Volumes map[string]any
			Env     []string
			Labels  map[string]string
		}
	}
	if json.Unmarshal(raw, &meta) != nil || (!hasString(meta.RepoDigests, image) && meta.ID != digestPart) || !strings.HasPrefix(meta.ID, "sha256:") {
		code = "image_digest_mismatch"
		return "", checks, code
	}
	if len(meta.Config.Volumes) > 0 {
		code = "image_volumes_forbidden"
		return "", checks, code
	}
	for _, env := range meta.Config.Env {
		if !strings.HasPrefix(env, "PATH=") && !strings.HasPrefix(env, "LANG=") && !strings.HasPrefix(env, "LC_ALL=") && !strings.HasPrefix(env, "TZ=") {
			code = "image_environment_forbidden"
			return "", checks, code
		}
	}
	if meta.Config.Labels["org.opencontainers.image.title"] != "hunter" {
		code = "hunter_probe_image_required"
		return "", checks, code
	}
	checks = append(checks, map[string]any{"name": "local_approved_image", "ok": true, "code": "ok"})
	return meta.ID, checks, "ok"
}

type executionContainer struct {
	ID     string `json:"Id"`
	Image  string
	Config struct{ Labels map[string]string }
	State  struct {
		Status   string
		Running  bool
		ExitCode int
	}
}

func executionInspect(ctx context.Context, s agentExecutionServer, name, scanID, image string) (executionContainer, string) {
	var v executionContainer
	raw, _, code := executionDockerRequest(ctx, s, "GET", "/v1.43/containers/"+url.PathEscape(name)+"/json", nil)
	if code != "ok" {
		return v, code
	}
	if json.Unmarshal(raw, &v) != nil || v.ID == "" || v.Image != image || v.Config.Labels["hunter.scan_id"] != scanID || v.Config.Labels["hunter.execution"] != "fixed-probe-v1" {
		return v, "container_identity_mismatch"
	}
	return v, "ok"
}
func executionLogs(ctx context.Context, s agentExecutionServer, name string) (map[string]any, string) {
	raw, _, code := executionDockerRequest(ctx, s, "GET", "/v1.43/containers/"+url.PathEscape(name)+"/logs?stdout=1&stderr=0&tail=20", nil)
	if code != "ok" {
		return nil, code
	}
	output := []byte{}
	for len(raw) > 0 {
		if len(raw) < 8 || raw[0] != 1 {
			return nil, "invalid_probe_logs"
		}
		n := int(binary.BigEndian.Uint32(raw[4:8]))
		raw = raw[8:]
		if n > len(raw) || len(output)+n > 32768 {
			return nil, "invalid_probe_logs"
		}
		output = append(output, raw[:n]...)
		raw = raw[n:]
	}
	var result map[string]any
	if json.Unmarshal(output, &result) != nil || !hasString([]string{"completed", "inconclusive"}, str(result, "status")) {
		return nil, "invalid_probe_result"
	}
	safe := map[string]any{}
	for _, key := range []string{"status", "kind", "code", "request_count", "http_status", "headers", "certificate", "connected"} {
		if value, ok := result[key]; ok {
			safe[key] = redactAgentValue(value)
		}
	}
	return safe, "ok"
}
