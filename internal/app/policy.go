package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

type probePolicy struct {
	Fingerprint                       string
	Target                            *url.URL
	Roots                             *x509.CertPool
	Hosts, Paths, BlockedPaths, CIDRs []string
	MaxRequests, Timeout, MaxRPS      int
	ExpiresAt                         time.Time
	AllowedMethods                    []string
}

func parseTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, errors.New("대상 URL은 사용자 정보가 없는 http(s) 주소여야 합니다")
	}
	if u.Port() != "" {
		if _, err := net.LookupPort("tcp", u.Port()); err != nil {
			return nil, errors.New("유효한 포트가 필요합니다")
		}
	}
	return u, nil
}

func validateScope(m map[string]any) error {
	if str(m, "service_id") == "" {
		return errors.New("범위의 대상 서비스를 선택하세요")
	}
	hosts := stringList(m["allowed_hosts"])
	if len(hosts) == 0 {
		return errors.New("허용 호스트를 하나 이상 입력하세요")
	}
	for _, host := range hosts {
		if host == "" || strings.ContainsAny(host, "/*?#@ \\ ") || strings.Contains(host, "://") {
			return errors.New("허용 호스트는 와일드카드 없이 host 또는 host:port 형식으로 입력하세요")
		}
	}
	paths := stringList(m["allowed_paths"])
	if len(paths) == 0 {
		return errors.New("허용 경로를 하나 이상 입력하세요 (예: /)")
	}
	for _, p := range paths {
		if !validScopePath(p) {
			return errors.New("허용 경로에는 절대 경로만 지정할 수 있습니다")
		}
	}
	expires, err := time.Parse(time.RFC3339, str(m, "expires_at"))
	if err != nil || !expires.After(time.Now()) {
		return errors.New("미래의 범위 만료 일시(RFC3339)를 입력하세요")
	}
	for _, cidr := range stringList(m["allowed_cidrs"]) {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return errors.New("IP 허용 범위는 CIDR 형식이어야 합니다")
		}
	}
	for _, b := range []struct {
		k        string
		def, max int
	}{{"max_rps", 1, 5}, {"max_requests", 10, 100}, {"timeout_seconds", 30, 300}} {
		n := number(m, b.k, b.def)
		if n < 1 || n > b.max {
			return fmt.Errorf("%s 값은 1~%d 범위입니다", b.k, b.max)
		}
		m[b.k] = n
	}
	return nil
}

func validatePolicy(m map[string]any) error {
	if boolean(m, "production_active_scan") {
		return errors.New("운영계 능동 공격은 이 버전에서 제공하지 않습니다")
	}
	for _, b := range []struct {
		k        string
		def, max int
	}{{"max_rps", 1, 5}, {"max_concurrency", 1, 1}, {"max_requests", 10, 100}, {"timeout_seconds", 30, 300}} {
		n := number(m, b.k, b.def)
		if n < 1 || n > b.max {
			return fmt.Errorf("%s 값은 1~%d 범위입니다", b.k, b.max)
		}
		m[b.k] = n
	}
	methods := stringList(m["allowed_methods"])
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD"}
		m["allowed_methods"] = methods
	}
	for _, method := range methods {
		if method != "GET" && method != "HEAD" {
			return errors.New("진단은 GET, HEAD 메서드만 지원합니다")
		}
	}
	for _, p := range stringList(m["blocked_paths"]) {
		if !validScopePath(p) {
			return errors.New("차단 경로는 절대 경로여야 합니다")
		}
	}
	if _, ok := m["enabled"]; !ok {
		m["enabled"] = true
	}
	return nil
}

func validScopePath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "?#\\") && !strings.Contains(strings.ToLower(p), "%2f") && !strings.Contains(strings.ToLower(p), "%5c")
}
func pathContains(prefix, value string) bool {
	prefix = path.Clean(prefix)
	value = path.Clean(value)
	return prefix == "/" || value == prefix || strings.HasPrefix(value, prefix+"/")
}

func (p probePolicy) validateURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" || u.User != nil {
		return errors.New("허용되지 않은 URL 형식입니다")
	}
	if u.Scheme != p.Target.Scheme {
		return errors.New("리다이렉트의 프로토콜 변경은 허용하지 않습니다")
	}
	if time.Now().After(p.ExpiresAt) {
		return errors.New("승인 범위가 만료되었습니다")
	}
	allowed := false
	for _, host := range p.Hosts {
		if strings.EqualFold(host, u.Host) || strings.EqualFold(host, u.Hostname()) && u.Port() == "" {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("승인 범위 밖 호스트입니다")
	}
	decoded, err := url.PathUnescape(u.EscapedPath())
	if err != nil || strings.Contains(decoded, "\\") {
		return errors.New("유효하지 않은 대상 경로입니다")
	}
	// Repeated decoding prevents encoded traversal from bypassing an allowlist.
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			break
		}
		if next == decoded {
			break
		}
		decoded = next
	}
	if strings.ContainsAny(decoded, "\\\x00") {
		return errors.New("유효하지 않은 경로입니다")
	}
	for _, part := range strings.Split(decoded, "/") {
		if part == ".." {
			return errors.New("상위 경로 이동은 허용하지 않습니다")
		}
	}
	allowed = false
	for _, prefix := range p.Paths {
		if pathContains(prefix, decoded) {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("승인 범위 밖 경로입니다")
	}
	for _, blocked := range p.BlockedPaths {
		if pathContains(blocked, decoded) {
			return errors.New("정책에서 차단한 경로입니다")
		}
	}
	return nil
}

func validateProbeIP(ip netip.Addr, cidrs []string) error {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return errors.New("루프백·링크 로컬·멀티캐스트 대상은 차단됩니다")
	}
	if len(cidrs) > 0 {
		for _, raw := range cidrs {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil && prefix.Contains(ip) {
				return nil
			}
		}
		return errors.New("승인 CIDR 밖 IP 주소입니다")
	}
	return nil
}

func (a *App) scanPolicy(ctx context.Context, input map[string]any) (domainResource, domainResource, probePolicy, error) {
	var p probePolicy
	s, err := a.resource(ctx, "services", str(input, "service_id"))
	if err != nil {
		return s, domainResource{}, p, errors.New("서비스를 찾을 수 없습니다")
	}
	if !boolean(s.Data, "approved") {
		return s, domainResource{}, p, errors.New("관리자가 승인한 서비스만 진단할 수 있습니다")
	}
	scopeID := str(input, "scope_id")
	if scopeID == "" {
		rows, err := a.DB.Query(ctx, `SELECT id FROM resources WHERE kind='scopes' AND data->>'service_id'=$1 AND data->>'approved'='true' ORDER BY created_at DESC`, s.ID)
		if err != nil {
			return s, domainResource{}, p, err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				candidate, e := a.resource(ctx, "scopes", id)
				if e == nil {
					expiry, e := time.Parse(time.RFC3339, str(candidate.Data, "expires_at"))
					if e == nil && expiry.After(time.Now()) {
						scopeID = id
						break
					}
				}
			}
		}
	}
	scope, err := a.resource(ctx, "scopes", scopeID)
	if err != nil || !boolean(scope.Data, "approved") || str(scope.Data, "service_id") != s.ID {
		return s, scope, p, errors.New("서비스와 연결된 승인된 진단 범위가 필요합니다")
	}
	p.Roots, err = a.trustedRoots(ctx)
	if err != nil {
		return s, scope, p, err
	}
	p.Target, err = parseTarget(str(s.Data, "url"))
	if err != nil {
		return s, scope, p, err
	}
	p.Hosts = stringList(scope.Data["allowed_hosts"])
	p.Paths = stringList(scope.Data["allowed_paths"])
	p.CIDRs = stringList(scope.Data["allowed_cidrs"])
	p.ExpiresAt, err = time.Parse(time.RFC3339, str(scope.Data, "expires_at"))
	if err != nil {
		return s, scope, p, errors.New("범위 만료 설정이 올바르지 않습니다")
	}
	p.MaxRequests = number(scope.Data, "max_requests", 10)
	p.Timeout = number(scope.Data, "timeout_seconds", 30)
	p.MaxRPS = number(scope.Data, "max_rps", 1)
	p.AllowedMethods = []string{"GET", "HEAD"}
	p.BlockedPaths = []string{"/logout", "/delete", "/payment", "/send-sms", "/send-mail"}
	policySnapshots := []any{}
	rows, err := a.DB.Query(ctx, `SELECT data FROM resources WHERE kind='policies' AND COALESCE(data->>'enabled','true')='true' AND (COALESCE(data->>'service_id','')='' OR data->>'service_id'=$1) ORDER BY id`, s.ID)
	if err != nil {
		return s, scope, p, err
	}
	defer rows.Close()
	for rows.Next() {
		var m map[string]any
		if err := rows.Scan(&m); err != nil {
			return s, scope, p, err
		}
		policySnapshots = append(policySnapshots, m)
		p.MaxRequests = min(p.MaxRequests, number(m, "max_requests", 10))
		p.Timeout = min(p.Timeout, number(m, "timeout_seconds", 30))
		p.MaxRPS = min(p.MaxRPS, number(m, "max_rps", 1))
		p.BlockedPaths = append(p.BlockedPaths, stringList(m["blocked_paths"])...)
		methods := stringList(m["allowed_methods"])
		if len(methods) > 0 {
			next := []string{}
			for _, method := range p.AllowedMethods {
				if hasString(methods, method) {
					next = append(next, method)
				}
			}
			p.AllowedMethods = next
		}
		if boolean(m, "emergency_stop") {
			return s, scope, p, errors.New("정책 긴급 중지가 활성화되어 있습니다")
		}
	}
	if p.MaxRequests < 1 || p.MaxRequests > 100 || p.Timeout < 1 || p.Timeout > 300 || p.MaxRPS < 1 || p.MaxRPS > 5 {
		return s, scope, p, errors.New("정책 제한값이 유효하지 않습니다")
	}
	snapshots := []any{s.Data, s.OwnerID, scope.Data, policySnapshots}
	if scenarioID := str(input, "scenario_id"); scenarioID != "" {
		scenario, e := a.resource(ctx, "scenarios", scenarioID)
		if e != nil {
			return s, scope, p, e
		}
		snapshots = append(snapshots, scenario.Data)
		for _, key := range []string{"authorized_profile_id", "unauthorized_profile_id"} {
			profile, e := a.resource(ctx, "auth-profiles", str(scenario.Data, key))
			if e != nil {
				return s, scope, p, e
			}
			snapshots = append(snapshots, profile.Data)
		}
	}
	security, e := a.setting(ctx, "security")
	if e != nil {
		return s, scope, p, e
	}
	snapshots = append(snapshots, security["trusted_ca_pem"])
	encoded, _ := json.Marshal(snapshots)
	fingerprint := sha256.Sum256(encoded)
	p.Fingerprint = hex.EncodeToString(fingerprint[:])
	err = p.validateURL(p.Target)
	return s, scope, p, err
}

// The transport pins the validated DNS answer to the actual connection and
// ignores proxy environment variables. Every redirect repeats the same checks.
func (p probePolicy) client(ctx context.Context, check func() error) (*http.Client, func()) {
	var mu sync.Mutex
	count := 0
	var last time.Time
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.Roots}, DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 65536}
	tr.DialContext = func(c context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(c, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("DNS 주소가 없습니다")
		}
		for _, ip := range ips {
			if err := validateProbeIP(ip, p.CIDRs); err != nil {
				return nil, err
			}
		}
		if err := check(); err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(c, "tcp", net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			lastErr = e
		}
		return nil, lastErr
	}
	round := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := p.validateURL(r.URL); err != nil {
			return nil, err
		}
		if !hasString(p.AllowedMethods, r.Method) {
			return nil, errors.New("허용되지 않은 HTTP 메서드입니다")
		}
		if err := check(); err != nil {
			return nil, err
		}
		mu.Lock()
		count++
		if count > p.MaxRequests {
			mu.Unlock()
			return nil, errors.New("최대 요청 횟수에 도달했습니다")
		}
		delay := time.Until(last.Add(time.Second / time.Duration(p.MaxRPS)))
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-r.Context().Done():
				timer.Stop()
				mu.Unlock()
				return nil, r.Context().Err()
			case <-timer.C:
			}
		}
		last = time.Now()
		mu.Unlock()
		if err := p.validateURL(r.URL); err != nil {
			return nil, err
		}
		if err := check(); err != nil {
			return nil, err
		}
		resp, err := tr.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			return nil, fmt.Errorf("안전 차단: 대상 HTTP %d 응답", resp.StatusCode)
		}
		return resp, nil
	})
	client := &http.Client{Transport: round, Timeout: time.Duration(p.Timeout) * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("리다이렉트 제한을 초과했습니다")
		}
		if len(via) > 0 && !strings.EqualFold(r.URL.Host, via[0].URL.Host) {
			return errors.New("다른 호스트로의 리다이렉트는 인증 정보 보호를 위해 차단됩니다")
		}
		return p.validateURL(r.URL)
	}}
	return client, tr.CloseIdleConnections
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
