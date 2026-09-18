package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
)

// MCP 를 SSO 로 — 개인 키 없이, Keycloak 이 발급한 액세스 토큰으로.
//
// The MCP authorization specification (2025-06-18 and later) is OAuth 2.1: the
// MCP server is a *resource server* that publishes where its authorization
// server is (RFC 9728, /.well-known/oauth-protected-resource) and a client
// refused with 401 reads that document, sends the person through Keycloak with
// PKCE and returns with an access token whose audience is this server. Nothing
// about issuing tokens happens here; this file answers two questions only —
// where is the authorization server, and is this token one it issued for us.
//
// The personal key stays. An SSO token is a second door into the same room: it
// authenticates an *existing* Hunter account (the web sign-in is what
// provisions one), carries the scopes the administrator chose intersected with
// the account's role, and is accepted on /mcp only. REST, GraphQL and the
// administration API keep taking keys and sessions exactly as before.

var mcpOAuthDefaultScopes = []string{"services:read", "findings:read", "scans:read"}

// Only asymmetric signatures: a shared-secret (HS*) or unsigned token could be
// minted by anyone holding the JWKS document, which is public.
var mcpOAuthAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

func mcpOAuthDefaults() map[string]any {
	return map[string]any{"enabled": false, "resource": "", "audience": []string{}, "scopes": append([]string{}, mcpOAuthDefaultScopes...)}
}

// mcpOAuthValues lays the stored oauth object over the defaults: setting()
// replaces a stored top-level value wholesale, so a map saved by an older
// version keeps sensible values for keys it did not know.
func mcpOAuthValues(group map[string]any) map[string]any {
	out := mcpOAuthDefaults()
	stored, _ := group["oauth"].(map[string]any)
	for k, v := range stored {
		out[k] = v
	}
	return out
}

// Space-separated strings are the standard's notation for audiences and
// scopes; the screen sends arrays. Both normalize to a deduplicated list.
func mcpOAuthList(v any) []string {
	items := stringSlice(v)
	if s, ok := v.(string); ok {
		items = strings.Fields(s)
	}
	out := []string{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" && !slices.Contains(out, item) {
			out = append(out, item)
		}
	}
	return out
}

func validateMCPSettings(v map[string]any) error {
	o := mcpOAuthValues(v)
	enabled, ok := o["enabled"].(bool)
	if !ok {
		return fmt.Errorf("oauth.enabled 값은 true 또는 false여야 합니다")
	}
	resource := strings.TrimSpace(asString(o["resource"]))
	if resource != "" && (len(resource) > 2048 || !validURL(resource)) {
		return fmt.Errorf("MCP 리소스 식별자는 http(s) 공개 주소여야 합니다 (예: https://hunter.internal/mcp)")
	}
	audience := mcpOAuthList(o["audience"])
	if len(audience) > 20 {
		return fmt.Errorf("MCP SSO 허용 대상은 20개 이하로 입력해 주세요")
	}
	for _, item := range audience {
		if len(item) > 255 || strings.IndexFunc(item, func(r rune) bool { return r <= ' ' || r == '"' || r == 0x7f }) >= 0 {
			return fmt.Errorf("MCP SSO 허용 대상은 공백·따옴표 없이 255자 이하로 입력해 주세요: %s", item)
		}
	}
	scopes := mcpOAuthList(o["scopes"])
	for _, scope := range scopes {
		if !slices.Contains(allScopes, scope) {
			return fmt.Errorf("MCP SSO 범위에 허용되지 않은 권한입니다: %s", scope)
		}
	}
	if enabled && len(scopes) == 0 {
		return fmt.Errorf("SSO 토큰 주체에게 줄 MCP 권한을 하나 이상 선택해 주세요")
	}
	v["oauth"] = map[string]any{"enabled": enabled, "resource": resource, "audience": audience, "scopes": scopes}
	return nil
}

// mcpOAuthConfig is the effective state: Enabled is true only when the
// administrator switched it on *and* the pieces it depends on exist.
type mcpOAuthConfig struct {
	Enabled bool
	// Reason says why Enabled is false while the switch is on.
	Reason string
	// Issuer is oidc.issuer exactly as stored — also the string the web
	// sign-in hashes into users.oidc_subject, so the account lookup matches.
	Issuer   string
	ClientID string
	// Resource is the identifier this deployment claims (RFC 8707): what the
	// metadata advertises and what a token's aud may name.
	Resource string
	// PublicBase is general.public_url without a trailing slash; the metadata
	// document lives under it because this server is what answers there.
	PublicBase string
	Audience   []string
	Scopes     []string
}

func (c mcpOAuthConfig) metadataURL() string {
	return c.PublicBase + "/.well-known/oauth-protected-resource/mcp"
}

func (a *App) mcpOAuth(ctx context.Context) (mcpOAuthConfig, error) {
	m, err := a.setting(ctx, "mcp")
	if err != nil {
		return mcpOAuthConfig{}, err
	}
	o := mcpOAuthValues(m)
	cfg := mcpOAuthConfig{Resource: strings.TrimSpace(asString(o["resource"])), Audience: mcpOAuthList(o["audience"]), Scopes: mcpOAuthList(o["scopes"])}
	oidcSettings, err := a.setting(ctx, "oidc")
	if err != nil {
		return cfg, err
	}
	g, err := a.setting(ctx, "general")
	if err != nil {
		return cfg, err
	}
	cfg.Issuer, cfg.ClientID = asString(oidcSettings["issuer"]), asString(oidcSettings["client_id"])
	cfg.PublicBase = strings.TrimSuffix(asString(g["public_url"]), "/")
	if cfg.Resource == "" && cfg.PublicBase != "" {
		cfg.Resource = cfg.PublicBase + "/mcp"
	}
	if !asBool(o["enabled"]) {
		return cfg, nil
	}
	switch {
	case !asBool(oidcSettings["enabled"]) || !validURL(cfg.Issuer):
		cfg.Reason = "oidc sso is not configured (oidc.enabled, oidc.issuer)"
	case !validURL(cfg.Resource) || !validURL(cfg.PublicBase):
		cfg.Reason = "resource identifier unavailable (general.public_url or mcp.oauth.resource)"
	case len(cfg.Scopes) == 0:
		cfg.Reason = "mcp.oauth.scopes is empty"
	default:
		cfg.Enabled = true
	}
	if cfg.Reason != "" {
		slog.Warn("mcp oauth switched on but inactive", "reason", cfg.Reason)
	}
	return cfg, nil
}

// The PUT handler refuses a switch-on that would sit inactive; the runtime
// check above still guards a later change to the OIDC or general group.
func (a *App) validateMCPSettingsLinks(ctx context.Context, v map[string]any) error {
	if !asBool(mcpOAuthValues(v)["enabled"]) {
		return nil
	}
	oidcSettings, err := a.setting(ctx, "oidc")
	if err != nil {
		return err
	}
	if !asBool(oidcSettings["enabled"]) || !validURL(asString(oidcSettings["issuer"])) {
		return fmt.Errorf("MCP SSO 연결은 SSO · 로그인 그룹에서 OIDC 를 켜고 Issuer URL 을 저장한 뒤 켤 수 있습니다")
	}
	return nil
}

// mcpOAuthProviderCache keeps one discovery per issuer and CA bundle. Discovery
// is a round trip to Keycloak and the key set behind it verifies every token;
// doing that per request would put Keycloak's latency in front of every MCP
// call. go-oidc refetches the key set on an unknown key id, so rotation needs
// no invalidation here.
type mcpOAuthProviderCache struct {
	mu       sync.Mutex
	key      string
	provider *oidc.Provider
}

// mcpJWKSThrottle bounds sequential forged-kid traffic to one key-set fetch per
// second. go-oidc coalesces concurrent refreshes but retries on every unknown
// kid; tokens verified by already cached keys never wait here.
type mcpJWKSThrottle struct {
	base        http.RoundTripper
	discovery   string
	mu          sync.Mutex
	nextRefresh time.Time
}

func (t *mcpJWKSThrottle) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != t.discovery {
		t.mu.Lock()
		delay := time.Until(t.nextRefresh)
		if delay < 0 {
			delay = 0
		}
		t.nextRefresh = time.Now().Add(delay + time.Second)
		t.mu.Unlock()
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-timer.C:
			}
		}
	}
	return t.base.RoundTrip(r)
}

func (a *App) mcpOAuthProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	s, err := a.setting(ctx, "security")
	if err != nil {
		return nil, err
	}
	key := digest(issuer + "\n" + asString(s["trusted_ca_pem"]))
	a.MCPOAuth.mu.Lock()
	defer a.MCPOAuth.mu.Unlock()
	if a.MCPOAuth.provider != nil && a.MCPOAuth.key == key {
		return a.MCPOAuth.provider, nil
	}
	client, err := a.outboundClient(ctx, 15*time.Second)
	if err != nil {
		return nil, err
	}
	client.Transport = &mcpJWKSThrottle{base: client.Transport, discovery: strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"}
	// Discovery must outlive this request: the provider keeps the context for
	// later key fetches.
	provider, err := oidc.NewProvider(oidc.ClientContext(context.WithoutCancel(ctx), client), issuer)
	if err != nil {
		return nil, err
	}
	a.MCPOAuth.key, a.MCPOAuth.provider = key, provider
	return provider, nil
}

// looksLikeJWT is the cheap shape test that separates "not a key" from "not a
// token of any kind we accept", so the refusal can say which.
func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

// mcpOAuthRefusal carries the sentence the client sees and the cause the
// operator sees in the log. Every refusal path builds one, so the /mcp handler
// logs the cause in exactly one place and no path can skip it.
type mcpOAuthRefusal struct {
	message string
	cause   error
}

func (r mcpOAuthRefusal) Error() string { return r.message }
func (r mcpOAuthRefusal) Unwrap() error { return r.cause }

func mcpRefuse(message string, cause error) error { return mcpOAuthRefusal{message: message, cause: cause} }

// mcpOAuthPrincipal turns a bearer access token into a Hunter principal, or
// says exactly why it will not.
func (a *App) mcpOAuthPrincipal(ctx context.Context, token string) (User, error) {
	var u User
	cfg, err := a.mcpOAuth(ctx)
	if err != nil {
		return u, mcpRefuse("설정을 읽을 수 없어 SSO 액세스 토큰을 확인할 수 없습니다", err)
	}
	if !cfg.Enabled {
		reason := cfg.Reason
		if reason == "" {
			reason = "mcp.oauth.enabled is false"
		}
		return u, mcpRefuse("이 서버는 SSO 액세스 토큰을 받지 않습니다. 개인 API 키(hnt_)를 쓰거나 관리자가 MCP SSO 연결을 켜야 합니다.", errors.New("mcp oauth inactive: "+reason))
	}
	// The header before anything that needs the network: an ID token or a
	// symmetric signature is refused without asking Keycloak for keys.
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(token, ".", 2)[0])
	if err != nil || json.Unmarshal(raw, &header) != nil {
		return u, mcpRefuse("SSO 액세스 토큰의 형식이 올바르지 않습니다.", fmt.Errorf("jwt header unreadable: %v", err))
	}
	if strings.EqualFold(header.Typ, "ID") {
		return u, mcpRefuse("ID 토큰은 로그인 증거이지 MCP 자격이 아닙니다. 클라이언트가 액세스 토큰을 보내야 합니다.", errors.New("typ=ID token presented"))
	}
	if !slices.Contains(mcpOAuthAlgorithms, header.Alg) {
		return u, mcpRefuse("SSO 토큰의 서명 알고리즘을 받지 않습니다(RS·ES·PS 계열만 허용).", fmt.Errorf("unsupported alg %q", header.Alg))
	}
	provider, err := a.mcpOAuthProvider(ctx, cfg.Issuer)
	if err != nil {
		return u, mcpRefuse("Keycloak 발급자 정보를 읽지 못해 SSO 토큰을 확인할 수 없습니다. 잠시 후 다시 시도하거나 관리자에게 알리세요.", fmt.Errorf("discovery %s: %w", cfg.Issuer, err))
	}
	// Signature, issuer and expiry. The audience is checked below by hand
	// because more than one value is acceptable and the library compares one.
	verified, err := provider.Verifier(&oidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: mcpOAuthAlgorithms}).Verify(ctx, token)
	if err != nil {
		return u, mcpRefuse("SSO 액세스 토큰이 유효하지 않습니다(서명·발급자·만료). 클라이언트에서 다시 로그인하세요.", fmt.Errorf("token rejected: %w", err))
	}
	var claims map[string]any
	if err = verified.Claims(&claims); err != nil {
		return u, mcpRefuse("SSO 토큰의 사용자 정보를 읽을 수 없습니다.", fmt.Errorf("claims unreadable: %w", err))
	}
	if nbf, ok := claims["nbf"]; ok {
		if n, ok := nbf.(float64); !ok || time.Unix(int64(n), 0).After(time.Now().Add(time.Minute)) {
			return u, mcpRefuse("SSO 액세스 토큰이 아직 유효하지 않습니다(nbf). 시계를 확인하세요.", fmt.Errorf("token not yet valid: nbf=%v", nbf))
		}
	}
	if _, ok := claims["cnf"]; ok {
		return u, mcpRefuse("소지자 증명(cnf)이 묶인 토큰은 이 서버가 검증할 수 없어 받지 않습니다.", errors.New("cnf claim present"))
	}
	if verified.Subject == "" {
		return u, mcpRefuse("SSO 토큰에 사용자 식별 정보(sub)가 없습니다.", errors.New("sub missing"))
	}
	// Whom the token was minted for. A real Keycloak 26 puts the client in
	// `azp` and only `account` in `aud` unless an Audience mapper is added, so
	// "aud names us, or aud/azp is a client the administrator trusts" is the
	// binding — either way the token is for this deployment, not passed
	// through from some other application in the realm.
	azp := asString(claims["azp"])
	accepted := append([]string{cfg.Resource}, cfg.Audience...)
	if cfg.ClientID != "" {
		accepted = append(accepted, cfg.ClientID)
	}
	bound := append(slices.Clone(verified.Audience), azp)
	if !slices.ContainsFunc(bound, func(v string) bool { return v != "" && slices.Contains(accepted, v) }) {
		fix := azp
		if fix == "" {
			fix = "<MCP 클라이언트 ID>"
		}
		return u, mcpRefuse(fmt.Sprintf("SSO 토큰이 이 서버를 위해 발급된 것이 아닙니다(aud %v, azp %q). 관리자가 MCP SSO 허용 대상에 %q 를 적거나, Keycloak 클라이언트의 Audience 매퍼에 %q 를 넣어야 합니다.", verified.Audience, azp, fix, cfg.Resource), fmt.Errorf("audience %v / azp %q not in %v", verified.Audience, azp, accepted))
	}
	// The same lookup the web sign-in uses, without the provisioning half. A
	// token never creates an account, revives a disabled one or carries a role.
	err = a.DB.QueryRow(ctx, `SELECT id,username,name,role,team FROM users WHERE oidc_subject=$1 AND NOT disabled`, digest(cfg.Issuer+"|"+verified.Subject)).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, mcpRefuse("이 SSO 계정은 Hunter 에 등록되지 않았거나 비활성입니다. 먼저 웹으로 한 번 로그인하세요.", errors.New("no active hunter account for sso subject"))
	}
	if err != nil {
		return User{}, mcpRefuse("계정을 조회할 수 없습니다. 잠시 후 다시 시도하세요.", err)
	}
	// Never wider than a key: the administrator's ceiling intersected with the
	// account's current role. An empty intersection is a refusal, not an
	// unlimited principal.
	u.Scopes = []string{}
	for _, scope := range a.roleScopes(ctx, u.Role) {
		if slices.Contains(cfg.Scopes, scope) {
			u.Scopes = append(u.Scopes, scope)
		}
	}
	if len(u.Scopes) == 0 {
		return User{}, mcpRefuse(fmt.Sprintf("이 계정의 역할(%s)에는 SSO 로 허용된 MCP 권한이 없습니다. 관리자가 MCP SSO 범위(%s)와 역할 권한을 확인해야 합니다.", u.Role, strings.Join(cfg.Scopes, " ")), fmt.Errorf("role %s has no scope in %v", u.Role, cfg.Scopes))
	}
	u.Auth = "oauth"
	return u, nil
}

// mcpChallenge is the header that turns a 401 into an invitation: the MCP
// client reads resource_metadata and starts the OAuth flow from there. It is
// set on the MCP path only — a REST 401 carrying it would send browsers and
// other clients somewhere they cannot use.
func (a *App) mcpChallenge(w http.ResponseWriter, r *http.Request, invalid bool) {
	value := `Bearer realm="hunter"`
	if cfg, err := a.mcpOAuth(r.Context()); err == nil && cfg.Enabled {
		value += `, resource_metadata="` + cfg.metadataURL() + `"`
	}
	if invalid {
		value += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", value)
}

// mcpResourceMetadata is RFC 9728: the bare document, not the product
// envelope, because the reader is an OAuth client library. Public by design —
// it says where to sign in, not who is signed in.
func (a *App) mcpResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "MCP-Protocol-Version")
		w.WriteHeader(204)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, OPTIONS")
		fail(w, 405, "허용되지 않는 요청입니다")
		return
	}
	cfg, err := a.mcpOAuth(r.Context())
	if err != nil || !cfg.Enabled {
		fail(w, 404, "이 서버의 MCP 는 SSO 토큰을 받지 않습니다. 개인 API 키(hnt_)를 사용하세요.")
		return
	}
	g, _ := a.setting(r.Context(), "general")
	name := strings.TrimSpace(asString(g["service_name"]))
	if name == "" {
		name = "Hunter"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                 cfg.Resource,
		"authorization_servers":    []string{cfg.Issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         cfg.Scopes,
		"resource_name":            name + " MCP",
	})
}
