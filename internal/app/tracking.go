package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/html"
	"golang.org/x/net/idna"
)

// Tracking never shares the application's origin. Only approved page categories
// cross the iframe message boundary; browser code is encrypted at rest and never audited.
type trackingConfig struct {
	Enabled        bool       `json:"enabled"`
	Name           string     `json:"name"`
	Script         string     `json:"script"`
	AllowedOrigins []string   `json:"allowed_origins"`
	Revision       int64      `json:"revision"`
	UpdatedAt      *time.Time `json:"updated_at"`
}
type trackingScript struct {
	Code       string            `json:"code,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func (a *App) initTracking(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS visitor_tracking_config (
 id boolean PRIMARY KEY DEFAULT true CHECK(id), config_encrypted text NOT NULL,
 revision bigint NOT NULL DEFAULT 0, updated_at timestamptz);
 CREATE TABLE IF NOT EXISTS visitor_tracking_previews (
 token_hash text PRIMARY KEY, user_id text NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 config_encrypted text NOT NULL, expires_at timestamptz NOT NULL);
 CREATE INDEX IF NOT EXISTS visitor_tracking_previews_expiry ON visitor_tracking_previews(expires_at);`)
	if err != nil {
		return err
	}
	b, err := json.Marshal(trackingConfig{Name: "방문 통계", AllowedOrigins: []string{}})
	if err != nil {
		return err
	}
	cipher, err := a.encrypt(string(b))
	if err != nil {
		return err
	}
	_, err = a.DB.Exec(ctx, `INSERT INTO visitor_tracking_config(id,config_encrypted) VALUES(true,$1) ON CONFLICT DO NOTHING`, cipher)
	return err
}
func (a *App) trackingConfig(ctx context.Context) (trackingConfig, error) {
	var c trackingConfig
	var cipher string
	var rev int64
	var updated *time.Time
	err := a.DB.QueryRow(ctx, `SELECT config_encrypted,revision,updated_at FROM visitor_tracking_config WHERE id`).Scan(&cipher, &rev, &updated)
	if err != nil {
		return c, err
	}
	plain, err := a.decrypt(cipher)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal([]byte(plain), &c)
	c.Revision = rev
	c.UpdatedAt = updated
	return c, err
}
func trackingOrigin(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || len(s) > 300 || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(s, "*;,'\"\\ \t\r\n") || strings.Contains(u.Host, "%") {
		return "", errors.New("허용 주소는 와일드카드 없이 http(s)://호스트[:포트]로 입력해 주세요")
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", errors.New("허용 주소의 포트를 확인해 주세요")
		}
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || len(host) > 253 {
			return "", errors.New("허용 주소의 호스트 이름을 확인해 주세요")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("허용 주소의 호스트 이름을 확인해 주세요")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return "", errors.New("허용 주소의 호스트 이름을 확인해 주세요")
				}
			}
		}
		// Browsers interpret numeric/hexadecimal final labels as legacy IPv4.
		// Require canonical IP literals above so aliases cannot bypass app-origin denial.
		last := host[strings.LastIndex(host, ".")+1:]
		if _, e := strconv.ParseUint(last, 10, 64); e == nil || strings.HasPrefix(last, "0x") {
			return "", errors.New("IP 주소는 표준 IPv4 또는 IPv6 형식으로 입력해 주세요")
		}
	}
	if port := u.Port(); port != "" {
		n, _ := strconv.Atoi(port)
		if !(n == 80 && u.Scheme == "http" || n == 443 && u.Scheme == "https") {
			host += ":" + strconv.Itoa(n)
		}
	}
	return u.Scheme + "://" + host, nil
}
func validateTracking(c *trackingConfig, forbidden []string) ([]trackingScript, error) {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || utf8.RuneCountInString(c.Name) > 100 || len(c.Script) > 32768 || !utf8.ValidString(c.Script) || c.Revision < 0 || len(c.AllowedOrigins) > 10 {
		return nil, errors.New("이름은 1~100자, 스크립트는 32 KiB 이하, 허용 주소는 10개 이하로 입력해 주세요")
	}
	seen := map[string]bool{}
	origins := []string{}
	totalOriginBytes := 0
	for _, s := range c.AllowedOrigins {
		o, err := trackingOrigin(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		for _, f := range forbidden {
			if normal, e := trackingOrigin(f); e == nil && o == normal {
				return nil, errors.New("Hunter 서비스 자체 주소는 추적 통신 대상으로 허용할 수 없습니다")
			}
		}
		if !seen[o] {
			totalOriginBytes += len(o) + 1
			if totalOriginBytes > 1536 {
				return nil, errors.New("허용 주소 전체 길이는 1,536바이트 이하여야 합니다")
			}
			origins = append(origins, o)
			seen[o] = true
		}
	}
	c.AllowedOrigins = origins
	if strings.TrimSpace(c.Script) == "" {
		if c.Enabled {
			return nil, errors.New("추적을 사용하려면 스크립트를 입력해 주세요")
		}
		return []trackingScript{}, nil
	}
	if !strings.HasPrefix(strings.TrimSpace(c.Script), "<") {
		return []trackingScript{{Code: c.Script}}, nil
	}
	// Parse, then construct script elements. Never paste arbitrary HTML (meta refresh,
	// base, iframe, event attributes) into an authenticated HTML response.
	z := html.NewTokenizer(strings.NewReader(c.Script))
	var out []trackingScript
	var current *trackingScript
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if z.Err() != io.EOF || current != nil {
				return nil, errors.New("스크립트 태그가 올바르게 닫혔는지 확인해 주세요")
			}
			if len(out) == 0 {
				return nil, errors.New("실행할 script 태그를 입력해 주세요")
			}
			return out, nil
		case html.CommentToken:
			if current != nil {
				current.Code += string(z.Raw())
			}
		case html.TextToken:
			if current != nil {
				current.Code += string(z.Text())
			} else if strings.TrimSpace(string(z.Text())) != "" {
				return nil, errors.New("HTML 형식은 script 태그와 주석만 지원합니다")
			}
		case html.StartTagToken:
			t := z.Token()
			if t.Data != "script" || current != nil || len(out) >= 10 {
				return nil, errors.New("HTML 형식은 최대 10개의 script 태그만 지원합니다")
			}
			current = &trackingScript{Attributes: map[string]string{}}
			for _, attr := range t.Attr {
				k := strings.ToLower(attr.Key)
				if k == "src" {
					u, e := url.Parse(attr.Val)
					if e != nil || u.User != nil || u.Host == "" || u.Fragment != "" {
						return nil, errors.New("script src는 허용 주소의 절대 URL이어야 합니다")
					}
					origin, e := trackingOrigin(u.Scheme + "://" + u.Host)
					if e != nil || !slices.Contains(origins, origin) {
						return nil, errors.New("script src 주소를 허용 통신 주소에 추가해 주세요")
					}
				} else if k == "type" {
					if !slices.Contains([]string{"", "text/javascript", "application/javascript", "module"}, attr.Val) {
						return nil, errors.New("JavaScript script 태그만 지원합니다")
					}
				} else if !slices.Contains([]string{"async", "defer", "integrity", "crossorigin", "charset"}, k) && !strings.HasPrefix(k, "data-") {
					return nil, errors.New("script 태그 속성은 src·type·async·defer·integrity·crossorigin·charset·data-*만 지원합니다")
				}
				current.Attributes[k] = attr.Val
			}
		case html.EndTagToken:
			if z.Token().Data != "script" || current == nil {
				return nil, errors.New("script 태그 구성을 확인해 주세요")
			}
			out = append(out, *current)
			current = nil
		default:
			return nil, errors.New("HTML 형식은 script 태그와 주석만 지원합니다")
		}
	}
}
func (a *App) trackingForbidden(r *http.Request) []string {
	g, _ := a.setting(r.Context(), "general")
	return []string{asString(g["public_url"]), "http://" + r.Host, "https://" + r.Host}
}
func (a *App) trackingAdmin(h http.HandlerFunc) http.HandlerFunc {
	return a.sessionOnly(func(w http.ResponseWriter, r *http.Request) {
		if !slices.Contains(currentUser(r).Scopes, "admin:manage") {
			fail(w, 403, "관리자 권한이 필요합니다")
			return
		}
		h(w, r)
	})
}
func (a *App) registerTracking(m *http.ServeMux) {
	m.HandleFunc("GET /api/admin/tracking", a.trackingAdmin(func(w http.ResponseWriter, r *http.Request) {
		c, e := a.trackingConfig(r.Context())
		if e != nil {
			fail(w, 503, "방문 추적 설정을 읽을 수 없습니다")
			return
		}
		jsonResponse(w, 200, c)
	}))
	m.HandleFunc("PUT /api/admin/tracking", a.trackingAdmin(a.saveTracking))
	m.HandleFunc("POST /api/admin/tracking/test", a.trackingAdmin(a.testTracking))
	m.HandleFunc("GET /api/tracking/config", a.sessionOnly(func(w http.ResponseWriter, r *http.Request) {
		c, e := a.trackingConfig(r.Context())
		if e != nil {
			fail(w, 503, "방문 추적 설정을 읽을 수 없습니다")
			return
		}
		jsonResponse(w, 200, map[string]any{"enabled": c.Enabled, "revision": c.Revision, "frame_url": fmt.Sprintf("/api/tracking/frame?revision=%d", c.Revision)})
	}))
	m.HandleFunc("GET /api/tracking/frame", a.sessionOnly(func(w http.ResponseWriter, r *http.Request) {
		c, e := a.trackingConfig(r.Context())
		if e != nil {
			fail(w, 503, "방문 추적 설정을 읽을 수 없습니다")
			return
		}
		if !c.Enabled {
			fail(w, 404, "방문 추적이 꺼져 있습니다")
			return
		}
		if r.URL.Query().Get("revision") != strconv.FormatInt(c.Revision, 10) {
			fail(w, 409, "방문 추적 설정이 변경되었습니다")
			return
		}
		a.serveTrackingFrame(w, r, c)
	}))
	a.registerTrackingViolations(m)
	m.HandleFunc("GET /api/tracking/preview/{token}", a.trackingAdmin(func(w http.ResponseWriter, r *http.Request) {
		var cipher string
		e := a.DB.QueryRow(r.Context(), `DELETE FROM visitor_tracking_previews WHERE token_hash=$1 AND user_id=$2 AND expires_at>now() RETURNING config_encrypted`, digest(r.PathValue("token")), currentUser(r).ID).Scan(&cipher)
		if e != nil {
			fail(w, 404, "미리보기가 만료되었습니다. 다시 검증해 주세요")
			return
		}
		plain, e := a.decrypt(cipher)
		var c trackingConfig
		if e != nil || json.Unmarshal([]byte(plain), &c) != nil {
			fail(w, 503, "미리보기를 읽을 수 없습니다")
			return
		}
		a.serveTrackingFrame(w, r, c)
	}))
}
func (a *App) decodeTracking(w http.ResponseWriter, r *http.Request) (trackingConfig, bool) {
	var c trackingConfig
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if decode(r, &c) != nil {
		fail(w, 400, "방문 추적 설정을 확인해 주세요")
		return c, false
	}
	if _, e := validateTracking(&c, a.trackingForbidden(r)); e != nil {
		fail(w, 400, e.Error())
		return c, false
	}
	return c, true
}
func (a *App) saveTracking(w http.ResponseWriter, r *http.Request) {
	c, ok := a.decodeTracking(w, r)
	if !ok {
		return
	}
	b, _ := json.Marshal(c)
	cipher, e := a.encrypt(string(b))
	if e != nil {
		fail(w, 500, "방문 추적 설정 암호화 실패")
		return
	}
	var revision int64
	var updated time.Time
	e = a.DB.QueryRow(r.Context(), `UPDATE visitor_tracking_config SET config_encrypted=$1,revision=revision+1,updated_at=clock_timestamp() WHERE id AND revision=$2 RETURNING revision,updated_at`, cipher, c.Revision).Scan(&revision, &updated)
	if e == pgx.ErrNoRows {
		fail(w, 409, "다른 관리자가 설정을 변경했습니다. 입력을 보존한 채 최신 설정을 확인해 주세요")
		return
	}
	if e != nil {
		fail(w, 500, "방문 추적 설정 저장 실패")
		return
	}
	c.Revision = revision
	c.UpdatedAt = &updated
	a.audit(r, "tracking.update", "visitor_tracking", map[string]any{"enabled": c.Enabled, "revision": revision, "origin_count": len(c.AllowedOrigins), "script_bytes": len(c.Script)})
	jsonResponse(w, 200, c)
}
func (a *App) testTracking(w http.ResponseWriter, r *http.Request) {
	c, ok := a.decodeTracking(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(c.Script) == "" {
		fail(w, 400, "검증할 스크립트를 입력해 주세요")
		return
	}
	b, _ := json.Marshal(c)
	cipher, e := a.encrypt(string(b))
	if e != nil {
		fail(w, 500, "미리보기 준비 실패")
		return
	}
	token := randomToken()
	tx, e := a.DB.Begin(r.Context())
	if e != nil {
		fail(w, 503, "미리보기 준비 실패")
		return
	}
	defer tx.Rollback(r.Context())
	// One pending preview per administrator; expired encrypted snippets are removed.
	_, e = tx.Exec(r.Context(), `DELETE FROM visitor_tracking_previews WHERE user_id=$1 OR expires_at<=now()`, currentUser(r).ID)
	if e == nil {
		_, e = tx.Exec(r.Context(), `INSERT INTO visitor_tracking_previews(token_hash,user_id,config_encrypted,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes') ON CONFLICT(user_id) DO UPDATE SET token_hash=EXCLUDED.token_hash,config_encrypted=EXCLUDED.config_encrypted,expires_at=EXCLUDED.expires_at`, digest(token), currentUser(r).ID, cipher)
	}
	if e != nil || tx.Commit(r.Context()) != nil {
		fail(w, 503, "미리보기 준비 실패")
		return
	}
	a.audit(r, "tracking.test", "visitor_tracking", map[string]any{"origin_count": len(c.AllowedOrigins), "script_bytes": len(c.Script)})
	jsonResponse(w, 200, map[string]any{"ok": true, "preview_token": token, "preview_url": "/api/tracking/preview/" + token, "checks": []map[string]any{
		{"name": "구성 검증", "message": "스크립트 형식과 허용 주소를 확인했습니다", "ok": true},
		{"name": "브라우저 격리", "message": "로그인 정보 없이 예시 화면 이벤트로 미리보기를 실행합니다. 수집 완료 여부는 연동 시스템에서도 확인해 주세요", "ok": true},
	}})
}
func (a *App) serveTrackingFrame(w http.ResponseWriter, r *http.Request, c trackingConfig) {
	scripts, e := validateTracking(&c, a.trackingForbidden(r))
	if e != nil {
		fail(w, 400, "방문 추적 구성이 유효하지 않습니다")
		return
	}
	origins := strings.Join(c.AllowedOrigins, " ")
	external := origins
	if external == "" {
		external = "'none'"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox allow-scripts; script-src 'unsafe-inline' "+origins+"; connect-src "+external+"; img-src "+external+"; style-src 'none'; font-src 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
	// JSON escapes <, > and &: a pasted closing script tag cannot escape this bootstrap.
	data, _ := json.Marshal(scripts)
	_, _ = io.WriteString(w, "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>Hunter 방문 추적 격리 프레임</title></head><body><script>"+trackingBridge+"\nrun("+string(data)+");</script></body></html>")
}

const trackingBridge = `
(()=>{
const send=(status,code)=>parent.postMessage({type:'hunter:tracking-status',status,code},'*');
window.hunterTracking={pageview:null};
window.addEventListener('message',event=>{
 if(event.source!==parent || !event.data || event.data.type!=='hunter:pageview')return;
 const p=event.data.page;
 if(!p || typeof p.path!=='string' || typeof p.title!=='string' || !/^\/[a-z/-]*(?::id)?$/.test(p.path) || p.path.length>100 || p.title.length>100)return;
 const page=Object.freeze({path:p.path,title:p.title});
 window.hunterTracking.pageview=page;
 window.dispatchEvent(new CustomEvent('hunter:pageview',{detail:page}));
});
window.addEventListener('error',()=>send('error','script_error'));
window.addEventListener('unhandledrejection',()=>send('error','script_error'));
const reported=new Set();
document.addEventListener('securitypolicyviolation',event=>{
 send('blocked','policy_blocked');
 const blocked=String(event.blockedURI||'').slice(0,300),directive=String(event.effectiveDirective||'').slice(0,40);
 const key=directive+' '+blocked;
 if(!/^https?:/i.test(blocked) || reported.has(key) || reported.size>=100)return;
 reported.add(key);
 parent.postMessage({type:'hunter:tracking-violation',blocked_uri:blocked,directive},'*');
});
window.run=async scripts=>{
 for(const item of scripts){
  const script=document.createElement('script');
  for(const [key,value] of Object.entries(item.attributes||{}))script.setAttribute(key,value);
  script.referrerPolicy='no-referrer';
  if(item.code)script.textContent=item.code;
  if(script.src || script.type==='module'){
   const ok=await new Promise(resolve=>{
    const timer=setTimeout(()=>resolve(false),8000);
    script.onload=()=>{clearTimeout(timer);resolve(true)};
    script.onerror=()=>{clearTimeout(timer);resolve(false)};
    document.body.append(script);
   });
   if(!ok){send('error','script_load_failed');return}
  }else{document.body.append(script)}
 }
 send('ready','bridge_ready');
};
})();`
