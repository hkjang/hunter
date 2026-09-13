package app

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed schema.sql
var schema string

type App struct {
	DB        *pgxpool.Pool
	Key       []byte
	Version   string
	WorkerID  string
	AuthSlots chan struct{}
	Assets    fs.FS
}
type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	Scopes   []string `json:"scopes"`
	Team     string   `json:"team"`
	KeyID    string   `json:"-"`
}
type userContextKey struct{}

func currentUser(r *http.Request) User { u, _ := r.Context().Value(userContextKey{}).(User); return u }
func New(ctx context.Context, version string, assets fs.FS) (*App, error) {
	dsn, admin, pass, key := os.Getenv("POSTGRES_DSN"), os.Getenv("BOOTSTRAP_ADMIN"), os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"), os.Getenv("ENCRYPTION_KEY")
	if dsn == "" || admin == "" || pass == "" || key == "" {
		return nil, errors.New("POSTGRES_DSN, BOOTSTRAP_ADMIN, BOOTSTRAP_ADMIN_PASSWORD, ENCRYPTION_KEY are required")
	}
	if len(pass) < 12 || len(pass) > 72 {
		return nil, errors.New("bootstrap admin password must be 12–72 bytes")
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("ENCRYPTION_KEY must be a base64-encoded 32-byte key")
	}
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL connection configuration")
	}
	a := &App{DB: db, Key: raw, Version: version, Assets: assets, AuthSlots: make(chan struct{}, 4)}
	conn, err := db.Acquire(ctx)
	if err != nil {
		db.Close()
		return nil, errors.New("PostgreSQL connection failed")
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock(748621092)"); err != nil {
		return nil, err
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(748621092)")
	if _, err = conn.Exec(ctx, schema); err != nil {
		return nil, err
	}
	var check string
	err = conn.QueryRow(ctx, "SELECT value->>'value' FROM settings WHERE key='_encryption_check'").Scan(&check)
	if err == nil {
		plain, e := a.decrypt(check)
		if e != nil || plain != "hunter-encryption-check" {
			return nil, errors.New("ENCRYPTION_KEY does not match this database")
		}
	} else {
		s, _ := a.encrypt("hunter-encryption-check")
		v, _ := json.Marshal(map[string]string{"value": s})
		if _, err = conn.Exec(ctx, "INSERT INTO settings(key,value) VALUES('_encryption_check',$1) ON CONFLICT DO NOTHING", v); err != nil {
			return nil, err
		}
	}
	var count int
	if err = conn.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
		return nil, err
	}
	if count == 0 {
		hash, e := bcrypt.GenerateFromPassword([]byte(pass), 12)
		if e != nil {
			return nil, e
		}
		_, err = conn.Exec(ctx, "INSERT INTO users(id,username,name,role,password_hash) VALUES($1,$2,$3,'admin',$4)", newID(), admin, "서비스 관리자", string(hash))
		if err != nil {
			return nil, err
		}
	}
	if err = a.initDomain(ctx); err != nil {
		return nil, err
	}
	for _, init := range []func(context.Context) error{a.initAuth, a.initTracking, a.initFindingOps, a.initSBOM, a.initCampaigns, a.initNotifications, a.initNotificationAutomation, a.initNotificationOperations, a.initWorkflowAutomation, a.initAgentPlatform, a.initAgentKnowledge, a.initAgentProviders, a.initAgentControl, a.initAgentExecution} {
		if err = init(ctx); err != nil {
			return nil, err
		}
	}
	return a, nil
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 10<<20))
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("JSON 요청을 확인해 주세요")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("하나의 JSON 문서만 허용합니다")
	}
	return nil
}
func (a *App) audit(r *http.Request, action, target string, detail any) {
	u := currentUser(r)
	v, _ := json.Marshal(redact(detail))
	ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
	defer c()
	_, err := a.DB.Exec(ctx, "INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,$3,$4,$5,$6)", newID(), u.ID, u.Username, action, target, v)
	if err != nil {
		slog.Error("audit write failed", "action", action)
	}
}
func redact(v any) any {
	b, _ := json.Marshal(v)
	var x any
	_ = json.Unmarshal(b, &x)
	var walk func(any) any
	walk = func(t any) any {
		switch z := t.(type) {
		case map[string]any:
			for k, v := range z {
				l := strings.ToLower(k)
				if strings.Contains(l, "secret") || strings.Contains(l, "password") || strings.Contains(l, "token") || strings.Contains(l, "dsn") || l == "authorization" || l == "cookie" {
					z[k] = "[REDACTED]"
				} else {
					z[k] = walk(v)
				}
			}
		case []any:
			for i, v := range z {
				z[i] = walk(v)
			}
		}
		return t
	}
	return walk(x)
}
func (a *App) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
		defer c()
		if a.DB.Ping(ctx) != nil {
			fail(w, 503, "데이터베이스 연결을 확인해 주세요")
			return
		}
		jsonResponse(w, 200, map[string]any{"status": "ok", "version": a.Version})
	})
	a.registerAuth(m)
	a.registerSettings(m)
	a.registerTracking(m)
	a.registerKeys(m)
	a.registerAI(m)
	a.registerAgents(m)
	a.registerAgentKnowledge(m)
	a.registerAgentProviders(m)
	a.registerAgentControl(m)
	a.registerAgentExecution(m)
	a.registerGraphQL(m)
	a.registerAgentReports(m)
	a.registerMCP(m)
	a.registerDomain(m)
	a.registerFindingOps(m)
	a.registerSBOM(m)
	a.registerCampaigns(m)
	a.registerOperations(m)
	a.registerRemediation(m)
	a.registerNotifications(m)
	a.registerNotificationAutomation(m)
	a.registerNotificationOperations(m)
	a.registerWorkflowAutomation(m)
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "API를 찾을 수 없습니다") })
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "허용되지 않는 요청입니다")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if !fs.ValidPath(path) {
			http.NotFound(w, r)
			return
		}
		if _, e := fs.Stat(a.Assets, path); e != nil {
			if strings.Contains(path, ".") {
				http.NotFound(w, r)
				return
			}
			r.URL.Path = "/"
		}
		http.FileServer(http.FS(a.Assets)).ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		defer func() {
			if e := recover(); e != nil {
				slog.Error("request panic", "path", r.URL.Path)
				fail(w, 500, "요청 처리 중 오류가 발생했습니다")
			}
		}()
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		m.ServeHTTP(w, r)
	})
}
