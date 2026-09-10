# Hunter implementation contract

Go module github.com/hkjang/hunter. Go 1.26, React + Vite + Mantine. All default UI Korean. Version 1.0.0.
Only runtime environment: POSTGRES_DSN, BOOTSTRAP_ADMIN, BOOTSTRAP_ADMIN_PASSWORD, ENCRYPTION_KEY (32-byte base64). Listener :8080; Go serves web/dist (embedded by cmd build through internal/webassets later).

## Shared Go package internal/app
Root owns server.go, auth.go, settings.go, crypto.go, schema.sql, keys.go, ai.go, mcp.go. Domain agent owns domain*.go, worker*.go, integrations*.go, policy*.go, imports*.go and tests.
`type App struct { DB *pgxpool.Pool; Key []byte; Version string; ... }`
`type User struct { ID, Username, Name, Role string; Scopes []string }` JSON lower snake names (id username name role scopes).
`func (a *App) Routes() http.Handler` invokes `a.registerDomain(mux)` where mux *http.ServeMux.
`func (a *App) protect(scope string, h http.HandlerFunc) http.HandlerFunc` authenticates session cookie OR Bearer key, applies RBAC and API key scopes; use e.g. services:read, services:write, findings:read, findings:write, scans:read, scans:write, integrations:manage, admin:manage, audit:read. Admin gets all interactive scopes; API keys remain explicitly scope limited.
`func currentUser(r *http.Request) User` from context. `func jsonResponse(w http.ResponseWriter,status int,v any)`; `func fail(w http.ResponseWriter,status int,message string)` outputs {error:message}. `func decode(r *http.Request,v any) error` bounded JSON body.
`func newID() string` random UUID. `func (a *App) audit(r *http.Request, action, target string, detail any)` redacted audit entry.
`func (a *App) setting(ctx context.Context, group string) (map[string]any,error)` decrypted secret settings internal only.
`func (a *App) encrypt(s string)(string,error)` and decrypt.
DB tables root creates: users(id text PK, username text UNIQUE, name text, role text, password_hash text, oidc_subject text UNIQUE nullable, disabled boolean default false, preferences jsonb default '{}', created_at timestamptz default now()); resources(id text PK, kind text, owner_id text, data jsonb, created_at timestamptz default now(), updated_at timestamptz default now()); index(kind); audit_logs(id text PK, user_id text, username text, action text,target text,detail jsonb,created_at timestamptz default now()); settings(key text PK,value jsonb,updated_at timestamptz default now()); other auth tables root owned. Domain may migrate dedicated tables in `func (a *App) initDomain(ctx context.Context) error` called at startup and `func (a *App) StartWorkers(ctx context.Context)`.

## API
Session cookie HttpOnly/SameSite Lax; POST mutations with X-Hunter-CSRF: 1 required for cookie auth (Bearer exempt). Fetch wrapper ALWAYS add header to mutations. Same-origin strict origin check.
GET /api/health {status,version}; GET /api/auth/config {version,oidc_enabled,service_name}; POST /api/auth/login {username,password} -> {user}; GET /api/auth/me -> {user}; POST /api/auth/logout; GET /api/auth/oidc/login redirect; GET /api/auth/oidc/callback.
GET /api/settings/public {service_name,approval_enabled,ai_enabled,version}; GET /api/settings -> {general:{service_name,public_url},oidc:{enabled,issuer,client_id,client_secret,default_role},ai:{enabled,base_url,api_key,model,max_tokens,context_window},workflow:{approval_enabled},security:{session_hours,key_max_days},roles:{admin:[...],lead:[...],analyst:[...],viewer:[...]}} secrets returned empty + secret field configured boolean. PUT /api/settings/{group} -> object; PATCH not used. Secret empty means preserve, explicit clear_secret flag to clear.
GET /api/users -> array; POST /api/users {username,name,password,role}; PUT /api/users/{id} {name,role,disabled,password?}; GET /api/audit -> array.
GET /api/profile -> user with preferences; PUT /api/profile {name,preferences}; POST /api/profile/password {current_password,new_password}.
GET /api/keys -> array {id,name,prefix,scopes,expires_at,created_at,last_used_at,revoked_at}; POST /api/keys {name,scopes,expires_days} -> {key,token}; PUT /api/keys/{id} {name,scopes}; POST /api/keys/{id}/rotate -> {key,token}; DELETE /api/keys/{id}.
POST /api/ai/chat {messages:[{role,content}]} -> SSE OpenAI delta format (data: {choices:[{delta:{content}}]} then data: [DONE]); failures JSON before stream or SSE error. No autonomous tools.
POST /mcp JSON-RPC scoped key authentication, supported tools hunter_list_services, hunter_list_findings, hunter_request_scan; GET /api/openapi.json.

## Domain API (domain agent)
GET /api/dashboard -> {services,findings,open_findings,critical,scans,coverage,security_debt,by_severity:{critical:0,high:0,medium:0,low:0,info:0},recent_findings:[],recent_scans:[],...}.
GET /api/{services,findings,scans,policies,scopes,auth-profiles,integrations,discovery,reports,approvals,workers,events,scenarios,remediations} -> array (never envelope). POST /api/{kind} body; PUT /api/{kind}/{id}; DELETE /api/{kind}/{id}. Not every kind permits all CRUD: agent documents restrictions.
All resource outputs flattened {id,...data,owner_id,created_at,updated_at}.
Services: {name,url,environment:'staging'|'production'|'development',network,team,owner,criticality:'tier1'..'tier4',repository,image,description,targets:[{type,value}],approved:false}.
Findings: {title,service_id,severity:'critical'|'high'|'medium'|'low'|'info',status:'candidate'|'confirmed'|'in_progress'|'retest'|'resolved'|'inconclusive'|'false_positive'|'accepted',source,description,evidence,remediation,cve,component,fingerprint,assignee,due_date,contribution_points}.
Scans: POST {service_id,profile:'http-baseline'|'import-only'|'authorization',scope_id?,scenario_id?}; POST /api/scans/{id}/cancel; POST /api/scans/{id}/approve {decision:'approved'|'rejected',reason}; GET produces {status,profile,service_id,started_at,finished_at,result,logs,...}. Engine binaries not silently simulated: HTTP baseline is real bounded approved-target HEAD/GET security header inspection; integrations import scanner results JSON. External isolated workers via task claim/result endpoints can be added by domain agent.
Scopes: {name,service_id,allowed_hosts:[],allowed_paths:[],expires_at,approved,max_rps,max_requests,timeout_seconds}. A scope is ALWAYS needed for network probes; optional managerial workflow is separate from safety scope.
Policies: {name,description,production_active_scan:false,max_rps:1,max_concurrency:1,max_requests:20,timeout_seconds:30,allowed_methods:['GET','HEAD'],blocked_paths:[],enabled:true,...}.
Integrations: {name,type:'rest'|'postgres'|'webhook'|'scanner-import',endpoint,secret,config:{...},enabled}; POST /api/integrations/{id}/test; POST /api/integrations/{id}/sync; POST /api/integrations/{id}/webhook scoped bearer.
POST /api/imports {format:'trivy'|'nuclei'|'zap'|'sarif'|'gitleaks'|'generic',service_id,results:any} -> counts.
POST /api/emergency-stop {enabled:true|false,reason}. GET /api/graph -> {nodes:[{id,label,type}],edges:[{source,target,label}]}.
GET /api/reports/export?format=json|csv. Changes /api/events create scan under same policy and existing approved service only.

## Frontend routes
/login, /dashboard, /services, /findings, /scans, /graph, /scenarios, /reports, /contributions, /copilot, /approvals (only enabled), /admin/integrations, /admin/discovery, /admin/policies, /admin/scopes, /admin/auth-profiles, /admin/workers, /admin/users, /admin/audit, /admin/settings, /personal/profile, /personal/keys. Use React Router browser paths; Go SPA fallback preserves deep link refresh. Forms real API; empty initial data, no fake stats. Optional screenshot demo fixtures via scripts only never startup.
