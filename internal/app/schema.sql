CREATE TABLE IF NOT EXISTS users(id text PRIMARY KEY,username text NOT NULL UNIQUE,name text NOT NULL,role text NOT NULL,password_hash text NOT NULL DEFAULT '',oidc_subject text UNIQUE,disabled boolean NOT NULL DEFAULT false,preferences jsonb NOT NULL DEFAULT '{}',created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS resources(id text PRIMARY KEY,kind text NOT NULL,owner_id text NOT NULL,data jsonb NOT NULL DEFAULT '{}',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS resources_kind ON resources(kind);
CREATE INDEX IF NOT EXISTS resources_owner ON resources(owner_id);
CREATE TABLE IF NOT EXISTS settings(key text PRIMARY KEY,value jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS audit_logs(id text PRIMARY KEY,user_id text NOT NULL,username text NOT NULL,action text NOT NULL,target text NOT NULL,detail jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions(token_hash text PRIMARY KEY,user_id text NOT NULL REFERENCES users(id),expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS api_keys(id text PRIMARY KEY,user_id text NOT NULL REFERENCES users(id),name text NOT NULL,prefix text NOT NULL,token_hash text NOT NULL UNIQUE,scopes jsonb NOT NULL,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),last_used_at timestamptz,revoked_at timestamptz);
CREATE TABLE IF NOT EXISTS oidc_states(state_hash text PRIMARY KEY,nonce text NOT NULL,verifier text NOT NULL,expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts(identity text PRIMARY KEY,failures integer NOT NULL DEFAULT 0,window_start timestamptz NOT NULL DEFAULT now());

ALTER TABLE users ADD COLUMN IF NOT EXISTS team text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS oidc_states_expiry ON oidc_states(expires_at);
CREATE INDEX IF NOT EXISTS login_attempts_expiry ON login_attempts(window_start);
