-- Hunter-owned compatibility schema for the pinned sqlc core queries.
-- No upstream authentication, extension, container, or network service tables.
CREATE TABLE IF NOT EXISTS flows (
 id BIGSERIAL PRIMARY KEY, hunter_run_id TEXT NOT NULL UNIQUE, service_id TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'created', deleted_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tasks (
 id BIGSERIAL PRIMARY KEY, status TEXT NOT NULL DEFAULT 'created', title TEXT NOT NULL DEFAULT '',
 input TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '', flow_id BIGINT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS subtasks (
 id BIGSERIAL PRIMARY KEY, status TEXT NOT NULL DEFAULT 'created', title TEXT NOT NULL DEFAULT '',
 description TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '', context TEXT NOT NULL DEFAULT '',
 task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS msgchains (
 id BIGSERIAL PRIMARY KEY, type TEXT NOT NULL, model TEXT NOT NULL DEFAULT '', model_provider TEXT NOT NULL DEFAULT '',
 usage_in BIGINT NOT NULL DEFAULT 0, usage_out BIGINT NOT NULL DEFAULT 0, chain JSONB NOT NULL DEFAULT '[]',
 flow_id BIGINT NOT NULL REFERENCES flows(id) ON DELETE CASCADE, task_id BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
 subtask_id BIGINT REFERENCES subtasks(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 usage_cache_in BIGINT NOT NULL DEFAULT 0, usage_cache_out BIGINT NOT NULL DEFAULT 0,
 usage_cost_in DOUBLE PRECISION NOT NULL DEFAULT 0, usage_cost_out DOUBLE PRECISION NOT NULL DEFAULT 0,
 duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS msglogs (
 id BIGSERIAL PRIMARY KEY, type TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '',
 flow_id BIGINT NOT NULL REFERENCES flows(id) ON DELETE CASCADE, task_id BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
 subtask_id BIGINT REFERENCES subtasks(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 result_format TEXT NOT NULL DEFAULT 'plain', thinking TEXT
);
CREATE INDEX IF NOT EXISTS core_tasks_flow_idx ON tasks(flow_id);
CREATE INDEX IF NOT EXISTS core_subtasks_task_idx ON subtasks(task_id);
CREATE INDEX IF NOT EXISTS core_msgchains_flow_idx ON msgchains(flow_id,task_id,type,id);
CREATE INDEX IF NOT EXISTS core_msglogs_task_idx ON msglogs(task_id,id);
