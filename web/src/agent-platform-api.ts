import { api, type Row } from "./api";
import { newPlatformID } from "./agent-platform-state";
export type PlatformDocument<T> = { config: T; updated_at: string };
export type ModelProvider = {
  id: string;
  name: string;
  type: "openai" | "anthropic" | "gemini" | "ollama";
  enabled: boolean;
  base_url: string;
  model: string;
  api_key: string;
  api_key_configured?: boolean;
  clear_api_key?: boolean;
  context_window: number;
  max_tokens: number;
  priority: number;
  timeout_seconds: number;
  failure_threshold: number;
  cooldown_seconds: number;
};
export type ModelsConfig = {
  enabled: boolean;
  providers: ModelProvider[];
  role_providers: Record<string, string[]>;
};
export type Exporter = {
  id: string;
  name: string;
  type: "otlp" | "langfuse";
  enabled: boolean;
  endpoint: string;
  signals: string[];
  api_key: string;
  api_key_configured?: boolean;
  clear_api_key?: boolean;
  public_key: string;
  priority: number;
  failover_group: string;
  timeout_seconds: number;
  failure_threshold: number;
  cooldown_seconds: number;
};
export type ObservabilityConfig = {
  enabled: boolean;
  exporters: Exporter[];
  dashboards: { name: string; url: string }[];
  max_attempts: number;
  retention_days: number;
};
export type PlatformStatusResponse = {
  items: Row[];
  summary?: Record<string, number>;
  recent?: Row[];
};
export const platformAPI = {
  get: <T>(group: string) =>
    api<PlatformDocument<T>>("/api/agent-platform/" + group),
  save: <T>(group: string, config: T, revision: string) => {
    if (!revision) throw new Error("최신 설정을 다시 불러오세요.");
    return api<PlatformDocument<T>>("/api/agent-platform/" + group, {
      method: "PUT",
      body: JSON.stringify({ config, expected_updated_at: revision }),
    });
  },
  test: (group: string, body: Row) =>
    api<Row>("/api/agent-platform/" + group + "/test", {
      method: "POST",
      body: JSON.stringify(body),
    }),
};
export const newModelProvider = (): ModelProvider => ({
  id: newPlatformID(),
  name: "",
  type: "openai",
  enabled: false,
  base_url: "",
  model: "",
  api_key: "",
  context_window: 32768,
  max_tokens: 4096,
  priority: 10,
  timeout_seconds: 120,
  failure_threshold: 3,
  cooldown_seconds: 30,
});
export type SearchProvider = {
  id: string;
  name: string;
  kind:
    | "duckduckgo"
    | "google_cse"
    | "tavily"
    | "perplexity"
    | "searxng"
    | "http_json";
  enabled: boolean;
  priority: number;
  endpoint: string;
  api_key: string;
  api_key_configured?: boolean;
  clear_api_key?: boolean;
  cx: string;
  timeout_seconds: number;
  method: "GET" | "POST";
  results_path: string;
  title_path: string;
  url_path: string;
  snippet_path: string;
};
export type SearchConfig = {
  enabled: boolean;
  max_results: number;
  total_timeout_seconds: number;
  failure_threshold: number;
  cooldown_seconds: number;
  providers: SearchProvider[];
};
export type MemoryConnection = {
  enabled: boolean;
  endpoint: string;
  model?: string;
  api_key: string;
  api_key_configured?: boolean;
  clear_api_key?: boolean;
  timeout_seconds: number;
};
export type MemoryConfig = {
  max_results: number;
  vector_backend: "auto" | "database" | "pgvector";
  failure_threshold: number;
  cooldown_seconds: number;
  embedding: MemoryConnection;
  graphiti: MemoryConnection;
};
export type KnowledgeStatus = {
  providers: Row[];
  local_available?: boolean;
  pgvector_available?: boolean;
};
export const newSearchProvider = (): SearchProvider => ({
  id: newPlatformID(),
  name: "",
  kind: "http_json",
  enabled: false,
  priority: 1,
  endpoint: "",
  api_key: "",
  cx: "",
  timeout_seconds: 10,
  method: "GET",
  results_path: "results",
  title_path: "title",
  url_path: "url",
  snippet_path: "snippet",
});
export type ExecutionServer = {
  id: string;
  name: string;
  enabled: boolean;
  endpoint: string;
  ca_pem: string;
  client_cert_pem: string;
  client_key_pem: string;
  client_key_pem_configured?: boolean;
  clear_client_key_pem?: boolean;
  priority: number;
  network: string;
  service_network?: string;
  timeout_seconds: number;
  failure_threshold: number;
  cooldown_seconds: number;
};
export type ExecutionProfile = {
  id: string;
  name: string;
  enabled: boolean;
  kind: "http_headers" | "tls_certificate" | "tcp_connect";
  image: string;
  server_ids: string[];
};
export type ExecutionConfig = {
  enabled: boolean;
  servers: ExecutionServer[];
  profiles: ExecutionProfile[];
  max_concurrent: number;
  timeout_seconds: number;
};
