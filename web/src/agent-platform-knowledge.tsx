import { useRef, useState } from "react";
import {
  Accordion,
  Alert,
  Anchor,
  Badge,
  Button,
  Group,
  Modal,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { success, useData, type Row } from "./api";
import { LoadState } from "./components";
import { WorkflowTable, type WorkflowColumn } from "./workflow-components";
import {
  AutomationEditor,
  AutomationSection,
  AutomationValues,
} from "./automation-ui";
import {
  PlatformProbe,
  PlatformSecret,
  PlatformStatus,
  ProviderHealth,
} from "./agent-platform-ui";
import {
  providerEndpoint,
  safeProviderFields,
  secretChange,
  webAddress,
  type SecretChoice,
} from "./agent-platform-state";
import {
  platformAPI,
  newSearchProvider,
  type SearchProvider,
  type SearchConfig,
  type MemoryConfig,
  type MemoryConnection,
  type PlatformDocument,
  type KnowledgeStatus,
} from "./agent-platform-api";
const searchKinds = [
  { value: "http_json", label: "사내 검색 API · JSON" },
  { value: "searxng", label: "SearXNG" },
  { value: "duckduckgo", label: "DuckDuckGo 요약" },
  { value: "google_cse", label: "Google 맞춤 검색" },
  { value: "tavily", label: "Tavily" },
  { value: "perplexity", label: "Perplexity" },
];
function normalizeSearch(config: SearchConfig): SearchConfig {
  return {
    ...config,
    providers: (config.providers || []).map((row) => ({
      ...newSearchProvider(),
      ...row,
      api_key: "",
    })),
  };
}
function searchBody(config: SearchConfig) {
  return {
    ...config,
    providers: config.providers.map((row) => ({
      ...safeProviderFields(row),
      ...(row.clear_api_key
        ? { clear_api_key: true }
        : row.api_key
          ? { api_key: row.api_key }
          : {}),
    })),
  };
}
export function PlatformSearch() {
  const data = useData<PlatformDocument<SearchConfig>>(
      "/api/agent-platform/search",
    ),
    status = useData<KnowledgeStatus>("/api/agent-platform/search/status");
  const [editor, setEditor] = useState<SearchProvider | null | undefined>(),
    [general, setGeneral] = useState(false),
    [probe, setProbe] = useState<SearchProvider | null>(null),
    [remove, setRemove] = useState<SearchProvider | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const doc = data.data
    ? { ...data.data, config: normalizeSearch(data.data.config) }
    : null;
  async function reload() {
    await Promise.all([data.reload(), status.reload()]);
  }
  async function save(config: SearchConfig, revision: string) {
    await platformAPI.save("search", searchBody(config), revision);
    success("검색 연동을 저장했습니다.");
    await reload();
  }
  const columns: WorkflowColumn<SearchProvider>[] = [
    { key: "priority", label: "우선순위", value: (r) => r.priority },
    {
      key: "name",
      label: "검색 제공자",
      value: (r) => r.name,
      render: (r) => (
        <Button variant="subtle" onClick={() => setEditor(r)}>
          {r.name}
        </Button>
      ),
    },
    {
      key: "kind",
      label: "연동 방식",
      value: (r) =>
        searchKinds.find((v) => v.value === r.kind)?.label || r.kind,
    },
    {
      key: "enabled",
      label: "사용",
      value: (r) => (r.enabled ? "사용 중" : "사용 안 함"),
      render: (r) => (
        <PlatformStatus status={r.enabled ? "enabled" : "disabled"} />
      ),
    },
    { key: "endpoint", label: "연결 주소", value: (r) => r.endpoint },
    {
      key: "timeout",
      label: "제한 시간",
      value: (r) => r.timeout_seconds + "초",
    },
    {
      key: "health",
      label: "연결 상태",
      value: (r) =>
        String(
          status.data?.providers?.find((v) => v.provider_id === r.id)?.state ||
            "미확인",
        ),
      render: (r) => (
        <ProviderHealth
          row={status.data?.providers?.find((v) => v.provider_id === r.id)}
        />
      ),
    },
    {
      key: "actions",
      label: "관리",
      value: () => "",
      render: (r) => (
        <Group wrap="nowrap">
          <Button
            variant="default"
            size="compact-sm"
            onClick={() => setEditor(r)}
          >
            수정
          </Button>
          <Button variant="light" size="compact-sm" onClick={() => setProbe(r)}>
            연결 시험
          </Button>
          <Button
            variant="subtle"
            color="red"
            size="compact-sm"
            onClick={() => {
              setRemove(r);
              setError("");
            }}
          >
            삭제
          </Button>
        </Group>
      ),
    },
  ];
  return (
    <Stack gap="lg">
      <LoadState
        loading={data.loading}
        error={data.error}
        reload={data.reload}
      />
      <LoadState loading={false} error={status.error} reload={status.reload} />
      {doc && (
        <>
          <AutomationSection
            title="출처가 있는 검색 근거"
            enabled={doc.config.enabled}
            description="우선순위에 따라 검색 제공자를 사용하고, 검색할 수 없으면 내부 서비스·발견 근거로 작업을 이어갑니다."
            onEdit={() => setGeneral(true)}
          >
            <AutomationValues
              items={[
                {
                  label: "등록 제공자",
                  value: doc.config.providers.length + "개",
                },
                {
                  label: "최대 검색 결과",
                  value: doc.config.max_results + "개",
                },
                {
                  label: "전체 검색 제한",
                  value: doc.config.total_timeout_seconds + "초",
                },
              ]}
            />
          </AutomationSection>
          <Alert color="teal">
            검색 결과는 확인할 근거 후보입니다. 실제 진단에는 기존
            서비스·범위·정책을 적용합니다. DuckDuckGo 연동은 Instant Answer
            요약이며 전체 웹 검색 결과를 보장하지 않습니다.
          </Alert>
          <Group justify="space-between">
            <Text fw={700}>검색 제공자 · 숫자가 작을수록 우선</Text>
            <Button
              leftSection={<IconPlus size={16} />}
              disabled={doc.config.providers.length >= 8}
              onClick={() => setEditor(null)}
            >
              검색 제공자 추가
            </Button>
          </Group>
          <WorkflowTable
            rows={doc.config.providers}
            columns={columns}
            name="검색 제공자"
            rowKey={(r) => r.id}
            reload={reload}
            defaultSort={{ key: "priority", direction: "asc" }}
            preferenceContext="platform-search"
            empty="등록한 검색 연동이 없습니다. 사내 검색 API나 사용할 제공자를 추가하세요."
          />
          {general && (
            <AutomationEditor
              title="검색 기본 설정"
              value={doc.config}
              revision={doc.updated_at}
              onClose={() => setGeneral(false)}
              onSave={save}
              loadLatest={async () => {
                const latest = await platformAPI.get<SearchConfig>("search");
                return {
                  value: normalizeSearch(latest.config),
                  revision: latest.updated_at,
                };
              }}
            >
              {(value, set) => (
                <Stack gap="lg">
                  <Switch
                    label="에이전트 검색 연동 사용"
                    checked={value.enabled}
                    onChange={(e) =>
                      set({ ...value, enabled: e.currentTarget.checked })
                    }
                  />
                  <SimpleGrid cols={{ base: 1, sm: 2 }}>
                    <NumberInput
                      label="최대 검색 결과"
                      min={1}
                      max={10}
                      value={value.max_results}
                      onChange={(v) =>
                        set({ ...value, max_results: Number(v) })
                      }
                    />
                    <NumberInput
                      label="전체 검색 제한 시간 (초)"
                      min={1}
                      max={120}
                      value={value.total_timeout_seconds}
                      onChange={(v) =>
                        set({ ...value, total_timeout_seconds: Number(v) })
                      }
                    />
                    <NumberInput
                      label="연속 실패 기준"
                      min={1}
                      max={20}
                      value={value.failure_threshold}
                      onChange={(v) =>
                        set({ ...value, failure_threshold: Number(v) })
                      }
                    />
                    <NumberInput
                      label="회복 대기 시간 (초)"
                      min={5}
                      max={3600}
                      value={value.cooldown_seconds}
                      onChange={(v) =>
                        set({ ...value, cooldown_seconds: Number(v) })
                      }
                    />
                  </SimpleGrid>
                </Stack>
              )}
            </AutomationEditor>
          )}
          {editor !== undefined && (
            <SearchEditor
              source={editor}
              document={doc}
              onClose={() => setEditor(undefined)}
              onSaved={reload}
            />
          )}
          {probe && (
            <KnowledgeProbe
              group="search"
              revision={doc.updated_at}
              id={probe.id}
              name={probe.name}
              onClose={() => setProbe(null)}
              onDone={status.reload}
            />
          )}
          <Modal
            opened={!!remove}
            title="검색 제공자 삭제"
            zIndex={350}
            onClose={() => {
              if (!busy) setRemove(null);
            }}
            withCloseButton={!busy}
          >
            <Stack>
              <Text>
                ‘{remove?.name}’ 검색 제공자를 삭제합니다. 이후 검색은 남은
                우선순위로 선택합니다.
              </Text>
              {error && <Alert color="red">{error}</Alert>}
              <Group justify="flex-end">
                <Button
                  variant="default"
                  onClick={() => setRemove(null)}
                  disabled={busy}
                >
                  취소
                </Button>
                <Button
                  color="red"
                  loading={busy}
                  onClick={async () => {
                    if (!remove || busy) return;
                    setBusy(true);
                    try {
                      await save(
                        {
                          ...doc.config,
                          providers: doc.config.providers.filter(
                            (row) => row.id !== remove.id,
                          ),
                        },
                        doc.updated_at,
                      );
                      setRemove(null);
                    } catch (e) {
                      setError((e as Error).message);
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  제공자 삭제
                </Button>
              </Group>
            </Stack>
          </Modal>
        </>
      )}
    </Stack>
  );
}
function SearchEditor({
  source,
  document,
  onClose,
  onSaved,
}: {
  source: SearchProvider | null;
  document: PlatformDocument<SearchConfig>;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document);
  return (
    <AutomationEditor
      title={source ? "검색 제공자 수정" : "검색 제공자 추가"}
      value={{
        provider: source ? { ...source } : newSearchProvider(),
        mode: "keep" as SecretChoice,
        secret: "",
      }}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (value, revision) => {
        const provider = {
          ...safeProviderFields(value.provider),
          ...secretChange(value.mode, value.secret),
        } as SearchProvider;
        if (!provider.name.trim()) throw new Error("제공자 이름을 입력하세요.");
        if (provider.endpoint.trim())
          provider.endpoint = providerEndpoint(provider.endpoint);
        else if (
          provider.enabled &&
          ["http_json", "searxng"].includes(provider.kind)
        )
          throw new Error("활성화할 사내 검색 API 주소를 입력하세요.");
        if (
          provider.enabled &&
          provider.kind === "google_cse" &&
          !provider.cx.trim()
        )
          throw new Error("Google 맞춤 검색 엔진 ID를 입력하세요.");
        const config = normalizeSearch(base.current.config);
        config.providers = source
          ? config.providers.map((row) =>
              row.id === source.id ? provider : row,
            )
          : [...config.providers, provider];
        await platformAPI.save("search", searchBody(config), revision);
        success("검색 제공자를 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = await platformAPI.get<SearchConfig>("search");
        base.current = latest;
        const provider = source
          ? normalizeSearch(latest.config).providers.find(
              (row) => row.id === source.id,
            )
          : newSearchProvider();
        if (!provider)
          throw new Error(
            "제공자가 삭제되었습니다. 입력을 확인하고 창을 닫아 주세요.",
          );
        return {
          value: { provider, mode: "keep" as SecretChoice, secret: "" },
          revision: latest.updated_at,
        };
      }}
    >
      {(draft, set) => {
        const value = draft.provider,
          update = (change: Partial<SearchProvider>) =>
            set({ ...draft, provider: { ...value, ...change } });
        return (
          <Stack gap="lg">
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label="제공자 이름"
                required
                value={value.name}
                onChange={(e) => update({ name: e.currentTarget.value })}
              />
              <Select
                label="검색 연동 방식"
                disabled={!!source}
                data={searchKinds}
                value={value.kind}
                onChange={(kind) =>
                  update({
                    kind: (kind || "http_json") as SearchProvider["kind"],
                  })
                }
              />
            </SimpleGrid>
            <Switch
              label="이 검색 제공자 사용"
              checked={value.enabled}
              onChange={(e) => update({ enabled: e.currentTarget.checked })}
            />
            <TextInput
              label="검색 API 주소"
              required={
                value.enabled && ["http_json", "searxng"].includes(value.kind)
              }
              value={value.endpoint}
              onChange={(e) => update({ endpoint: e.currentTarget.value })}
              placeholder={
                (
                  {
                    duckduckgo: "https://api.duckduckgo.com/",
                    google_cse: "https://www.googleapis.com/customsearch/v1",
                    tavily: "https://api.tavily.com/search",
                    perplexity: "https://api.perplexity.ai/search",
                  } as Record<string, string>
                )[value.kind] || "https://search.internal/search"
              }
              description={
                ["http_json", "searxng"].includes(value.kind)
                  ? "사내 검색 주소를 입력하세요."
                  : "비우면 위 공급자의 기본 주소를 저장합니다. 켜거나 연결 시험을 실행하기 전에는 검색하지 않습니다."
              }
            />
            {value.kind === "google_cse" && (
              <TextInput
                label="맞춤 검색 엔진 ID (cx)"
                required
                value={value.cx}
                onChange={(e) => update({ cx: e.currentTarget.value })}
              />
            )}
            <PlatformSecret
              mode={draft.mode}
              value={draft.secret}
              configured={value.api_key_configured}
              onMode={(mode) => set({ ...draft, mode, secret: "" })}
              onValue={(secret) => set({ ...draft, secret })}
            />
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <NumberInput
                label="우선순위"
                min={0}
                max={1000}
                value={value.priority}
                onChange={(v) => update({ priority: Number(v) })}
              />
              <NumberInput
                label="제한 시간 (초)"
                min={1}
                max={30}
                value={value.timeout_seconds}
                onChange={(v) => update({ timeout_seconds: Number(v) })}
              />
            </SimpleGrid>
            {value.kind === "http_json" && (
              <Accordion variant="separated">
                <Accordion.Item value="mapping">
                  <Accordion.Control>사내 JSON 응답 매핑</Accordion.Control>
                  <Accordion.Panel>
                    <Stack>
                      <Select
                        label="검색 요청 방식"
                        data={["GET", "POST"]}
                        value={value.method}
                        onChange={(method) =>
                          update({
                            method: (method || "GET") as "GET" | "POST",
                          })
                        }
                      />
                      {(
                        [
                          ["results_path", "결과 배열 경로"],
                          ["title_path", "제목 필드"],
                          ["url_path", "출처 주소 필드"],
                          ["snippet_path", "요약 필드"],
                        ] as const
                      ).map(([key, label]) => (
                        <TextInput
                          key={key}
                          label={label}
                          value={value[key]}
                          onChange={(e) =>
                            update({ [key]: e.currentTarget.value })
                          }
                        />
                      ))}
                    </Stack>
                  </Accordion.Panel>
                </Accordion.Item>
              </Accordion>
            )}
          </Stack>
        );
      }}
    </AutomationEditor>
  );
}
function memoryBody(config: MemoryConfig) {
  return {
    ...config,
    embedding: {
      ...safeProviderFields(config.embedding),
      ...(config.embedding.clear_api_key
        ? { clear_api_key: true }
        : config.embedding.api_key
          ? { api_key: config.embedding.api_key }
          : {}),
    },
    graphiti: {
      ...safeProviderFields(config.graphiti),
      ...(config.graphiti.clear_api_key
        ? { clear_api_key: true }
        : config.graphiti.api_key
          ? { api_key: config.graphiti.api_key }
          : {}),
    },
  };
}
export function PlatformMemory() {
  const data = useData<PlatformDocument<MemoryConfig>>(
      "/api/agent-platform/memory",
    ),
    status = useData<KnowledgeStatus>("/api/agent-platform/memory/status");
  const [edit, setEdit] = useState<"general" | "embedding" | "graphiti" | null>(
      null,
    ),
    [probe, setProbe] = useState<string | null>(null);
  const doc = data.data;
  async function reload() {
    await Promise.all([data.reload(), status.reload()]);
  }
  return (
    <Stack gap="lg">
      <LoadState
        loading={data.loading}
        error={data.error}
        reload={data.reload}
      />
      <LoadState loading={false} error={status.error} reload={status.reload} />
      {doc && (
        <>
          <AutomationSection
            title="로컬 원본과 선택 지식 연동"
            description="암호화한 로컬 메모리를 원본으로 유지합니다. 임베딩·원격 지식 연동이 실패해도 로컬 검색을 계속 사용할 수 있습니다."
            onEdit={() => setEdit("general")}
          >
            <AutomationValues
              items={[
                {
                  label: "로컬 메모리",
                  value: status.data?.local_available
                    ? "사용 가능"
                    : "상태 확인 중",
                },
                {
                  label: "검색 방식",
                  value: {
                    auto: "자동 선택",
                    database: "PostgreSQL 기본",
                    pgvector: "pgvector",
                  }[doc.config.vector_backend],
                },
                {
                  label: "pgvector 확장",
                  value: status.data
                    ? status.data.pgvector_available
                      ? "사용 가능"
                      : "현재 미설치"
                    : "상태 확인 중",
                },
                {
                  label: "최대 검색 결과",
                  value: doc.config.max_results + "개",
                },
              ]}
            />
          </AutomationSection>
          <Alert color="teal">
            에이전트의 메모리 사용 여부는{" "}
            <Link to="/admin/settings?tab=agents">에이전트 기본 설정</Link>에서
            관리합니다. 아래 원격 연동은 각각 켤 수 있습니다.
          </Alert>
          {(["embedding", "graphiti"] as const).map((key) => (
            <AutomationSection
              key={key}
              title={key === "embedding" ? "임베딩 모델" : "Graphiti 지식 서버"}
              enabled={doc.config[key].enabled}
              onEdit={() => setEdit(key)}
            >
              <AutomationValues
                items={[
                  {
                    label: "연결 주소",
                    value: doc.config[key].endpoint || "미설정",
                  },
                  {
                    label: "제한 시간",
                    value: doc.config[key].timeout_seconds + "초",
                  },
                  {
                    label: "모델",
                    value:
                      key === "embedding"
                        ? doc.config.embedding.model || "미설정"
                        : "원격 지식 관계",
                  },
                ]}
              />
              <Group justify="space-between" mt="lg">
                <ProviderHealth
                  row={status.data?.providers?.find(
                    (row) => row.provider_id === key,
                  )}
                />
                <Button variant="light" onClick={() => setProbe(key)}>
                  연결 시험
                </Button>
              </Group>
            </AutomationSection>
          ))}
          <Group>
            <Button variant="default" onClick={reload}>
              상태 새로고침
            </Button>
            <Button variant="light" onClick={() => setProbe("pgvector")}>
              데이터베이스 검색 확인
            </Button>
          </Group>
          {edit && (
            <MemoryEditor
              kind={edit}
              document={doc}
              onClose={() => setEdit(null)}
              onSaved={reload}
            />
          )}
          {probe && (
            <KnowledgeProbe
              group="memory"
              revision={doc.updated_at}
              id={probe}
              name={
                probe === "embedding"
                  ? "임베딩 모델"
                  : probe === "graphiti"
                    ? "Graphiti 지식 서버"
                    : "데이터베이스 검색"
              }
              onClose={() => setProbe(null)}
              onDone={status.reload}
            />
          )}
        </>
      )}
    </Stack>
  );
}
function MemoryEditor({
  kind,
  document,
  onClose,
  onSaved,
}: {
  kind: "general" | "embedding" | "graphiti";
  document: PlatformDocument<MemoryConfig>;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  return (
    <AutomationEditor
      title={
        kind === "general"
          ? "지식 메모리 기본 설정"
          : kind === "embedding"
            ? "임베딩 모델 설정"
            : "Graphiti 지식 서버 설정"
      }
      value={{
        config: document.config,
        mode: "keep" as SecretChoice,
        secret: "",
      }}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (value, revision) => {
        const config = structuredClone(value.config);
        if (kind !== "general") {
          const entry = config[kind];
          if (entry.enabled || entry.endpoint)
            entry.endpoint = providerEndpoint(entry.endpoint);
          Object.assign(entry, secretChange(value.mode, value.secret));
          if (kind === "embedding" && entry.enabled && !entry.model?.trim())
            throw new Error("임베딩 모델 이름을 입력하세요.");
        }
        await platformAPI.save("memory", memoryBody(config), revision);
        success("지식 메모리 설정을 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = await platformAPI.get<MemoryConfig>("memory");
        return {
          value: {
            config: latest.config,
            mode: "keep" as SecretChoice,
            secret: "",
          },
          revision: latest.updated_at,
        };
      }}
    >
      {(draft, set) => {
        const value = draft.config;
        if (kind === "general")
          return (
            <Stack gap="lg">
              <Select
                label="벡터 검색 방식"
                value={value.vector_backend}
                data={[
                  {
                    value: "auto",
                    label: "자동 · 사용할 수 있는 검색 방식 선택",
                  },
                  { value: "database", label: "PostgreSQL 기본 검색" },
                  { value: "pgvector", label: "pgvector 확장 사용" },
                ]}
                onChange={(v) =>
                  set({
                    ...draft,
                    config: {
                      ...value,
                      vector_backend: (v ||
                        "auto") as MemoryConfig["vector_backend"],
                    },
                  })
                }
              />
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <NumberInput
                  label="최대 검색 결과"
                  min={1}
                  max={10}
                  value={value.max_results}
                  onChange={(v) =>
                    set({
                      ...draft,
                      config: { ...value, max_results: Number(v) },
                    })
                  }
                />
                <NumberInput
                  label="연속 실패 기준"
                  min={1}
                  max={20}
                  value={value.failure_threshold}
                  onChange={(v) =>
                    set({
                      ...draft,
                      config: { ...value, failure_threshold: Number(v) },
                    })
                  }
                />
                <NumberInput
                  label="회복 대기 시간 (초)"
                  min={5}
                  max={3600}
                  value={value.cooldown_seconds}
                  onChange={(v) =>
                    set({
                      ...draft,
                      config: { ...value, cooldown_seconds: Number(v) },
                    })
                  }
                />
              </SimpleGrid>
            </Stack>
          );
        const entry = value[kind],
          update = (change: Partial<MemoryConnection>) =>
            set({
              ...draft,
              config: { ...value, [kind]: { ...entry, ...change } },
            });
        return (
          <Stack gap="lg">
            <Switch
              label="이 지식 연동 사용"
              checked={entry.enabled}
              onChange={(e) => update({ enabled: e.currentTarget.checked })}
            />
            <TextInput
              label={
                kind === "embedding"
                  ? "임베딩 API 전체 주소"
                  : "Graphiti 기본 주소"
              }
              required={entry.enabled}
              value={entry.endpoint}
              placeholder={
                kind === "embedding"
                  ? "https://llm.internal/v1/embeddings"
                  : "https://knowledge.internal"
              }
              onChange={(e) => update({ endpoint: e.currentTarget.value })}
            />
            {kind === "embedding" && (
              <TextInput
                label="임베딩 모델"
                value={entry.model || ""}
                onChange={(e) => update({ model: e.currentTarget.value })}
              />
            )}
            <PlatformSecret
              mode={draft.mode}
              value={draft.secret}
              configured={entry.api_key_configured}
              onMode={(mode) => set({ ...draft, mode, secret: "" })}
              onValue={(secret) => set({ ...draft, secret })}
            />
            <NumberInput
              label="응답 제한 시간 (초)"
              min={1}
              max={30}
              value={entry.timeout_seconds}
              onChange={(v) => update({ timeout_seconds: Number(v) })}
            />
          </Stack>
        );
      }}
    </AutomationEditor>
  );
}
function KnowledgeProbe({
  revision,
  group,
  id,
  name,
  onClose,
  onDone,
}: {
  group: "search" | "memory";
  revision: string;
  id: string;
  name: string;
  onClose: () => void;
  onDone: () => Promise<unknown>;
}) {
  const [query, setQuery] = useState("Hunter 합성 연결 시험");
  return (
    <PlatformProbe
      name={name}
      onClose={onClose}
      description={
        group === "search"
          ? "입력한 검색어를 저장한 검색 제공자에 보내 출처와 결과를 확인합니다. 개별 제공자를 먼저 활성화하세요. 전체 검색 기능은 꺼 둔 채 시험할 수 있습니다."
          : id === "graphiti"
            ? "합성 문장으로 Graphiti 검색 응답을 확인합니다. 비동기 지식 저장이나 인덱싱 완료를 뜻하지 않습니다."
            : "입력한 합성 문장으로 저장한 지식 연동의 연결 상태를 확인합니다. 임베딩·Graphiti는 해당 연동을 먼저 활성화하세요."
      }
      onTest={async () => {
        if (!query.trim()) throw new Error("시험 문장을 입력하세요.");
        if (new TextEncoder().encode(query).length > 2000)
          throw new Error("시험 문장은 UTF-8 기준 2,000바이트까지 입력하세요.");
        const result = await platformAPI.test(group, {
          provider_id: id,
          expected_updated_at: revision,
          query,
        });
        await onDone();
        return result;
      }}
      renderResult={(result) => (
        <Stack mt="md">
          {!!result.degraded && (
            <Alert color="yellow">
              이번 연동 시험에서 사용할 결과를 확인하지 못했습니다. 실제 작업은
              내부 서비스 자료·로컬 검색을 사용해 이어갈 수 있습니다.
            </Alert>
          )}
          {!!result.code && (
            <Text size="sm">결과 분류: {String(result.code)}</Text>
          )}
          {!!(result.details as Row)?.check_scope && (
            <Text size="sm">{String((result.details as Row).check_scope)}</Text>
          )}
          {Array.isArray(result.attempts) &&
            result.attempts.map((attempt: Row, index: number) => (
              <Text size="sm" key={index}>
                시험 {index + 1}: {String(attempt.code || "미확인")}
                {typeof attempt.elapsed_ms === "number"
                  ? ` · ${attempt.elapsed_ms} ms`
                  : ""}
              </Text>
            ))}
          {Array.isArray(result.items) &&
            result.items.map((row: Row, index: number) => (
              <div key={index} className="platform-form-section">
                {webAddress(row.url || "") ? (
                  <Anchor
                    href={webAddress(row.url)!}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {row.title || row.url}
                  </Anchor>
                ) : (
                  <Text fw={600}>{row.title || "검색 결과"}</Text>
                )}
                <Text mt="sm">{row.snippet || ""}</Text>
                {row.url && (
                  <Text size="sm" c="dimmed">
                    {row.url}
                  </Text>
                )}
              </div>
            ))}
        </Stack>
      )}
    >
      <TextInput
        label={group === "search" ? "시험 검색어" : "합성 시험 문장"}
        description="최대 2,000바이트 · 개인정보나 자격값을 입력하지 마세요."
        value={query}
        onChange={(e) => setQuery(e.currentTarget.value)}
      />
    </PlatformProbe>
  );
}
