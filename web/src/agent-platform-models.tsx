import { useRef, useState } from "react";
import {
  Alert,
  Button,
  Group,
  Modal,
  MultiSelect,
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
import { api, success, useData, useSession } from "./api";
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
  ProviderPriority,
} from "./agent-platform-ui";
import {
  modelRoles,
  modelTypes,
  providerEndpoint,
  safeProviderFields,
  secretChange,
  type SecretChoice,
} from "./agent-platform-state";
import {
  newModelProvider,
  platformAPI,
  type ModelProvider,
  type ModelsConfig,
  type PlatformDocument,
  type PlatformStatusResponse,
} from "./agent-platform-api";
function normalized(config: ModelsConfig): ModelsConfig {
  return {
    enabled: !!config.enabled,
    providers: (config.providers || []).map((row) => ({
      ...newModelProvider(),
      ...row,
      api_key: "",
    })),
    role_providers: Object.fromEntries(
      Object.entries(config.role_providers || {}).map(([key, ids]) => [
        key,
        ids || [],
      ]),
    ),
  };
}
function configBody(config: ModelsConfig) {
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
export function PlatformModels() {
  const { refreshConfig } = useSession();
  const data = useData<PlatformDocument<ModelsConfig>>(
      "/api/agent-platform/models",
    ),
    status = useData<PlatformStatusResponse>(
      "/api/agent-platform/models/status",
    );
  const [editor, setEditor] = useState<ModelProvider | null | undefined>(),
    [general, setGeneral] = useState(false),
    [role, setRole] = useState<string | null | undefined>(),
    [probe, setProbe] = useState<ModelProvider | null>(null),
    [remove, setRemove] = useState<ModelProvider | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const doc = data.data
    ? { ...data.data, config: normalized(data.data.config) }
    : null;
  async function reload() {
    await Promise.all([data.reload(), status.reload(), refreshConfig()]);
  }
  async function save(config: ModelsConfig, revision: string) {
    await platformAPI.save("models", configBody(config), revision);
    success("모델 연동 설정을 저장했습니다.");
    await reload();
  }
  const columns: WorkflowColumn<ModelProvider>[] = [
    { key: "priority", label: "기본 우선순위", value: (r) => r.priority },
    {
      key: "name",
      label: "제공자",
      value: (r) => r.name,
      render: (r) => (
        <Button variant="subtle" onClick={() => setEditor(r)}>
          {r.name}
        </Button>
      ),
    },
    {
      key: "type",
      label: "연동 방식",
      value: (r) => modelTypes.find((v) => v.value === r.type)?.label || r.type,
    },
    { key: "model", label: "모델", value: (r) => r.model },
    {
      key: "enabled",
      label: "사용",
      value: (r) => (r.enabled ? "사용 중" : "사용 안 함"),
      render: (r) => (
        <PlatformStatus status={r.enabled ? "enabled" : "disabled"} />
      ),
    },
    {
      key: "limits",
      label: "컨텍스트 / 출력",
      value: (r) =>
        `${r.context_window.toLocaleString()} / ${r.max_tokens.toLocaleString()}`,
    },
    {
      key: "health",
      label: "연결 상태",
      value: (r) =>
        String(
          status.data?.items?.find((v) => v.provider_id === r.id)?.status ||
            "미확인",
        ),
      render: (r) => (
        <ProviderHealth
          row={status.data?.items?.find((v) => v.provider_id === r.id)}
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
            size="compact-sm"
            variant="default"
            onClick={() => setEditor(r)}
          >
            수정
          </Button>
          <Button size="compact-sm" variant="light" onClick={() => setProbe(r)}>
            연결 시험
          </Button>
          <Button
            size="compact-sm"
            variant="subtle"
            color="red"
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
            title="모델 제공자와 역할별 선택"
            enabled={doc.config.enabled}
            description="공통 우선순위와 역할별 대체 순서를 관리합니다. 지정한 연동이 모두 실패하면 실행 근거를 보존한 대기로 전환합니다."
            onEdit={() => setGeneral(true)}
          >
            <AutomationValues
              items={[
                {
                  label: "등록 모델",
                  value: `${doc.config.providers.length}개`,
                },
                {
                  label: "역할별 경로",
                  value: `${Object.keys(doc.config.role_providers).length}개`,
                },
                { label: "응답 처리", value: "스트리밍 · 최대 262,144 토큰" },
              ]}
            />
          </AutomationSection>
          <Alert color="teal">
            기존 <Link to="/admin/settings?tab=ai">서비스 AI 설정</Link>은
            유지됩니다. 여러 제공자 사용을 끄면 기존 AI 설정을 사용합니다. 켜면
            새 제공자 목록과 선택한 모델의 실제 컨텍스트·출력 한도를 함께
            확인하세요. 우선순위 숫자가 작을수록 먼저 선택합니다.
          </Alert>
          <Group justify="space-between">
            <Text fw={700}>모델 제공자</Text>
            <Button
              leftSection={<IconPlus size={16} />}
              onClick={() => setEditor(null)}
              disabled={doc.config.providers.length >= 20}
            >
              모델 제공자 추가
            </Button>
          </Group>
          <WorkflowTable
            rows={doc.config.providers}
            columns={columns}
            name="모델 제공자"
            rowKey={(r) => r.id}
            reload={reload}
            defaultSort={{ key: "priority", direction: "asc" }}
            preferenceContext="platform-models"
            empty="등록한 모델이 없습니다. 사내 OpenAI 호환 또는 사용할 모델 제공자를 추가하세요."
          />
          <Group justify="space-between">
            <Text fw={700}>역할별 우선 모델</Text>
            <Button variant="light" onClick={() => setRole(null)}>
              역할별 모델 지정
            </Button>
          </Group>
          <Stack>
            {Object.entries(doc.config.role_providers).map(([key, ids]) => (
              <AutomationSection
                key={key}
                title={modelRoles.find((v) => v.value === key)?.label || key}
                onEdit={() => setRole(key)}
              >
                <Text>
                  {ids
                    .map(
                      (id) =>
                        doc.config.providers.find((v) => v.id === id)?.name ||
                        id,
                    )
                    .join(" → ") || "공통 우선순위 적용"}
                </Text>
              </AutomationSection>
            ))}
            {!Object.keys(doc.config.role_providers).length && (
              <Text c="dimmed">
                역할별 경로를 지정하지 않으면 공통 선택 순서를 사용합니다.
              </Text>
            )}
          </Stack>
          {general && (
            <AutomationEditor
              title="모델 제공자 기본 설정"
              value={doc.config}
              revision={doc.updated_at}
              onClose={() => setGeneral(false)}
              onSave={(value, revision) => save(value, revision)}
              loadLatest={async () => {
                const latest = await platformAPI.get<ModelsConfig>("models");
                return {
                  value: normalized(latest.config),
                  revision: latest.updated_at,
                };
              }}
            >
              {(value, onChange) => (
                <Switch
                  label="여러 모델 제공자 사용"
                  checked={value.enabled}
                  onChange={(e) =>
                    onChange({ ...value, enabled: e.currentTarget.checked })
                  }
                />
              )}
            </AutomationEditor>
          )}
          {editor !== undefined && (
            <ModelEditor
              source={editor}
              document={doc}
              onClose={() => setEditor(undefined)}
              onSaved={reload}
            />
          )}
          {role !== undefined && (
            <RoleEditor
              source={role}
              document={doc}
              onClose={() => setRole(undefined)}
              onSaved={reload}
            />
          )}
          {probe && (
            <PlatformProbe
              name={probe.name}
              description="저장한 모델에 짧은 합성 요청을 보내 스트리밍 응답과 토큰 정보를 확인합니다. 응답 본문과 키 원문은 시험 결과에 표시하지 않습니다."
              onClose={() => setProbe(null)}
              onTest={async () => {
                const result = await platformAPI.test("models", {
                  provider_id: probe.id,
                  expected_updated_at: doc.updated_at,
                });
                await status.reload();
                return result;
              }}
            />
          )}
          <Modal
            opened={!!remove}
            title="모델 제공자 삭제"
            onClose={() => {
              if (!busy) setRemove(null);
            }}
            zIndex={350}
            withCloseButton={!busy}
          >
            <Stack>
              <Text>
                ‘{remove?.name}’을 삭제하고 이 제공자를 참조하는 역할별 경로에서
                제외합니다.
              </Text>
              {error && <Alert color="red">{error}</Alert>}
              <Group justify="flex-end">
                <Button
                  variant="default"
                  disabled={busy}
                  onClick={() => setRemove(null)}
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
                            (r) => r.id !== remove.id,
                          ),
                          role_providers: Object.fromEntries(
                            Object.entries(doc.config.role_providers).map(
                              ([key, ids]) => [
                                key,
                                ids.filter((id) => id !== remove.id),
                              ],
                            ),
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
function ModelEditor({
  source,
  document,
  onClose,
  onSaved,
}: {
  source: ModelProvider | null;
  document: PlatformDocument<ModelsConfig>;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document);
  type Draft = { provider: ModelProvider; mode: SecretChoice; secret: string };
  const initial: Draft = {
    provider: source ? { ...source } : newModelProvider(),
    mode: "keep",
    secret: "",
  };
  return (
    <AutomationEditor
      title={source ? "모델 제공자 수정" : "모델 제공자 추가"}
      value={initial}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (value, revision) => {
        const provider = {
          ...safeProviderFields(value.provider),
          ...secretChange(value.mode, value.secret),
        } as ModelProvider;
        provider.name = provider.name.trim();
        provider.model = provider.model.trim();
        provider.base_url = providerEndpoint(provider.base_url);
        if (!provider.name || !provider.model)
          throw new Error("제공자 이름과 모델 이름을 입력하세요.");
        if (provider.max_tokens > provider.context_window)
          throw new Error("최대 출력 토큰은 컨텍스트 한도를 넘을 수 없습니다.");
        if (
          provider.enabled &&
          ["anthropic", "gemini"].includes(provider.type) &&
          (value.mode === "clear" ||
            (!value.provider.api_key_configured && value.mode !== "replace"))
        )
          throw new Error("이 제공자를 활성화하려면 API 키를 설정하세요.");
        const config = normalized(base.current.config);
        config.providers = source
          ? config.providers.map((row) =>
              row.id === source.id ? provider : row,
            )
          : [...config.providers, provider];
        await platformAPI.save("models", configBody(config), revision);
        success("모델 제공자를 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = await platformAPI.get<ModelsConfig>("models");
        base.current = latest;
        const provider = source
          ? normalized(latest.config).providers.find(
              (row) => row.id === source.id,
            )
          : newModelProvider();
        if (!provider)
          throw new Error(
            "제공자가 삭제되었습니다. 작성 내용을 확인하고 창을 닫아 주세요.",
          );
        return {
          value: { provider, mode: "keep" as SecretChoice, secret: "" },
          revision: latest.updated_at,
        };
      }}
    >
      {(draft, set) => {
        const value = draft.provider,
          update = (change: Partial<ModelProvider>) =>
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
                label="모델 연동 방식"
                value={value.type}
                data={modelTypes}
                onChange={(type) =>
                  update({ type: (type || "openai") as ModelProvider["type"] })
                }
              />
            </SimpleGrid>
            <Switch
              label="이 모델 제공자 사용"
              checked={value.enabled}
              onChange={(e) => update({ enabled: e.currentTarget.checked })}
            />
            <TextInput
              label="API 기본 주소"
              required
              value={value.base_url}
              placeholder={
                value.type === "ollama"
                  ? "http://llm.internal:11434"
                  : value.type === "gemini"
                    ? "https://model.internal/v1beta"
                    : "https://model.internal/v1"
              }
              onChange={(e) => update({ base_url: e.currentTarget.value })}
              description="사내 주소를 직접 입력하세요. 주소에 인증 정보나 쿼리 문자열을 넣지 마세요."
            />
            <TextInput
              label="모델 이름"
              required
              value={value.model}
              onChange={(e) => update({ model: e.currentTarget.value })}
            />
            <PlatformSecret
              mode={draft.mode}
              value={draft.secret}
              configured={value.api_key_configured}
              onMode={(mode) => set({ ...draft, mode, secret: "" })}
              onValue={(secret) => set({ ...draft, secret })}
            />
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <NumberInput
                label="기본 우선순위"
                min={0}
                max={1000}
                value={value.priority}
                onChange={(v) => update({ priority: Number(v) })}
              />
              <NumberInput
                label="응답 제한 시간 (초)"
                min={5}
                max={600}
                value={value.timeout_seconds}
                onChange={(v) => update({ timeout_seconds: Number(v) })}
              />
              <NumberInput
                label="연속 실패 기준"
                min={1}
                max={20}
                value={value.failure_threshold}
                onChange={(v) => update({ failure_threshold: Number(v) })}
              />
              <NumberInput
                label="회복 대기 시간 (초)"
                min={5}
                max={3600}
                value={value.cooldown_seconds}
                onChange={(v) => update({ cooldown_seconds: Number(v) })}
              />
              <NumberInput
                label="컨텍스트 한도 (토큰)"
                min={1024}
                max={262144}
                value={value.context_window}
                onChange={(v) => update({ context_window: Number(v) })}
              />
              <NumberInput
                label="최대 출력 토큰"
                min={1}
                max={262144}
                value={value.max_tokens}
                onChange={(v) => update({ max_tokens: Number(v) })}
              />
            </SimpleGrid>
            <Text size="sm" c="dimmed">
              내부 무인증 OpenAI 호환·Ollama는 키를 비워 둘 수 있습니다.
              Anthropic·Gemini를 활성화하려면 키가 필요합니다.
            </Text>
          </Stack>
        );
      }}
    </AutomationEditor>
  );
}
function RoleEditor({
  source,
  document,
  onClose,
  onSaved,
}: {
  source: string | null;
  document: PlatformDocument<ModelsConfig>;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document);
  return (
    <AutomationEditor
      title="역할별 우선 모델 지정"
      value={{
        role: source || "default",
        ids: source
          ? document.config.role_providers[source] || []
          : ([] as string[]),
      }}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (value, revision) => {
        const config = normalized(base.current.config);
        if (value.ids.length) config.role_providers[value.role] = value.ids;
        else delete config.role_providers[value.role];
        await platformAPI.save("models", configBody(config), revision);
        success("역할별 모델 순서를 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = await platformAPI.get<ModelsConfig>("models");
        base.current = latest;
        return {
          value: {
            role: source || "default",
            ids: source ? latest.config.role_providers?.[source] || [] : [],
          },
          revision: latest.updated_at,
        };
      }}
    >
      {(value, set) => {
        const options = base.current.config.providers.map((row) => ({
          value: row.id,
          label: row.name + (row.enabled ? "" : " · 사용 안 함"),
        }));
        return (
          <Stack gap="lg">
            <Select
              label="에이전트 역할"
              searchable
              disabled={!!source}
              value={value.role}
              data={modelRoles}
              onChange={(role) =>
                set({
                  role: role || "default",
                  ids:
                    base.current.config.role_providers?.[role || "default"] ||
                    [],
                })
              }
            />
            <MultiSelect
              label="우선 사용할 모델"
              searchable
              value={value.ids}
              data={options}
              onChange={(ids) => set({ ...value, ids })}
            />
            <ProviderPriority
              value={value.ids}
              options={options}
              onChange={(ids) => set({ ...value, ids })}
            />
            <Alert color="teal">
              위에서부터 순서대로 선택합니다. 비워서 저장하면 이 역할의 별도
              경로를 제거하고 공통 선택 순서를 사용합니다. 실제 대체 여부는
              서버의 응답·실패 분류를 따릅니다.
            </Alert>
          </Stack>
        );
      }}
    </AutomationEditor>
  );
}
