import { useRef, useState } from "react";
import {
  Alert,
  Button,
  Group,
  MultiSelect,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@mantine/core";
import { IconExternalLink, IconPlus, IconTrash } from "@tabler/icons-react";
import { dateText, success, useData, type Row } from "./api";
import { LoadState } from "./components";
import {
  AutomationEditor,
  AutomationSection,
  AutomationValues,
} from "./automation-ui";
import { WorkflowTable, type WorkflowColumn } from "./workflow-components";
import {
  PlatformProbe,
  PlatformSecret,
  PlatformStatus,
  ProviderHealth,
} from "./agent-platform-ui";
import {
  newPlatformID,
  providerEndpoint,
  safeProviderFields,
  secretChange,
  webAddress,
  type SecretChoice,
} from "./agent-platform-state";
import {
  platformAPI,
  type Exporter,
  type ObservabilityConfig,
  type PlatformDocument,
  type PlatformStatusResponse,
} from "./agent-platform-api";

function normalize(value: ObservabilityConfig): ObservabilityConfig {
  return {
    ...value,
    exporters: (value.exporters || []).map((row) => ({
      ...row,
      api_key: "",
      signals: row.signals || [],
      failure_threshold: row.failure_threshold ?? 3,
      cooldown_seconds: row.cooldown_seconds ?? 30,
    })),
    dashboards: value.dashboards || [],
  };
}
function body(value: ObservabilityConfig) {
  return {
    ...value,
    exporters: value.exporters.map((row) => ({
      ...safeProviderFields(row),
      ...(row.api_key ? { api_key: row.api_key } : {}),
      ...(row.clear_api_key ? { clear_api_key: true } : {}),
    })),
  };
}
const fresh = (): Exporter => ({
  id: newPlatformID(),
  name: "",
  type: "otlp",
  enabled: false,
  endpoint: "",
  signals: ["traces"],
  api_key: "",
  public_key: "",
  priority: 10,
  failover_group: "",
  timeout_seconds: 10,
  failure_threshold: 3,
  cooldown_seconds: 30,
});
export function PlatformObservability() {
  const data = useData<PlatformDocument<ObservabilityConfig>>(
      "/api/agent-platform/observability",
    ),
    status = useData<PlatformStatusResponse>(
      "/api/agent-platform/observability/status",
    );
  const [edit, setEdit] = useState<Exporter | null | undefined>(undefined),
    [general, setGeneral] = useState(false),
    [dashboards, setDashboards] = useState(false),
    [probe, setProbe] = useState<Exporter | null>(null),
    [remove, setRemove] = useState<Exporter | null>(null);
  const config = data.data ? normalize(data.data.config) : null;
  async function reload() {
    await Promise.all([data.reload(), status.reload()]);
  }
  const columns: WorkflowColumn<Exporter>[] = [
    {
      key: "name",
      label: "수집 대상",
      value: (r) => r.name,
      render: (r) => (
        <Stack gap={3}>
          <Text fw={600}>{r.name}</Text>
          <Text size="sm" c="dimmed">
            {r.type === "langfuse" ? "Langfuse" : "OpenTelemetry OTLP"}
          </Text>
        </Stack>
      ),
    },
    {
      key: "signals",
      label: "보내는 신호",
      value: (r) => r.signals.join(" "),
      render: (r) => (
        <Text>
          {r.signals
            .map(
              (s) =>
                ({ traces: "추적", metrics: "지표", logs: "로그" })[s] || s,
            )
            .join(" · ")}
        </Text>
      ),
    },
    { key: "priority", label: "우선순위", value: (r) => r.priority },
    {
      key: "group",
      label: "대체 그룹",
      value: (r) => r.failover_group || "독립 전송",
    },
    {
      key: "enabled",
      label: "사용",
      value: (r) => (r.enabled ? "사용 중" : "사용 안 함"),
    },
    {
      key: "health",
      label: "연결 상태",
      value: (r) => r.id,
      render: (r) => (
        <ProviderHealth
          row={status.data?.items?.find(
            (s) => s.exporter_id === r.id || s.provider_id === r.id,
          )}
        />
      ),
    },
    {
      key: "actions",
      label: "관리",
      value: () => "",
      render: (r) => (
        <Group gap="xs">
          <Button variant="light" onClick={() => setEdit(r)}>
            설정
          </Button>
          <Button variant="default" onClick={() => setProbe(r)}>
            연결 시험
          </Button>
          <Button variant="subtle" color="red" onClick={() => setRemove(r)}>
            삭제
          </Button>
        </Group>
      ),
    },
  ];
  return (
    <Stack gap="xl" className="agent-platform">
      <LoadState
        loading={data.loading}
        error={data.error}
        reload={data.reload}
      />
      {config && data.data && (
        <>
          <AutomationSection
            title="관측 데이터 내보내기"
            description="운영 메타데이터를 비동기로 전달합니다. 수집 대상의 실패가 에이전트 진단을 중지시키지 않습니다."
            enabled={config.enabled}
            onEdit={() => setGeneral(true)}
          >
            <AutomationValues
              items={[
                { label: "최대 전송 시도", value: config.max_attempts + "회" },
                {
                  label: "대기 기록 보존",
                  value: config.retention_days + "일",
                },
                { label: "수집 대상", value: config.exporters.length + "개" },
              ]}
            />
            <Text mt="sm" size="sm" c="dimmed">
              모델의 전체 프롬프트·응답·자격값을 보내는 기능이 아닙니다. 승인된
              사내 수집 주소만 등록하세요.
            </Text>
          </AutomationSection>
          <Group justify="space-between">
            <Text fw={600}>수집 대상과 대체 순서</Text>
            <Button
              leftSection={<IconPlus size={17} />}
              disabled={config.exporters.length >= 10}
              onClick={() => setEdit(null)}
            >
              수집 대상 추가
            </Button>
          </Group>
          <Alert color="teal">
            같은 대체 그룹은 동일한 신호를 우선순위가 작은 순서로 전달합니다.
            그룹이 비어 있으면 각 대상에 독립적으로 보냅니다.
          </Alert>
          <WorkflowTable
            rows={config.exporters}
            columns={columns}
            name="관측 수집 대상"
            rowKey={(r) => r.id}
            defaultSort={{ key: "priority", direction: "asc" }}
            reload={reload}
            empty="사내 OTLP 또는 Langfuse 수집 대상을 등록하세요."
            preferenceContext="platform-observability"
          />
          <AutomationSection
            title="관측 서비스 바로가기"
            description="등록한 사내 대시보드는 새 탭에서 열립니다."
            onEdit={() => setDashboards(true)}
          >
            {config.dashboards.length ? (
              <Group>
                {config.dashboards.map((row, i) => {
                  const url = webAddress(row.url);
                  return url ? (
                    <Button
                      key={i}
                      component="a"
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      variant="default"
                      rightSection={<IconExternalLink size={16} />}
                    >
                      {row.name}
                    </Button>
                  ) : (
                    <Text key={i}>주소 확인 필요: {row.name}</Text>
                  );
                })}
              </Group>
            ) : (
              <Text c="dimmed">등록한 대시보드가 없습니다.</Text>
            )}
          </AutomationSection>
          <AutomationSection
            title="최근 전송 상태"
            description="서버가 반환한 최근 기록입니다. 연결 시험은 저장한 대상별로 명시적으로 실행하세요."
          >
            <LoadState
              loading={status.loading}
              error={status.error}
              reload={status.reload}
            />
            {status.data && (
              <>
                <AutomationValues
                  items={Object.entries(status.data.summary || {}).map(
                    ([key, value]) => ({
                      label:
                        (
                          {
                            queued: "전송 대기",
                            retry: "재시도 대기",
                            sent: "전송 완료",
                            failed: "실패",
                            discarded: "재시도 종료",
                          } as Record<string, string>
                        )[key] || key,
                      value,
                    }),
                  )}
                />
                <Stack mt="md">
                  {(status.data.recent || []).map((row) => (
                    <Group key={row.id} justify="space-between">
                      <Text size="sm">
                        {dateText(row.created_at)} · {row.attempts}회
                      </Text>
                      <PlatformStatus status={row.status} />
                    </Group>
                  ))}
                  {!status.data.recent?.length && (
                    <Text c="dimmed">아직 전송 기록이 없습니다.</Text>
                  )}
                </Stack>
              </>
            )}
          </AutomationSection>
        </>
      )}
      {general && data.data && (
        <AutomationEditor
          title="관측 내보내기 설정"
          value={normalize(data.data.config)}
          revision={data.data.updated_at}
          onClose={() => setGeneral(false)}
          onSave={async (v, r) => {
            await platformAPI.save("observability", body(v), r);
            success("관측 설정을 저장했습니다.");
            await reload();
          }}
          loadLatest={async () => {
            const v =
              await platformAPI.get<ObservabilityConfig>("observability");
            return { value: normalize(v.config), revision: v.updated_at };
          }}
        >
          {(v, set) => (
            <Stack>
              <Switch
                label="관측 데이터 내보내기 사용"
                checked={v.enabled}
                onChange={(e) =>
                  set({ ...v, enabled: e.currentTarget.checked })
                }
              />
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <NumberInput
                  label="최대 전송 시도"
                  min={1}
                  max={10}
                  value={v.max_attempts}
                  onChange={(n) => set({ ...v, max_attempts: Number(n) })}
                />
                <NumberInput
                  label="대기 기록 보존 (일)"
                  min={1}
                  max={90}
                  value={v.retention_days}
                  onChange={(n) => set({ ...v, retention_days: Number(n) })}
                />
              </SimpleGrid>
            </Stack>
          )}
        </AutomationEditor>
      )}
      {edit !== undefined && data.data && (
        <ExporterEditor
          source={edit}
          document={data.data}
          onClose={() => setEdit(undefined)}
          onSaved={reload}
        />
      )}
      {dashboards && data.data && (
        <AutomationEditor
          title="관측 서비스 바로가기 설정"
          value={normalize(data.data.config)}
          revision={data.data.updated_at}
          onClose={() => setDashboards(false)}
          onSave={async (v, r) => {
            v.dashboards = v.dashboards.map((d) => {
              const url = webAddress(d.url);
              if (!d.name.trim() || !url)
                throw new Error(
                  "대시보드 이름과 인증 정보가 없는 HTTP(S) 주소를 입력하세요.",
                );
              return { name: d.name.trim(), url };
            });
            await platformAPI.save("observability", body(v), r);
            await reload();
          }}
          loadLatest={async () => {
            const v =
              await platformAPI.get<ObservabilityConfig>("observability");
            return { value: normalize(v.config), revision: v.updated_at };
          }}
        >
          {(v, set) => (
            <Stack>
              {v.dashboards.map((row, i) => (
                <div className="platform-form-section" key={i}>
                  <TextInput
                    label={"대시보드 " + (i + 1) + " 이름"}
                    value={row.name}
                    onChange={(e) =>
                      set({
                        ...v,
                        dashboards: v.dashboards.map((d, j) =>
                          j === i ? { ...d, name: e.currentTarget.value } : d,
                        ),
                      })
                    }
                  />
                  <TextInput
                    mt="sm"
                    label={"대시보드 " + (i + 1) + " 주소"}
                    value={row.url}
                    onChange={(e) =>
                      set({
                        ...v,
                        dashboards: v.dashboards.map((d, j) =>
                          j === i ? { ...d, url: e.currentTarget.value } : d,
                        ),
                      })
                    }
                  />
                  <Button
                    mt="sm"
                    color="red"
                    variant="subtle"
                    onClick={() =>
                      set({
                        ...v,
                        dashboards: v.dashboards.filter((_, j) => j !== i),
                      })
                    }
                  >
                    이 대시보드 삭제
                  </Button>
                </div>
              ))}
              <Button
                variant="default"
                disabled={v.dashboards.length >= 10}
                onClick={() =>
                  set({
                    ...v,
                    dashboards: [...v.dashboards, { name: "", url: "" }],
                  })
                }
              >
                대시보드 추가
              </Button>
            </Stack>
          )}
        </AutomationEditor>
      )}
      {probe && data.data && (
        <PlatformProbe
          name={probe.name}
          onClose={() => setProbe(null)}
          description="저장된 수집 주소에 합성 운영 메타데이터를 보냅니다. 모델 대화 본문은 보내지 않습니다."
          onTest={async () => {
            const result = await platformAPI.test("observability", {
              exporter_id: probe.id,
              expected_updated_at: data.data!.updated_at,
            });
            await status.reload();
            return result;
          }}
        />
      )}
      {remove && data.data && (
        <AutomationEditor
          title="수집 대상 삭제"
          value={normalize(data.data.config)}
          revision={data.data.updated_at}
          submitLabel="수집 대상 삭제"
          onClose={() => setRemove(null)}
          onSave={async (v, r) => {
            await platformAPI.save(
              "observability",
              body({
                ...v,
                exporters: v.exporters.filter((row) => row.id !== remove.id),
              }),
              r,
            );
            await reload();
          }}
        >
          {() => (
            <Text>
              {remove.name} 수집 대상을 삭제합니다. 기존 전송 기록은 서버 보존
              정책을 따릅니다.
            </Text>
          )}
        </AutomationEditor>
      )}
    </Stack>
  );
}
function ExporterEditor({
  source,
  document,
  onClose,
  onSaved,
}: {
  source: Exporter | null;
  document: PlatformDocument<ObservabilityConfig>;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document);
  return (
    <AutomationEditor
      title={source ? "관측 수집 대상 설정" : "관측 수집 대상 추가"}
      value={{
        provider: source ? { ...source, api_key: "" } : fresh(),
        mode: "keep" as SecretChoice,
        secret: "",
      }}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (v, r) => {
        const provider = {
          ...safeProviderFields(v.provider),
          ...secretChange(v.mode, v.secret),
        } as Exporter;
        provider.name = provider.name.trim();
        provider.endpoint = providerEndpoint(provider.endpoint);
        if (!provider.name || !provider.signals.length)
          throw new Error("수집 대상 이름과 보낼 신호를 선택하세요.");
        if (provider.type === "langfuse") {
          provider.signals = ["traces"];
          if (
            provider.enabled &&
            (!provider.public_key.trim() ||
              v.mode === "clear" ||
              (!v.provider.api_key_configured && v.mode !== "replace"))
          )
            throw new Error(
              "Langfuse를 활성화하려면 공개 키와 비밀 API 키를 설정하세요.",
            );
        }
        const config = normalize(base.current.config);
        config.exporters = source
          ? config.exporters.map((row) =>
              row.id === source.id ? provider : row,
            )
          : [...config.exporters, provider];
        await platformAPI.save("observability", body(config), r);
        success("수집 대상을 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest =
          await platformAPI.get<ObservabilityConfig>("observability");
        base.current = latest;
        const provider = source
          ? normalize(latest.config).exporters.find(
              (row) => row.id === source.id,
            )
          : fresh();
        if (!provider)
          throw new Error(
            "수집 대상이 삭제되었습니다. 창을 닫고 목록을 확인하세요.",
          );
        return {
          value: { provider, mode: "keep" as SecretChoice, secret: "" },
          revision: latest.updated_at,
        };
      }}
    >
      {(draft, set) => {
        const v = draft.provider,
          change = (patch: Partial<Exporter>) =>
            set({ ...draft, provider: { ...v, ...patch } });
        return (
          <Stack gap="lg">
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label="수집 대상 이름"
                required
                value={v.name}
                onChange={(e) => change({ name: e.currentTarget.value })}
              />
              <Select
                label="관측 연동 방식"
                value={v.type}
                data={[
                  { value: "otlp", label: "OpenTelemetry OTLP" },
                  { value: "langfuse", label: "Langfuse" },
                ]}
                onChange={(t) =>
                  change({
                    type: t === "langfuse" ? "langfuse" : "otlp",
                    signals: t === "langfuse" ? ["traces"] : v.signals,
                  })
                }
              />
            </SimpleGrid>
            <Switch
              label="이 수집 대상 사용"
              checked={v.enabled}
              onChange={(e) => change({ enabled: e.currentTarget.checked })}
            />
            <TextInput
              label="수집 기본 주소"
              required
              value={v.endpoint}
              onChange={(e) => change({ endpoint: e.currentTarget.value })}
              description={
                v.type === "langfuse"
                  ? "서버가 /api/public/otel/v1/traces 경로를 붙입니다."
                  : "서버가 /v1/traces, /v1/metrics, /v1/logs 경로를 붙입니다."
              }
            />
            <MultiSelect
              label="전송 신호"
              disabled={v.type === "langfuse"}
              data={[
                { value: "traces", label: "추적 (traces)" },
                { value: "metrics", label: "지표 (metrics)" },
                { value: "logs", label: "로그 (logs)" },
              ]}
              value={v.signals}
              onChange={(signals) => change({ signals })}
            />
            {v.type === "langfuse" && (
              <TextInput
                label="Langfuse 공개 키"
                value={v.public_key}
                onChange={(e) => change({ public_key: e.currentTarget.value })}
              />
            )}
            <PlatformSecret
              mode={draft.mode}
              value={draft.secret}
              configured={v.api_key_configured}
              onMode={(mode) => set({ ...draft, mode, secret: "" })}
              onValue={(secret) => set({ ...draft, secret })}
            />
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label="대체 그룹"
                placeholder="비우면 독립 전송"
                value={v.failover_group}
                onChange={(e) =>
                  change({ failover_group: e.currentTarget.value })
                }
              />
              <NumberInput
                label="그룹 내 우선순위"
                min={0}
                max={1000}
                value={v.priority}
                onChange={(n) => change({ priority: Number(n) })}
              />
              <NumberInput
                label="응답 제한 시간 (초)"
                min={1}
                max={30}
                value={v.timeout_seconds}
                onChange={(n) => change({ timeout_seconds: Number(n) })}
              />
              <NumberInput
                label="연속 실패 기준"
                min={1}
                max={20}
                value={v.failure_threshold}
                onChange={(n) => change({ failure_threshold: Number(n) })}
              />
              <NumberInput
                label="회복 대기 시간 (초)"
                min={5}
                max={3600}
                value={v.cooldown_seconds}
                onChange={(n) => change({ cooldown_seconds: Number(n) })}
              />
            </SimpleGrid>
          </Stack>
        );
      }}
    </AutomationEditor>
  );
}
