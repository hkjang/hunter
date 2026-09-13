import { useRef, useState } from "react";
import {
  Accordion,
  Alert,
  Badge,
  Button,
  Group,
  MultiSelect,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { dateText, labels, success, useData, type Row } from "./api";
import { LoadState } from "./components";
import {
  AutomationEditor,
  AutomationSection,
  AutomationValues,
} from "./automation-ui";
import { WorkflowTable, type WorkflowColumn } from "./workflow-components";
import {
  PlatformProbe,
  PlatformStatus,
  ProviderHealth,
} from "./agent-platform-ui";
import {
  platformAPI,
  type ExecutionConfig,
  type ExecutionServer,
  type ExecutionProfile,
  type PlatformDocument,
} from "./agent-platform-api";
import {
  newPlatformID,
  providerEndpoint,
  safeProviderFields,
  secretChange,
  type SecretChoice,
} from "./agent-platform-state";
const kinds = [
  { value: "http_headers", label: "HTTP 응답 헤더 조회" },
  { value: "tls_certificate", label: "TLS 인증서 조회" },
  { value: "tcp_connect", label: "TCP 연결 확인" },
];
const executionStates: Record<string, string> = {
  creating: "실행 준비 중",
  created: "실행 준비 완료",
  starting: "실행 시작 중",
  uncertain: "결과 확인 필요",
};
function normalize(config: ExecutionConfig): ExecutionConfig {
  return {
    ...config,
    servers: (config.servers || []).map((row) => ({
      ...row,
      client_key_pem: "",
    })),
    profiles: (config.profiles || []).map((row) => ({
      ...row,
      server_ids: row.server_ids || [],
    })),
  };
}
function body(config: ExecutionConfig) {
  return {
    ...config,
    servers: config.servers.map((row) => ({
      ...safeProviderFields(row),
      ...(row.client_key_pem ? { client_key_pem: row.client_key_pem } : {}),
      ...(row.clear_client_key_pem ? { clear_client_key_pem: true } : {}),
    })),
  };
}
const newServer = (): ExecutionServer => ({
  id: newPlatformID(),
  name: "",
  enabled: false,
  endpoint: "",
  ca_pem: "",
  client_cert_pem: "",
  client_key_pem: "",
  priority: 10,
  network: "",
  service_network: "업무망",
  timeout_seconds: 30,
  failure_threshold: 3,
  cooldown_seconds: 30,
});
const newProfile = (): ExecutionProfile => ({
  id: newPlatformID(),
  name: "",
  enabled: false,
  kind: "http_headers",
  image: "",
  server_ids: [],
});
export function PlatformExecution() {
  const data = useData<PlatformDocument<ExecutionConfig>>(
      "/api/agent-platform/execution",
    ),
    status = useData<{
      providers?: Row[];
      items?: Row[];
      servers?: Row[];
      summary?: { active: number; uncertain: number };
      recent?: Row[];
    }>("/api/agent-platform/execution/status");
  const [general, setGeneral] = useState(false),
    [server, setServer] = useState<ExecutionServer | null | undefined>(
      undefined,
    ),
    [profile, setProfile] = useState<ExecutionProfile | null | undefined>(
      undefined,
    ),
    [probe, setProbe] = useState<ExecutionServer | null>(null),
    [probeProfile, setProbeProfile] = useState<string | null>(null),
    [remove, setRemove] = useState<{
      kind: "server" | "profile";
      id: string;
      name: string;
    } | null>(null);
  const doc = data.data
    ? { ...data.data, config: normalize(data.data.config) }
    : null;
  async function reload() {
    await Promise.all([data.reload(), status.reload()]);
  }
  const health =
    status.data?.providers || status.data?.items || status.data?.servers || [];
  const columns: WorkflowColumn<ExecutionServer>[] = [
    {
      key: "name",
      label: "실행 서버",
      value: (r) => r.name,
      render: (r) => (
        <Stack gap={3}>
          <Text fw={600}>{r.name}</Text>
          <Text c="dimmed" size="sm">
            {r.endpoint}
          </Text>
        </Stack>
      ),
    },
    {
      key: "service_network",
      label: "서비스 망 구분",
      value: (r) => r.service_network || r.network,
    },
    { key: "network", label: "Docker 네트워크", value: (r) => r.network },
    { key: "priority", label: "우선순위", value: (r) => r.priority },
    {
      key: "enabled",
      label: "사용",
      value: (r) => (r.enabled ? "사용 중" : "사용 안 함"),
    },
    {
      key: "state",
      label: "연결 상태",
      value: (r) =>
        String(
          health.find((v) => v.provider_id === r.id || v.id === r.id)?.status ||
            "미확인",
        ),
      render: (r) => (
        <ProviderHealth
          row={health.find((v) => v.provider_id === r.id || v.id === r.id)}
        />
      ),
    },
    {
      key: "actions",
      label: "관리",
      value: () => "",
      render: (r) => (
        <Group wrap="nowrap">
          <Button variant="default" onClick={() => setServer(r)}>
            수정
          </Button>
          <Button
            variant="light"
            onClick={() => {
              setProbe(r);
              setProbeProfile(null);
            }}
          >
            연결 시험
          </Button>
          <Button
            variant="subtle"
            color="red"
            onClick={() =>
              setRemove({ kind: "server", id: r.id, name: r.name })
            }
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
      {doc && (
        <>
          <AutomationSection
            title="승인된 프로파일의 격리 실행"
            description="등록한 실행 서버에서 고정된 조회 프로파일만 실행합니다. 대상 승인·허용 범위·현재 정책을 서버가 다시 확인합니다."
            enabled={doc.config.enabled}
            onEdit={() => setGeneral(true)}
          >
            <AutomationValues
              items={[
                {
                  label: "최대 동시 실행",
                  value: doc.config.max_concurrent + "개",
                },
                {
                  label: "실행 제한 시간",
                  value: doc.config.timeout_seconds + "초",
                },
                {
                  label: "등록 프로파일",
                  value: doc.config.profiles.length + "개",
                },
              ]}
            />
          </AutomationSection>
          <Alert color="teal">
            실행 서버는 mTLS로 연결합니다. 생성 전 연결 실패만 다른 서버로
            대체하며, 이미 시작했거나 결과를 알 수 없는 작업을 자동으로 중복
            실행하지 않습니다.
          </Alert>
          <Group justify="space-between">
            <Text fw={700}>격리 실행 서버</Text>
            <Button
              leftSection={<IconPlus size={17} />}
              disabled={doc.config.servers.length >= 10}
              onClick={() => setServer(null)}
            >
              실행 서버 추가
            </Button>
          </Group>
          <LoadState
            loading={false}
            error={status.error}
            reload={status.reload}
          />
          <WorkflowTable
            name="격리 실행 서버"
            rows={doc.config.servers}
            columns={columns}
            rowKey={(r) => r.id}
            defaultSort={{ key: "priority", direction: "asc" }}
            preferenceContext="platform-execution"
            reload={reload}
            empty="사내 mTLS 실행 서버를 등록하고 저장한 연결을 먼저 시험하세요."
          />
          <Group justify="space-between">
            <Text fw={700}>고정 실행 프로파일</Text>
            <Button
              variant="light"
              leftSection={<IconPlus size={17} />}
              disabled={doc.config.profiles.length >= 20}
              onClick={() => setProfile(null)}
            >
              프로파일 추가
            </Button>
          </Group>
          {doc.config.profiles.map((row) => (
            <AutomationSection
              key={row.id}
              title={row.name}
              enabled={row.enabled}
              onEdit={() => setProfile(row)}
            >
              <AutomationValues
                items={[
                  {
                    label: "조회 유형",
                    value:
                      kinds.find((k) => k.value === row.kind)?.label ||
                      row.kind,
                  },
                  {
                    label: "실행 서버",
                    value:
                      row.server_ids
                        .map(
                          (id) =>
                            doc.config.servers.find((s) => s.id === id)?.name ||
                            id,
                        )
                        .join(" · ") || "미지정",
                  },
                  {
                    label: "고정 이미지",
                    value: (
                      <Text size="sm" style={{ overflowWrap: "anywhere" }}>
                        {row.image}
                      </Text>
                    ),
                  },
                ]}
              />
              <Button
                mt="md"
                variant="subtle"
                color="red"
                onClick={() =>
                  setRemove({ kind: "profile", id: row.id, name: row.name })
                }
              >
                프로파일 삭제
              </Button>
            </AutomationSection>
          ))}
          {!doc.config.profiles.length && (
            <Text c="dimmed">아직 등록한 실행 프로파일이 없습니다.</Text>
          )}
          <AutomationSection
            title="격리 실행 처리 상태"
            description="최근 20개 실행 기록입니다. 결과가 불확실한 실행은 진단 상세에서 확인하세요."
          >
            <AutomationValues
              items={[
                {
                  label: "진행 중",
                  value: status.data?.summary?.active ?? "확인 중",
                },
                {
                  label: "결과 확인 필요",
                  value: status.data?.summary?.uncertain ?? "확인 중",
                },
              ]}
            />
            <Accordion mt="md">
              {(status.data?.recent || []).map((row) => (
                <Accordion.Item key={row.scan_id} value={row.scan_id}>
                  <Accordion.Control>
                    {executionStates[row.status] ||
                      labels[row.status] ||
                      row.status}{" "}
                    · {dateText(row.updated_at || row.created_at)}
                  </Accordion.Control>
                  <Accordion.Panel>
                    <Stack gap="sm">
                      <Text>처리 분류: {row.code || "미확인"}</Text>
                      <Text>
                        실행 서버:{" "}
                        {doc.config.servers.find(
                          (server) => server.id === row.server_id,
                        )?.name || row.server_id}
                      </Text>
                      <Button
                        component={Link}
                        to={`/scans?item=${encodeURIComponent(row.scan_id)}`}
                        variant="light"
                      >
                        진단 상세 보기
                      </Button>
                    </Stack>
                  </Accordion.Panel>
                </Accordion.Item>
              ))}
            </Accordion>
            {!status.data?.recent?.length && (
              <Text mt="md" c="dimmed">
                아직 격리 실행 기록이 없습니다. 연결 시험은 진단 작업을 생성하지
                않습니다.
              </Text>
            )}
          </AutomationSection>
        </>
      )}
      {general && doc && (
        <AutomationEditor
          title="격리 실행 기본 설정"
          value={doc.config}
          revision={doc.updated_at}
          onClose={() => setGeneral(false)}
          onSave={async (v, r) => {
            await platformAPI.save("execution", body(v), r);
            await reload();
          }}
          loadLatest={async () => {
            const v = await platformAPI.get<ExecutionConfig>("execution");
            return { value: normalize(v.config), revision: v.updated_at };
          }}
        >
          {(v, set) => (
            <Stack>
              <Switch
                label="격리 프로파일 실행 사용"
                checked={v.enabled}
                onChange={(e) =>
                  set({ ...v, enabled: e.currentTarget.checked })
                }
              />
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <NumberInput
                  label="최대 동시 실행"
                  min={1}
                  max={4}
                  value={v.max_concurrent}
                  onChange={(n) => set({ ...v, max_concurrent: Number(n) })}
                />
                <NumberInput
                  label="실행 제한 시간 (초)"
                  min={5}
                  max={120}
                  value={v.timeout_seconds}
                  onChange={(n) => set({ ...v, timeout_seconds: Number(n) })}
                />
              </SimpleGrid>
            </Stack>
          )}
        </AutomationEditor>
      )}
      {server !== undefined && doc && (
        <ServerEditor
          source={server}
          document={doc}
          onClose={() => setServer(undefined)}
          onSaved={reload}
        />
      )}
      {profile !== undefined && doc && (
        <ProfileEditor
          source={profile}
          document={doc}
          onClose={() => setProfile(undefined)}
          onSaved={reload}
        />
      )}
      {probe && doc && (
        <PlatformProbe
          name={probe.name}
          onClose={() => setProbe(null)}
          renderResult={(result) => (
            <Stack mt="md">
              {Array.isArray(result.checks) &&
                result.checks.map((check: Row, index: number) => (
                  <Group key={index} justify="space-between">
                    <Text>{String(check.name || "연결 확인")}</Text>
                    <PlatformStatus
                      status={check.ok ? "ok" : String(check.code || "failed")}
                    />
                  </Group>
                ))}
            </Stack>
          )}
          description="저장된 실행 서버의 버전과 등록한 네트워크를 조회합니다. 프로파일을 선택하면 이미지도 확인합니다. 대상 요청과 컨테이너 생성은 하지 않습니다."
          onTest={async () => {
            const result = await platformAPI.test("execution", {
              server_id: probe.id,
              expected_updated_at: doc.updated_at,
              ...(probeProfile ? { profile_id: probeProfile } : {}),
            });
            await status.reload();
            return result;
          }}
        >
          <Select
            label="이미지 확인할 프로파일 (선택)"
            clearable
            value={probeProfile}
            onChange={setProbeProfile}
            data={doc.config.profiles
              .filter((p) => p.server_ids.includes(probe.id))
              .map((p) => ({ value: p.id, label: p.name }))}
          />
        </PlatformProbe>
      )}
      {remove && doc && (
        <AutomationEditor
          title={remove.kind === "server" ? "실행 서버 삭제" : "프로파일 삭제"}
          value={doc.config}
          revision={doc.updated_at}
          submitLabel="삭제"
          onClose={() => setRemove(null)}
          onSave={async (v, r) => {
            if (remove.kind === "server") {
              if (v.profiles.some((p) => p.server_ids.includes(remove.id)))
                throw new Error(
                  "이 서버를 사용하는 프로파일의 실행 서버를 먼저 변경하세요.",
                );
              v.servers = v.servers.filter((s) => s.id !== remove.id);
            } else v.profiles = v.profiles.filter((p) => p.id !== remove.id);
            await platformAPI.save("execution", body(v), r);
            await reload();
          }}
        >
          {() => (
            <Text>
              {remove.name} 설정을 삭제합니다. 실행 중인 작업의 종료 여부는 실행
              상세에서 확인하세요.
            </Text>
          )}
        </AutomationEditor>
      )}
    </Stack>
  );
}
function ServerEditor({
  source,
  document,
  onClose,
  onSaved,
}: {
  source: ExecutionServer | null;
  document: PlatformDocument<ExecutionConfig>;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document);
  return (
    <AutomationEditor
      title={source ? "격리 실행 서버 수정" : "격리 실행 서버 추가"}
      value={{
        server: source ? { ...source } : newServer(),
        mode: "keep" as SecretChoice,
        secret: "",
      }}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (v, r) => {
        const server = {
          ...safeProviderFields(v.server),
          ...secretChange(v.mode, v.secret, "client_key_pem"),
        } as ExecutionServer;
        server.name = server.name.trim();
        server.service_network = (server.service_network || "").trim();
        if (new TextEncoder().encode(server.service_network).length > 200)
          throw new Error(
            "서비스 망 구분은 UTF-8 기준 200바이트까지 입력하세요.",
          );
        server.endpoint = providerEndpoint(server.endpoint);
        if (new URL(server.endpoint).protocol !== "https:")
          throw new Error("격리 실행 서버는 HTTPS mTLS 주소가 필요합니다.");
        if (!server.name || !server.network.trim())
          throw new Error(
            "실행 서버 이름과 Docker 네트워크 이름을 입력하세요.",
          );
        const config = normalize(base.current.config);
        config.servers = source
          ? config.servers.map((s) => (s.id === source.id ? server : s))
          : [...config.servers, server];
        await platformAPI.save("execution", body(config), r);
        success("실행 서버를 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = await platformAPI.get<ExecutionConfig>("execution");
        base.current = latest;
        const server = source
          ? normalize(latest.config).servers.find((s) => s.id === source.id)
          : newServer();
        if (!server)
          throw new Error(
            "실행 서버가 삭제되었습니다. 창을 닫고 목록을 확인하세요.",
          );
        return {
          value: { server, mode: "keep" as SecretChoice, secret: "" },
          revision: latest.updated_at,
        };
      }}
    >
      {(draft, set) => {
        const v = draft.server,
          change = (patch: Partial<ExecutionServer>) =>
            set({ ...draft, server: { ...v, ...patch } });
        return (
          <Stack gap="lg">
            <TextInput
              label="실행 서버 이름"
              required
              value={v.name}
              onChange={(e) => change({ name: e.currentTarget.value })}
            />
            <Switch
              label="이 실행 서버 사용"
              checked={v.enabled}
              onChange={(e) => change({ enabled: e.currentTarget.checked })}
            />
            <TextInput
              label="mTLS 실행 서버 주소"
              required
              value={v.endpoint}
              placeholder="https://runner.internal:2376"
              onChange={(e) => change({ endpoint: e.currentTarget.value })}
            />
            <TextInput
              label="서비스 망 구분"
              value={v.service_network ?? ""}
              placeholder="업무망"
              onChange={(e) =>
                change({ service_network: e.currentTarget.value })
              }
              description="대상 서비스와 Hunter 워커의 망 구분에 정확히 맞추세요. 한글을 사용할 수 있으며, 비워 두면 아래 Docker 네트워크 이름을 사용합니다."
            />
            <TextInput
              label="Docker 네트워크 이름"
              maxLength={128}
              required
              value={v.network}
              placeholder="hunter-sandbox"
              onChange={(e) => change({ network: e.currentTarget.value })}
              description="실행 서버에 미리 만든 Docker 네트워크 이름입니다. 영문·숫자·밑줄·점·하이픈을 사용하며 host·none·bridge는 사용할 수 없습니다."
            />
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <NumberInput
                label="서버 우선순위"
                min={0}
                max={1000}
                value={v.priority}
                onChange={(n) => change({ priority: Number(n) })}
              />
              <NumberInput
                label="서버 응답 제한 (초)"
                min={5}
                max={120}
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
            <Textarea
              label="서버 CA 인증서 (PEM)"
              minRows={4}
              value={v.ca_pem}
              onChange={(e) => change({ ca_pem: e.currentTarget.value })}
            />
            <Textarea
              label="클라이언트 인증서 (PEM)"
              minRows={4}
              value={v.client_cert_pem}
              onChange={(e) =>
                change({ client_cert_pem: e.currentTarget.value })
              }
            />
            <Group>
              <Text fw={600}>클라이언트 개인 키</Text>
              <Badge color={v.client_key_pem_configured ? "teal" : "gray"}>
                {v.client_key_pem_configured
                  ? "저장됨 · 원문 비공개"
                  : "미설정"}
              </Badge>
            </Group>
            <Select
              label="클라이언트 개인 키 관리"
              value={draft.mode}
              data={[
                { value: "keep", label: "저장한 값 유지" },
                { value: "replace", label: "새 값으로 교체" },
                { value: "clear", label: "저장한 값 삭제" },
              ]}
              onChange={(mode) =>
                set({
                  ...draft,
                  mode: (mode || "keep") as SecretChoice,
                  secret: "",
                })
              }
            />
            {draft.mode === "replace" && (
              <Textarea
                label="새 클라이언트 개인 키 (PEM)"
                autoComplete="off"
                minRows={4}
                value={draft.secret}
                onChange={(e) =>
                  set({ ...draft, secret: e.currentTarget.value })
                }
              />
            )}
            <Text size="sm" c="dimmed">
              개인 키는 저장한 원문을 다시 표시하지 않습니다. 새 PEM 값의
              줄바꿈은 그대로 유지합니다.
            </Text>
          </Stack>
        );
      }}
    </AutomationEditor>
  );
}
function ProfileEditor({
  source,
  document,
  onClose,
  onSaved,
}: {
  source: ExecutionProfile | null;
  document: PlatformDocument<ExecutionConfig>;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document);
  return (
    <AutomationEditor
      title={source ? "격리 실행 프로파일 수정" : "격리 실행 프로파일 추가"}
      value={source ? structuredClone(source) : newProfile()}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (v, r) => {
        if (!v.name.trim()) throw new Error("프로파일 이름을 입력하세요.");
        if (!/^\S+@sha256:[a-f0-9]{64}$/.test(v.image))
          throw new Error(
            "이미지를 저장소@sha256:소문자 64자리 해시 형식으로 고정하세요.",
          );
        if (!v.server_ids.length)
          throw new Error("실행 서버를 하나 이상 선택하세요.");
        const config = normalize(base.current.config);
        config.profiles = source
          ? config.profiles.map((p) => (p.id === source.id ? v : p))
          : [...config.profiles, v];
        await platformAPI.save("execution", body(config), r);
        success("실행 프로파일을 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = await platformAPI.get<ExecutionConfig>("execution");
        base.current = latest;
        const value = source
          ? normalize(latest.config).profiles.find((p) => p.id === source.id)
          : newProfile();
        if (!value)
          throw new Error(
            "프로파일이 삭제되었습니다. 창을 닫고 목록을 확인하세요.",
          );
        return { value, revision: latest.updated_at };
      }}
    >
      {(v, set) => (
        <Stack gap="lg">
          <TextInput
            label="프로파일 이름"
            required
            value={v.name}
            onChange={(e) => set({ ...v, name: e.currentTarget.value })}
          />
          <Switch
            label="이 프로파일 사용"
            checked={v.enabled}
            onChange={(e) => set({ ...v, enabled: e.currentTarget.checked })}
          />
          <Select
            label="고정 조회 유형"
            data={kinds}
            value={v.kind}
            onChange={(kind) =>
              set({
                ...v,
                kind: (kind || "http_headers") as ExecutionProfile["kind"],
              })
            }
          />
          <TextInput
            label="고정 실행 이미지"
            required
            value={v.image}
            onChange={(e) => set({ ...v, image: e.currentTarget.value })}
            placeholder="registry.internal/hunter@sha256:…"
            description="동일 버전 Hunter 서비스 이미지를 실행 서버에 미리 docker load하고 승인한 SHA256 digest를 입력하세요. 자동 pull은 하지 않습니다."
          />
          <MultiSelect
            label="사용할 실행 서버"
            maxValues={10}
            searchable
            required
            data={base.current.config.servers.map((s) => ({
              value: s.id,
              label: s.name + (s.enabled ? "" : " · 사용 안 함"),
            }))}
            value={v.server_ids}
            onChange={(server_ids) => set({ ...v, server_ids })}
          />
          <Alert color="teal">
            조회 유형에 정해진 명령과 검증된 대상만 서버가 구성합니다. 임의
            명령·인자를 입력하는 기능은 제공하지 않습니다.
          </Alert>
        </Stack>
      )}
    </AutomationEditor>
  );
}
