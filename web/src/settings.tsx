import { ListTools, TableViewport } from "./list-tools";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Checkbox,
  Code,
  Divider,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  Paper,
  PasswordInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import {
  IconAdjustments,
  IconBell,
  IconCheck,
  IconCopy,
  IconEdit,
  IconExternalLink,
  IconEye,
  IconKey,
  IconLock,
  IconPlus,
  IconRefresh,
  IconRotateClockwise,
  IconSend,
  IconSettings,
  IconShieldCheck,
  IconSparkles,
  IconTrash,
  IconUser,
  IconUsers,
} from "@tabler/icons-react";
import {
  allScopes,
  api,
  dateText,
  fullDate,
  label,
  type Row,
  scopeNames,
  showError,
  success,
  useData,
  useSession,
  type User,
} from "./api";
import { Empty, LoadState, PageHeader, Status } from "./components";
import { FieldForm, initialValues, type Field } from "./resources";
import {
  ListPagination,
  ListReset,
  ListSearch,
  SortHeader,
  useListView,
} from "./use-list-view";
import {
  FormFeedback,
  SaveStatus,
  useUnsavedChanges,
  type FormIssue,
} from "./form-feedback";
import {
  changed,
  invalidFields,
  reconcileDrafts,
  requiredIssues,
} from "./form-state";
import { TrackingSettings } from "./tracking";
import { HandoffTargetsEditor } from "./handoff-settings";
import { handoffTargetsPayload, type HandoffTarget } from "./handoff-state";
const scopesOptions = allScopes.map((s) => ({
  value: s,
  label: `${scopeNames[s]} · ${s}`,
}));
const settingGroups: [string, string, any][] = [
  ["general", "기본 정보", IconSettings],
  ["oidc", "SSO · 로그인", IconShieldCheck],
  ["ai", "AI 분석", IconSparkles],
  ["agents", "에이전트 진단", IconAdjustments],
  ["workflow", "검토 · 승인", IconAdjustments],
  ["sla", "조치 기한 · SLA", IconAdjustments],
  ["risk", "조치 우선순위", IconShieldCheck],
  ["inventory", "소프트웨어 구성", IconSettings],
  ["security", "보안 · 세션", IconLock],
  ["tracking", "방문 추적", IconEye],
  ["handoff", "다른 서비스로 보내기", IconSend],
  ["roles", "역할 · 권한", IconUsers],
];
const settingFields: Record<string, Field[]> = {
  sla: [
    {
      key: "enabled",
      label: "심각도별 기본 조치 기한 사용",
      type: "switch",
      default: false,
      description:
        "개별 기한이 없는 발견 건에 적용합니다. 기한 경과는 발견 건 상태를 자동 변경하지 않습니다.",
    },
    ...(
      [
        ["critical", "심각", 7],
        ["high", "높음", 30],
        ["medium", "보통", 90],
        ["low", "낮음", 180],
        ["info", "정보", 0],
      ] as const
    ).map(([key, label, days]) => ({
      key: `${key}_days`,
      label: `${label} 조치 기한 (일)`,
      type: "number" as const,
      default: days,
      min: 0,
      max: 3650,
      description: "0이면 이 심각도의 기본 기한을 적용하지 않습니다.",
    })),
    {
      key: "due_soon_days",
      label: "기한 임박 표시 (남은 일수)",
      type: "number",
      default: 7,
      min: 0,
      max: 3650,
    },
  ],
  risk: [
    {
      key: "kev_boost",
      label: "KEV 목록 일치 가산점",
      type: "number",
      default: 25,
      min: 0,
      max: 100,
      description:
        "반입한 KEV 자료와 CVE가 일치할 때 조치 우선순위에 반영합니다.",
    },
    {
      key: "epss_threshold",
      label: "EPSS 가산 기준",
      type: "number",
      default: 0.1,
      min: 0,
      max: 1,
      description:
        "0~1 범위. 0.1은 10%를 뜻합니다. 자료가 없으면 가산하지 않습니다.",
    },
    {
      key: "epss_boost",
      label: "EPSS 기준 충족 가산점",
      type: "number",
      default: 10,
      min: 0,
      max: 100,
    },
    {
      key: "stale_after_days",
      label: "위협 정보 갱신 판단 기준 (일)",
      type: "number",
      default: 30,
      min: 1,
      max: 3650,
      description:
        "오래된 정보는 조치함과 위협 정보 반입 화면에 별도로 표시합니다.",
    },
  ],
  inventory: [
    {
      key: "stale_after_days",
      label: "SBOM 갱신 검토 기준 (일)",
      type: "number",
      default: 30,
      min: 1,
      max: 3650,
    },
    {
      key: "review_licenses",
      label: "검토 대상 라이선스",
      type: "tags",
      default: [],
      description:
        "예: GPL-3.0-only. 기록된 값과 정확히 일치하면 검토 대상으로 표시합니다. 라이선스 누락·복합 표현식·사용자 정의 식별자도 검토 대상으로 분류하며 법적 적합성을 자동 판정하지 않습니다.",
    },
  ],
  general: [
    {
      key: "service_name",
      label: "워크스페이스 이름",
      required: true,
      default: "Hunter 워크스페이스",
    },
    {
      key: "public_url",
      label: "서비스 외부 접근 주소",
      placeholder: "https://hunter.internal",
      description:
        "SSO 리다이렉트 URI와 쿠키 보안 설정에 사용합니다. 운영 환경에서는 HTTPS 주소를 지정하세요.",
    },
  ],
  oidc: [
    {
      key: "enabled",
      label: "OIDC SSO 로그인 사용",
      type: "switch",
      default: false,
    },
    {
      key: "auto_login",
      label: "기존 SSO 세션으로 자동 로그인",
      type: "switch",
      default: false,
      description:
        "기본 꺼짐입니다. 켜면 SSO 사용 시 로그인 화면을 표시하기 전에 사내 세션을 확인합니다. 세션이 없거나 추가 인증이 필요하면 로컬 로그인과 수동 SSO를 제공합니다.",
    },
    {
      key: "issuer",
      label: "Issuer URL",
      placeholder: "https://keycloak.internal/realms/company",
      description:
        "Discovery 문서의 issuer 주소를 마지막 /까지 포함해 정확히 입력하세요. OIDC 메타데이터와 서명키를 자동 검색합니다.",
    },
    { key: "client_id", label: "Client ID", placeholder: "hunter" },
    {
      key: "client_secret",
      label: "Client Secret",
      type: "password",
      description: "암호화하여 저장합니다. 빈 값은 기존 설정을 유지합니다.",
    },
    {
      key: "default_role",
      label: "신규 SSO 사용자 기본 역할",
      type: "select",
      options: ["viewer", "analyst", "lead"],
      default: "viewer",
    },
  ],
  ai: [
    {
      key: "enabled",
      label: "AI 분석 도우미 사용",
      type: "switch",
      default: false,
    },
    {
      key: "base_url",
      label: "OpenAI 호환 API Base URL",
      placeholder: "http://llm.internal:8000/v1",
      description:
        "사내 LLM의 /v1 경로까지 입력하세요. 외부 인터넷 연결 없이 사내 모델을 사용할 수 있습니다.",
    },
    {
      key: "api_key",
      label: "AI API 키",
      type: "password",
      description: "빈 값은 기존 키를 유지합니다.",
    },
    { key: "model", label: "모델 이름", placeholder: "local-model" },
    {
      key: "max_tokens",
      label: "최대 출력 토큰",
      type: "number",
      default: 4096,
      min: 1,
      max: 262144,
      description:
        "최대 262,144 (256K). 실제 모델과 서버가 지원하는 출력 상한을 확인하세요.",
    },
    {
      key: "context_window",
      label: "모델 컨텍스트 창",
      type: "number",
      default: 262144,
      min: 1024,
      max: 262144,
      description:
        "입력과 출력을 합산한 모델 한도입니다. 긴 요청은 모델의 실제 한도에 영향을 받습니다.",
    },
  ],
  agents: [
    {
      key: "enabled",
      label: "PentAGI 에이전트 진단 사용",
      type: "switch",
      default: false,
      description:
        "선택한 모델의 토큰 한도와 TLS 설정을 적용합니다. 여러 제공자와 역할별 선택은 에이전트 통합 연동에서 관리하며, 실행에는 에이전트 실행 권한과 AI 사용 권한이 모두 필요합니다.",
    },
    {
      key: "max_iterations",
      label: "에이전트별 최대 반복 횟수",
      type: "number",
      default: 24,
      min: 6,
      max: 100,
      description:
        "각 역할 에이전트의 개별 반복 루프에 적용합니다. 모델 호출 총량은 실행당 최대 모델 호출 설정으로 제한합니다.",
    },
    {
      key: "max_model_calls",
      label: "실행당 최대 모델 호출",
      type: "number",
      default: 60,
      min: 5,
      max: 200,
    },
    {
      key: "max_tool_calls",
      label: "Hunter 도구 호출 한도",
      type: "number",
      default: 40,
      min: 1,
      max: 200,
      description:
        "실행당 Hunter 도구 7종의 호출만 집계합니다. 코어 내부의 역할 위임 호출과 구분합니다.",
    },
    {
      key: "timeout_minutes",
      label: "실행 제한 시간 (분)",
      type: "number",
      default: 15,
      min: 1,
      max: 60,
    },
    {
      key: "allow_diagnosis",
      label: "허용된 실제 진단 요청",
      type: "switch",
      default: false,
      description:
        "서비스의 유효한 허용 범위와 실행 정책을 통과한 진단만 생성합니다. 검토 절차는 검토 · 승인 설정을 따릅니다.",
    },
    {
      key: "allow_candidates",
      label: "발견 후보 기록 허용",
      type: "switch",
      default: true,
      description:
        "발견 내용을 후보로 기록합니다. 취약점 확정이나 해결 처리는 자동 수행하지 않습니다.",
    },
    {
      key: "memory_enabled",
      label: "실행 메모리 사용",
      type: "switch",
      default: true,
      description:
        "허용된 범위에서 이전 작업의 기억 저장과 조회 도구를 사용합니다.",
    },
  ],
  workflow: [
    {
      key: "approval_enabled",
      label: "팀장 검토 · 승인 프로세스 사용",
      type: "switch",
      default: false,
      description:
        "활성화하면 진단 요청에 검토 · 승인 · 반려 절차와 메뉴가 나타납니다. 비활성화하면 해당 절차가 제외됩니다.",
    },
  ],
  security: [
    {
      key: "session_hours",
      label: "로그인 세션 유효 시간",
      type: "number",
      default: 12,
      min: 1,
      max: 168,
      description: "새로 생성되는 세션에 적용합니다.",
    },
    {
      key: "key_max_days",
      label: "개인 API 키 최대 유효 기간 (일)",
      type: "number",
      default: 90,
      min: 1,
      max: 365,
    },
    {
      key: "trusted_ca_pem",
      label: "사내 신뢰 CA 인증서 (PEM)",
      type: "textarea",
      description:
        "사내 HTTPS 인증기관의 인증서 체인을 붙여 넣으세요. OIDC, AI, 연동, 알림 및 진단의 TLS 검증에 적용됩니다.",
    },
  ],
};
function settingsGroupValues(group: string, data?: Row): Row {
  if (group === "roles") return data || {};
  if (group === "handoff")
    return handoffTargetsPayload(
      Array.isArray(data?.targets) ? (data!.targets as HandoffTarget[]) : [],
    );
  const values = initialValues(settingFields[group] || [], data);
  if (group === "oidc") values.clear_client_secret = false;
  if (group === "ai") values.clear_api_key = false;
  return values;
}
type SaveFeedback = {
  error?: string;
  issues?: FormIssue[];
  attempt?: number;
  savedAt?: string;
};

export function SettingsPage() {
  const { data, loading, error, reload, setData } =
    useData<Row>("/api/settings");
  const { refreshConfig, config } = useSession();
  const [params, setParams] = useSearchParams();
  const tab = settingGroups.some(([key]) => key === params.get("tab"))
    ? params.get("tab")!
    : "general";
  function moveTab(value: string) {
    const next = new URLSearchParams(params);
    next.set("tab", value);
    setParams(next, { replace: true });
  }
  const [values, setValues] = useState<Row>({}),
    [busy, setBusy] = useState(false),
    [feedback, setFeedback] = useState<Record<string, SaveFeedback>>({}),
    [pendingTab, setPendingTab] = useState<string | null>(null);
  const baseline = useRef<Row>({});
  const form = useRef<HTMLFormElement>(null);
  const pendingSaveTab = useRef<string | null>(null);
  const trackingSave = useRef<(() => Promise<boolean>) | null>(null);
  const [trackingDirty, setTrackingDirty] = useState(false);
  const dirtyGroups = settingGroups
    .filter(([group]) =>
      group === "tracking"
        ? trackingDirty
        : changed(baseline.current[group], values[group]),
    )
    .map(([group]) => group);
  const dirty = dirtyGroups.includes(tab);
  const currentFeedback = feedback[tab] || {};
  useUnsavedChanges(dirtyGroups.length > 0);
  function setTab(value: string) {
    if (busy || value === tab) return;
    if (dirty) setPendingTab(value);
    else moveTab(value);
  }
  useEffect(() => {
    if (data) {
      const next: Row = {};
      for (const [g] of settingGroups)
        next[g] = settingsGroupValues(g, data[g]);
      const previous = baseline.current;
      baseline.current = next;
      setValues((current) => reconcileDrafts(previous, current, next));
    }
  }, [data]);
  async function save(nextTab?: string) {
    if (busy) return;
    const group = tab;
    if (group === "tracking") {
      if (await trackingSave.current?.()) {
        if (nextTab) moveTab(nextTab);
      }
      return;
    }
    const required = requiredIssues(
      (settingFields[group] || [])
        .filter((field) => field.required)
        .map((field) => ({
          fieldId: `settings-${group}-${field.key}`,
          label: field.label,
          value: values[group]?.[field.key],
        })),
    );
    const issues = [
      ...new Map(
        [...required, ...(form.current ? invalidFields(form.current) : [])].map(
          (issue) => [issue.fieldId || issue.message, issue],
        ),
      ).values(),
    ];
    setFeedback((previous) => ({
      ...previous,
      [group]: {
        ...previous[group],
        error: undefined,
        issues,
        attempt: (previous[group]?.attempt || 0) + 1,
      },
    }));
    if (issues.length) return;
    const submitted =
      group === "handoff"
        ? handoffTargetsPayload(values.handoff?.targets || [])
        : values[group] || {};
    setBusy(true);
    try {
      const saved = await api<Row>(`/api/settings/${group}`, {
        method: "PUT",
        body: JSON.stringify(submitted),
      });
      const normalized = settingsGroupValues(group, saved);
      baseline.current = { ...baseline.current, [group]: normalized };
      setValues((current) => ({
        ...current,
        [group]: changed(submitted, current[group])
          ? current[group]
          : normalized,
      }));
      setData((current) => ({ ...current, [group]: saved }));
      setFeedback((previous) => ({
        ...previous,
        [group]: { savedAt: new Date().toISOString() },
      }));
      refreshConfig();
      if (nextTab) moveTab(nextTab);
    } catch (e) {
      setFeedback((previous) => ({
        ...previous,
        [group]: {
          ...previous[group],
          error:
            e instanceof Error
              ? e.message
              : "설정을 저장하지 못했습니다. 다시 시도하세요.",
          attempt: (previous[group]?.attempt || 0) + 1,
        },
      }));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        eyebrow="ADMINISTRATION"
        title="서비스 설정"
        description="서비스 운영에 필요한 모든 설정을 관리합니다. 변경 사항은 데이터베이스에 안전하게 저장됩니다."
        action={
          <Button
            component={Link}
            to="/admin/notifications"
            variant="default"
            leftSection={<IconBell size={17} />}
          >
            알림센터
          </Button>
        }
      />
      <LoadState loading={loading} error={error} reload={reload} />
      {!loading && !error && data && (
        <div className="settings-layout">
          <div className="settings-navigation">
            {settingGroups.map(([key, title, Icon]) => (
              <button
                key={key}
                className={tab === key ? "selected" : ""}
                onClick={() => setTab(key)}
                disabled={busy}
                aria-current={tab === key ? "page" : undefined}
              >
                <Icon size={20} />
                <span>{title}</span>
                {dirtyGroups.includes(key) && (
                  <span
                    className="settings-dirty-marker"
                    role="img"
                    aria-label={`${title} 저장하지 않은 변경`}
                  />
                )}
              </button>
            ))}
          </div>
          <TrackingSettings
            active={tab === "tracking"}
            saveRef={trackingSave}
            onDirtyChange={setTrackingDirty}
            onBusyChange={setBusy}
          />
          <Paper
            hidden={tab === "tracking"}
            className={`settings-panel${tab === "agents" ? " agent-settings" : ""}`}
          >
            <form
              ref={form}
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                void save();
              }}
            >
              <FormFeedback
                error={currentFeedback.error}
                issues={currentFeedback.issues}
                focusKey={currentFeedback.attempt}
              />
              <div className="settings-panel-head">
                <span className="settings-section-icon">
                  {tab === "ai" ? (
                    <IconSparkles />
                  ) : tab === "oidc" ? (
                    <IconShieldCheck />
                  ) : (
                    <IconSettings />
                  )}
                </span>
                <div>
                  <h2>{settingGroups.find((g) => g[0] === tab)?.[1]}</h2>
                  <p>
                    {tab === "roles"
                      ? "역할별 접근 가능한 기능을 정의합니다. 개인 키 권한은 소유자 권한을 초과할 수 없습니다."
                      : tab === "handoff"
                        ? "실행 보고서를 받아 갈 수 있는 사내 서비스의 허용 목록입니다. 기본값은 비어 있습니다."
                        : "워크스페이스의 설정을 확인하고 변경하세요."}
                  </p>
                </div>
              </div>
              <p className="form-required-hint">
                별표(*) 항목은 필수입니다. 현재 설정 그룹만 저장됩니다.
              </p>
              <fieldset className="form-fields" disabled={busy}>
                {tab === "roles" ? (
                  <Stack gap="xl">
                    {["admin", "lead", "analyst", "viewer"].map((role) => (
                      <div key={role}>
                        <MultiSelect
                          label={label(role)}
                          description={
                            role === "admin"
                              ? "서비스 관리자는 전체 관리 권한을 가집니다."
                              : "이 역할에 부여할 권한을 선택하세요."
                          }
                          data={scopesOptions}
                          value={values.roles?.[role] || []}
                          onChange={(v) =>
                            setValues({
                              ...values,
                              roles: { ...values.roles, [role]: v },
                            })
                          }
                          searchable
                          disabled={role === "admin"}
                        />
                      </div>
                    ))}
                  </Stack>
                ) : tab === "handoff" ? (
                  <HandoffTargetsEditor
                    targets={values.handoff?.targets || []}
                    publicURL={
                      values.general?.public_url || window.location.origin
                    }
                    onChange={(targets) =>
                      setValues({ ...values, handoff: { targets } })
                    }
                  />
                ) : (
                  <FieldForm
                    idPrefix={`settings-${tab}`}
                    errors={Object.fromEntries(
                      (currentFeedback.issues || [])
                        .filter((issue) =>
                          issue.fieldId?.startsWith(`settings-${tab}-`),
                        )
                        .map((issue) => [
                          issue.fieldId!.slice(`settings-${tab}-`.length),
                          issue.message,
                        ]),
                    )}
                    fields={settingFields[tab || "general"] || []}
                    values={values[tab || "general"] || {}}
                    setValues={(v) =>
                      setValues({ ...values, [tab || "general"]: v })
                    }
                  />
                )}
                {tab === "oidc" && (
                  <Alert color="teal" mt="xl" title="Keycloak · ReSSO 연결 안내">
                    <Text size="sm">
                      Client authentication을 활성화하고 Standard flow를
                      사용하세요. Valid redirect URI에 다음 주소를 등록하면
                      됩니다.
                    </Text>
                    <Code
                      block
                      mt="sm"
                      style={{
                        whiteSpace: "pre-wrap",
                        overflowWrap: "anywhere",
                      }}
                    >{`${(values.general?.public_url || window.location.origin).replace(/\/$/, "")}/api/auth/oidc/callback`}</Code>
                    {data.oidc?.client_secret_configured && (
                      <>
                        <Badge mt="md" color="teal" variant="light">
                          Client Secret 저장됨
                        </Badge>
                        <Checkbox
                          mt="md"
                          label="저장된 Client Secret 삭제"
                          checked={!!values.oidc?.clear_client_secret}
                          onChange={(e) =>
                            setValues({
                              ...values,
                              oidc: {
                                ...values.oidc,
                                clear_client_secret: e.currentTarget.checked,
                              },
                            })
                          }
                        />
                      </>
                    )}
                    <Text size="sm" mt="sm">
                      SSO를 활성화해도 초기 로컬 관리자 계정은 로그인할 수
                      있습니다.
                    </Text>
                    <Text size="sm" mt="sm">
                      자동 확인에 실패하거나 로그아웃하면 자동 진입을 잠시
                      멈춥니다. ReSSO 등 다른 인증 서버는 OIDC
                      Discovery·Authorization Code·PKCE를 지원해야 하며 실제
                      연결은 해당 서버에서 확인하세요.
                    </Text>
                    <Button
                      component="a"
                      href="/login?local=1"
                      target="_blank"
                      rel="noopener noreferrer"
                      variant="light"
                      mt="sm"
                      rightSection={<IconExternalLink size={16} />}
                      styles={{
                        root: {
                          maxWidth: "100%",
                          height: "auto",
                          paddingBlock: 8,
                        },
                        label: { whiteSpace: "normal", textAlign: "left" },
                      }}
                    >
                      로컬 로그인 주소 · 새 탭
                    </Button>
                  </Alert>
                )}
                {tab === "ai" && (
                  <Alert
                    color="teal"
                    mt="xl"
                    title="기본 스트리밍 · 사람 중심의 분석"
                  >
                    <Text size="sm">
                      AI 응답은 SSE로 실시간 표시합니다. 분석 도우미는 발견
                      내용을 설명하고 개선안을 제안합니다. 에이전트 진단은 별도
                      설정에서 활성화하며 허용된 도구와 실행 한도를 적용합니다.
                    </Text>
                    {data.ai?.api_key_configured && (
                      <>
                        <Badge mt="sm" color="teal" variant="light">
                          AI API 키 저장됨
                        </Badge>
                        <Checkbox
                          mt="md"
                          label="저장된 AI API 키 삭제"
                          checked={!!values.ai?.clear_api_key}
                          onChange={(e) =>
                            setValues({
                              ...values,
                              ai: {
                                ...values.ai,
                                clear_api_key: e.currentTarget.checked,
                              },
                            })
                          }
                        />
                      </>
                    )}
                  </Alert>
                )}
                {(tab === "ai" || tab === "agents") && (
                  <Alert color="teal" mt="lg" title="에이전트 통합 연동">
                    <Text size="sm">
                      여러 모델 제공자와 역할별 우선순위, 검색·메모리·격리
                      실행·관측성은 통합 연동에서 설정합니다. 기존 AI 설정은
                      유지됩니다.
                    </Text>
                    <Button
                      component="a"
                      href="/admin/agent-platform?tab=models"
                      target="_blank"
                      rel="noopener noreferrer"
                      variant="light"
                      mt="sm"
                      rightSection={<IconExternalLink size={16} />}
                    >
                      통합 연동 열기 · 새 탭
                    </Button>
                  </Alert>
                )}
                {tab === "agents" && (
                  <Alert
                    color="teal"
                    mt="xl"
                    title="PentAGI 코어 · 제한된 도구 실행"
                  >
                    <Text size="sm">
                      작업 분해와 역할 위임에 PentAGI MIT 코어를 사용합니다.
                      서비스 정보, 발견 건 조회, 허용된 진단 요청과 결과 조회,
                      후보 기록, 기억 저장·조회와 관리자가 설정한 출처 검색을
                      연결합니다.
                    </Text>
                    <Text size="sm" mt="sm">
                      기존에 저장한 역할 설정에는 새 권한이 자동 추가되지 않을
                      수 있습니다. 역할 · 권한에서 에이전트·서비스·발견 건·진단
                      조회 권한을 모두 확인하세요. 실행에는 에이전트 실행 권한과
                      AI 사용 권한도 필요합니다.
                    </Text>
                    <Text size="sm" c="dimmed" mt="md">
                      출처: vxcontrol/pentagi · MIT License · 커밋{" "}
                      {config.agent_upstream_commit || "서버 출처 정보 확인 중"}
                    </Text>
                  </Alert>
                )}
                {tab === "workflow" && (
                  <Alert
                    color="teal"
                    mt="xl"
                    title={
                      values.workflow?.approval_enabled
                        ? "팀장 검토 절차가 적용됩니다"
                        : "팀장 검토 절차가 제외됩니다"
                    }
                  >
                    <Text size="sm">
                      팀장 검토 사용 여부와 관계없이 네트워크 진단에는
                      관리자에게 승인받은 서비스와 유효한 진단 허용 범위가
                      필요합니다.
                    </Text>
                  </Alert>
                )}
              </fieldset>
              <Divider my="xl" />
              <Group justify="space-between" className="form-save-actions">
                <SaveStatus
                  dirty={dirty}
                  saving={busy}
                  savedAt={currentFeedback.savedAt}
                />
                <Button
                  loading={busy}
                  leftSection={<IconCheck size={18} />}
                  type="submit"
                >
                  설정 저장
                </Button>
              </Group>
            </form>
          </Paper>
        </div>
      )}
      <Modal
        opened={!!pendingTab}
        onClose={() => setPendingTab(null)}
        onExitTransitionEnd={() => {
          const target = pendingSaveTab.current;
          pendingSaveTab.current = null;
          if (target) void save(target);
        }}
        title="저장하지 않은 설정이 있습니다"
        centered
      >
        <Text>
          ‘{settingGroups.find(([group]) => group === tab)?.[1]}’의 변경 사항이
          아직 적용되지 않았습니다. 저장한 뒤 이동하거나 현재 입력을 유지할 수
          있습니다.
        </Text>
        <Group justify="flex-end" mt="xl">
          <Button variant="default" onClick={() => setPendingTab(null)}>
            계속 수정
          </Button>
          <Button
            variant="light"
            onClick={() => {
              if (pendingTab) moveTab(pendingTab);
              setPendingTab(null);
            }}
          >
            입력 유지하고 이동
          </Button>
          <Button
            onClick={() => {
              pendingSaveTab.current = pendingTab;
              setPendingTab(null);
            }}
          >
            저장 후 이동
          </Button>
        </Group>
      </Modal>
    </>
  );
}
export function ProfilePage() {
  const { user, setUser } = useSession();
  const { data, loading, error, reload } = useData<Row>("/api/profile");
  const [name, setName] = useState(""),
    [pref, setPref] = useState<Row>({}),
    [current, setCurrent] = useState(""),
    [password, setPassword] = useState(""),
    [confirm, setConfirm] = useState(""),
    [busy, setBusy] = useState<"profile" | "password" | null>(null),
    [profileFeedback, setProfileFeedback] = useState<SaveFeedback>({}),
    [passwordFeedback, setPasswordFeedback] = useState<SaveFeedback>({});
  const profileBaseline = useRef<Row | null>(null);
  const profileDirty =
    profileBaseline.current !== null &&
    changed(profileBaseline.current, { name, preferences: pref });
  const passwordDirty = !!(current || password || confirm);
  useUnsavedChanges(profileDirty || passwordDirty);
  useEffect(() => {
    if (data) {
      const next = {
        name: data.name || data.user?.name || "",
        preferences: data.preferences || data.user?.preferences || {},
      };
      if (
        !profileBaseline.current ||
        !changed(profileBaseline.current, { name, preferences: pref })
      ) {
        setName(next.name);
        setPref(next.preferences);
      }
      profileBaseline.current = next;
    }
  }, [data]);
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const issues = [
      ...new Map(
        [
          ...requiredIssues([
            { fieldId: "profile-name", label: "표시 이름", value: name },
          ]),
          ...invalidFields(event.currentTarget),
        ].map((issue) => [issue.fieldId || issue.message, issue]),
      ).values(),
    ];
    setProfileFeedback((previous) => ({
      ...previous,
      error: undefined,
      issues,
      attempt: (previous.attempt || 0) + 1,
    }));
    if (issues.length) return;
    const submitted = { name, preferences: pref };
    setBusy("profile");
    try {
      await api("/api/profile", {
        method: "PUT",
        body: JSON.stringify(submitted),
      });
      profileBaseline.current = submitted;
      if (user) setUser({ ...user, ...submitted });
      setProfileFeedback({ savedAt: new Date().toISOString() });
    } catch (e) {
      setProfileFeedback((previous) => ({
        ...previous,
        error:
          e instanceof Error
            ? e.message
            : "프로필을 저장하지 못했습니다. 다시 시도하세요.",
        attempt: (previous.attempt || 0) + 1,
      }));
    } finally {
      setBusy(null);
    }
  }
  async function changePassword(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (busy) return;
    const issues = invalidFields(e.currentTarget);
    if (confirm && password !== confirm)
      issues.push({
        fieldId: "profile-confirm-password",
        message: "새 비밀번호와 확인 값을 같게 입력하세요.",
      });
    setPasswordFeedback((previous) => ({
      ...previous,
      error: undefined,
      issues,
      attempt: (previous.attempt || 0) + 1,
    }));
    if (issues.length) return;
    setBusy("password");
    try {
      await api("/api/profile/password", {
        method: "POST",
        body: JSON.stringify({
          current_password: current,
          new_password: password,
        }),
      });
      setCurrent("");
      setPassword("");
      setConfirm("");
      setPasswordFeedback({ savedAt: new Date().toISOString() });
    } catch (e) {
      setPasswordFeedback((previous) => ({
        ...previous,
        error:
          e instanceof Error
            ? e.message
            : "비밀번호를 변경하지 못했습니다. 다시 시도하세요.",
        attempt: (previous.attempt || 0) + 1,
      }));
    } finally {
      setBusy(null);
    }
  }
  return (
    <>
      <PageHeader
        eyebrow="PERSONAL WORKSPACE"
        title="내 프로필"
        description="개인 정보와 계정 보안을 관리합니다. 서비스 전체 설정은 관리자 콘솔에서 관리합니다."
      />
      <LoadState loading={loading} error={error} reload={reload} />
      {!loading && !error && (
        <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="xl">
          <Paper className="content-card">
            <form noValidate onSubmit={save}>
              <FormFeedback
                error={profileFeedback.error}
                issues={profileFeedback.issues}
                focusKey={profileFeedback.attempt}
              />
              <div className="profile-card-header">
                <div className="profile-monogram">
                  {(user?.name || user?.username || "H")[0]}
                </div>
                <div>
                  <h2>{user?.name || user?.username}</h2>
                  <Badge color="teal" variant="light">
                    {label(user?.role)}
                  </Badge>
                </div>
              </div>
              <p className="form-required-hint">별표(*) 항목은 필수입니다.</p>
              <fieldset className="form-fields" disabled={!!busy}>
                <Stack mt="xl">
                  <TextInput
                    label="아이디"
                    value={user?.username || ""}
                    disabled
                  />
                  <TextInput
                    label="표시 이름"
                    id="profile-name"
                    error={
                      profileFeedback.issues?.find(
                        (issue) => issue.fieldId === "profile-name",
                      )?.message
                    }
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                  />
                  <Select
                    label="기본 시작 화면"
                    data={[
                      { value: "/dashboard", label: "보안 현황" },
                      { value: "/services", label: "서비스 자산" },
                      { value: "/findings", label: "발견 건" },
                    ]}
                    value={pref.home_page || "/dashboard"}
                    onChange={(v) => setPref({ ...pref, home_page: v })}
                  />
                  <Text size="sm" c="dimmed">
                    저장한 시작 화면은 다음 로그인에 적용됩니다.
                  </Text>
                </Stack>
              </fieldset>
              <Group justify="space-between" mt="xl">
                <SaveStatus
                  dirty={profileDirty}
                  saving={busy === "profile"}
                  savedAt={profileFeedback.savedAt}
                />
                <Button
                  loading={busy === "profile"}
                  disabled={!!busy}
                  type="submit"
                >
                  프로필 저장
                </Button>
              </Group>
            </form>
          </Paper>
          <Paper className="content-card">
            <h2>비밀번호 변경</h2>
            <Text c="dimmed" size="sm" mb="xl">
              로컬 계정의 비밀번호를 변경합니다. SSO 비밀번호는 사내 인증
              시스템에서 관리하세요.
            </Text>
            <form noValidate onSubmit={changePassword}>
              <FormFeedback
                error={passwordFeedback.error}
                issues={passwordFeedback.issues}
                focusKey={passwordFeedback.attempt}
                success={
                  passwordFeedback.savedAt && !passwordDirty
                    ? "비밀번호를 변경했습니다."
                    : undefined
                }
              />
              <p className="form-required-hint">
                세 항목을 모두 입력하세요. 입력값은 이 화면에만 유지됩니다.
              </p>
              <fieldset className="form-fields" disabled={!!busy}>
                <Stack>
                  <PasswordInput
                    label="현재 비밀번호"
                    id="profile-current-password"
                    error={
                      passwordFeedback.issues?.find(
                        (issue) => issue.fieldId === "profile-current-password",
                      )?.message
                    }
                    required
                    autoComplete="current-password"
                    value={current}
                    onChange={(e) => setCurrent(e.target.value)}
                  />
                  <PasswordInput
                    label="새 비밀번호"
                    id="profile-new-password"
                    error={
                      passwordFeedback.issues?.find(
                        (issue) => issue.fieldId === "profile-new-password",
                      )?.message
                    }
                    description="12자 이상의 비밀번호를 사용하세요."
                    minLength={12}
                    required
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  <PasswordInput
                    label="새 비밀번호 확인"
                    id="profile-confirm-password"
                    error={
                      passwordFeedback.issues?.find(
                        (issue) => issue.fieldId === "profile-confirm-password",
                      )?.message
                    }
                    required
                    autoComplete="new-password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                  />
                </Stack>
              </fieldset>
              <Group justify="space-between" mt="xl">
                {(passwordDirty || busy === "password") && (
                  <SaveStatus
                    dirty={passwordDirty}
                    saving={busy === "password"}
                  />
                )}
                <Button
                  variant="light"
                  type="submit"
                  loading={busy === "password"}
                  disabled={!!busy}
                >
                  비밀번호 변경
                </Button>
              </Group>
            </form>
          </Paper>
        </SimpleGrid>
      )}
    </>
  );
}
const keyStateLabels = { active: "활성", expired: "만료됨", revoked: "폐기됨" };
function sortableDate(value: unknown) {
  const timestamp = Date.parse(String(value || ""));
  return Number.isFinite(timestamp) ? timestamp : null;
}
function keyState(row: Row): keyof typeof keyStateLabels {
  if (row.revoked_at) return "revoked";
  return Date.parse(row.expires_at) <= Date.now() ? "expired" : "active";
}
export function KeysPage() {
  const { user } = useSession();
  const { data, loading, error, reload } = useData<Row[]>("/api/keys");
  const view = useListView<Row>({
    rows: data || [],
    columns: [
      { key: "name", label: "키 이름", value: (row) => row.name },
      { key: "prefix", label: "키 접두사", value: (row) => row.prefix },
      {
        key: "scopes",
        label: "권한",
        value: (row) =>
          (row.scopes || []).map((scope: string) => scopeNames[scope] || scope),
      },
      {
        key: "created_at",
        label: "발급 일시",
        value: (row) => sortableDate(row.created_at),
      },
      {
        key: "expires_at",
        label: "만료 일자",
        value: (row) => sortableDate(row.expires_at),
      },
      {
        key: "last_used_at",
        label: "최근 사용",
        value: (row) => sortableDate(row.last_used_at),
      },
      {
        key: "status",
        label: "상태",
        value: (row) => keyStateLabels[keyState(row)],
      },
    ],
    searchValues: (row) => [
      row.scopes || [],
      row.created_at,
      row.expires_at,
      row.last_used_at,
      dateText(row.created_at),
      fullDate(row.expires_at),
      dateText(row.last_used_at),
    ],
    defaultSort: { key: "created_at", direction: "desc" },
    filters: {
      status: (row, value) => keyState(row) === value,
      scope: (row, value) => (row.scopes || []).includes(value),
    },
  });
  const [opened, setOpened] = useState(false),
    [edit, setEdit] = useState<Row | null>(null),
    [name, setName] = useState(""),
    [scopes, setScopes] = useState<string[]>([]),
    [days, setDays] = useState<number | string>(30),
    [busy, setBusy] = useState(false),
    [token, setToken] = useState(""),
    [confirm, setConfirm] = useState<{
      row: Row;
      action: "rotate" | "revoke";
    } | null>(null);
  const available = scopesOptions.filter(
    (s) => user?.role === "admin" || user?.scopes?.includes(s.value),
  );
  function create() {
    setEdit(null);
    setName("");
    setScopes(
      ["services:read", "findings:read"].filter((s) =>
        available.some((a) => a.value === s),
      ),
    );
    setDays(30);
    setOpened(true);
  }
  function editKey(row: Row) {
    setEdit(row);
    setName(row.name);
    setScopes(row.scopes || []);
    setOpened(true);
  }
  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const result = await api(`/api/keys${edit ? `/${edit.id}` : ""}`, {
        method: edit ? "PUT" : "POST",
        body: JSON.stringify({ name, scopes, expires_days: days }),
      });
      setOpened(false);
      if (result.token) setToken(result.token);
      success(edit ? "키 권한을 변경했습니다" : "새 API 키를 발급했습니다");
      await reload();
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  async function doConfirm() {
    if (!confirm) return;
    setBusy(true);
    try {
      const result = await api(
        `/api/keys/${confirm.row.id}${confirm.action === "rotate" ? "/rotate" : ""}`,
        { method: confirm.action === "rotate" ? "POST" : "DELETE" },
      );
      if (result.token) setToken(result.token);
      success(
        confirm.action === "rotate"
          ? "키를 회전했습니다. 기존 키는 즉시 무효화됩니다."
          : "키를 폐기했습니다",
      );
      setConfirm(null);
      await reload();
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        eyebrow="PERSONAL ACCESS"
        title="개인 API 키"
        description="API와 MCP 연결을 위한 개인 키를 발급하고, 권한과 수명 주기를 관리합니다."
        action={
          <Button leftSection={<IconPlus size={18} />} onClick={create}>
            새 키 발급
          </Button>
        }
      />
      <div className="info-strip">
        <span className="info-strip-icon">
          <IconKey size={23} />
        </span>
        <div>
          <strong>필요한 권한만, 필요한 기간만</strong>
          <span>
            키는 발급 · 회전 시 한 번만 표시됩니다. 키 권한은 소유자의 현재 역할
            권한 안에서 적용됩니다.
          </span>
        </div>
      </div>
      <Paper className="data-panel">
        <div className="table-toolbar">
          <Group>
            <h2>내 API 키</h2>
            <Badge variant="light" color="gray">
              {data?.filter((key) => keyState(key) === "active").length || 0}개
              활성
            </Badge>
          </Group>
          <Group className="table-controls" gap="sm">
            <ListSearch
              view={view}
              label="개인 API 키 검색"
              placeholder="키 이름 · 접두사 · 권한 검색"
            />
            <Select
              aria-label="API 키 상태 필터"
              placeholder="모든 상태"
              data={Object.entries(keyStateLabels).map(([value, label]) => ({
                value,
                label,
              }))}
              value={view.filters.status || null}
              onChange={(value) => view.setFilter("status", value || "")}
              clearable
              size="sm"
              w={130}
            />
            <Select
              aria-label="API 키 권한 필터"
              placeholder="모든 권한"
              data={scopesOptions}
              value={view.filters.scope || null}
              onChange={(value) => view.setFilter("scope", value || "")}
              clearable
              searchable
              size="sm"
              w={170}
            />
            <ListReset view={view} />
            <ActionIcon
              aria-label="키 목록 새로고침"
              variant="default"
              onClick={reload}
            >
              <IconRefresh size={18} />
            </ActionIcon>
          </Group>
        </div>
        <ListTools
          view={view}
          loading={loading}
          failed={!!error}
          filterLabels={{
            status: {
              label: "상태",
              value: (value) =>
                keyStateLabels[value as keyof typeof keyStateLabels] || value,
            },
            scope: {
              label: "권한",
              value: (value) => scopeNames[value] || value,
            },
          }}
        />
        <LoadState loading={loading} error={error} reload={reload} />
        {!loading &&
          !error &&
          (view.rows.length ? (
            <TableViewport view={view} label="개인 API 키" minWidth={980}>
              <Table verticalSpacing="md" horizontalSpacing="lg">
                <Table.Thead>
                  <Table.Tr>
                    <SortHeader view={view} column="name">
                      키 이름
                    </SortHeader>
                    <SortHeader view={view} column="scopes">
                      권한
                    </SortHeader>
                    <SortHeader view={view} column="created_at">
                      발급 일시
                    </SortHeader>
                    <SortHeader view={view} column="expires_at">
                      만료 일자
                    </SortHeader>
                    <SortHeader view={view} column="last_used_at">
                      최근 사용
                    </SortHeader>
                    <SortHeader view={view} column="status">
                      상태
                    </SortHeader>
                    <Table.Th>관리</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {view.rows.map((k) => (
                    <Table.Tr key={k.id}>
                      <Table.Td>
                        <Text fw={600}>{k.name}</Text>
                        <Code>{k.prefix}••••••</Code>
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4} maw={260}>
                          {(k.scopes || []).map((s: string) => (
                            <Badge
                              key={s}
                              variant="light"
                              color="gray"
                              radius="sm"
                            >
                              {scopeNames[s] || s}
                            </Badge>
                          ))}
                        </Group>
                      </Table.Td>
                      <Table.Td>{dateText(k.created_at)}</Table.Td>
                      <Table.Td>{fullDate(k.expires_at)}</Table.Td>
                      <Table.Td>{dateText(k.last_used_at)}</Table.Td>
                      <Table.Td>
                        <Badge
                          color={
                            keyState(k) === "revoked"
                              ? "gray"
                              : keyState(k) === "expired"
                                ? "orange"
                                : "teal"
                          }
                          variant="light"
                        >
                          {keyStateLabels[keyState(k)]}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        {!k.revoked_at && (
                          <Group gap={3}>
                            <Tooltip label="권한 수정">
                              <ActionIcon
                                aria-label={`${k.name} 권한 수정`}
                                variant="subtle"
                                color="gray"
                                onClick={() => editKey(k)}
                              >
                                <IconEdit size={17} />
                              </ActionIcon>
                            </Tooltip>
                            <Tooltip label="키 회전">
                              <ActionIcon
                                aria-label={`${k.name} 키 회전`}
                                variant="subtle"
                                onClick={() =>
                                  setConfirm({ row: k, action: "rotate" })
                                }
                              >
                                <IconRotateClockwise size={17} />
                              </ActionIcon>
                            </Tooltip>
                            <Tooltip label="키 폐기">
                              <ActionIcon
                                aria-label={`${k.name} 키 폐기`}
                                color="red"
                                variant="subtle"
                                onClick={() =>
                                  setConfirm({ row: k, action: "revoke" })
                                }
                              >
                                <IconTrash size={17} />
                              </ActionIcon>
                            </Tooltip>
                          </Group>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </TableViewport>
          ) : (
            <Empty
              title={
                data?.length
                  ? "조건에 맞는 API 키가 없습니다"
                  : "발급한 API 키가 없습니다"
              }
              description={
                data?.length
                  ? "검색어나 상태·권한 필터를 변경하세요."
                  : "연동하려는 시스템에 필요한 권한을 선택하여 첫 번째 키를 발급하세요."
              }
              action={
                !data?.length ? (
                  <Button variant="light" onClick={create}>
                    새 키 발급
                  </Button>
                ) : undefined
              }
            />
          ))}
        {!loading && !error && <ListPagination view={view} totalLabel="개" />}
      </Paper>
      <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="xl" mt="xl">
        <Paper className="content-card">
          <h2>REST API 연결</h2>
          <Text c="dimmed" size="sm" mb="md">
            Bearer 헤더에 발급한 키를 지정합니다.
          </Text>
          <Code
            block
          >{`curl '${window.location.origin}/api/services' \\\n  -H 'Authorization: Bearer YOUR_HUNTER_KEY'`}</Code>
          <Button
            component="a"
            href="/api/openapi.json"
            target="_blank"
            variant="subtle"
            size="sm"
            mt="md"
            rightSection={<IconExternalLink size={16} />}
          >
            OpenAPI 명세 보기
          </Button>
        </Paper>
        <Paper className="content-card">
          <h2>MCP 연결</h2>
          <Text c="dimmed" size="sm" mb="md">
            HTTP MCP 주소와 개인 키로 AI 클라이언트를 연결하세요.
          </Text>
          <Code block>
            {JSON.stringify(
              {
                url: `${window.location.origin}/mcp`,
                headers: { Authorization: "Bearer YOUR_HUNTER_KEY" },
              },
              null,
              2,
            )}
          </Code>
          <Text c="dimmed" size="sm" mt="md">
            서비스 조회, 발견 건 조회, 정책을 적용한 진단 요청 도구를
            제공합니다.
          </Text>
        </Paper>
      </SimpleGrid>
      <Modal
        opened={opened}
        onClose={() => setOpened(false)}
        title={edit ? "키 이름 · 권한 수정" : "새 개인 API 키 발급"}
        size="lg"
      >
        <form onSubmit={save}>
          <Stack>
            <TextInput
              label="키 이름"
              placeholder="예: 사내 AI 도우미"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            <MultiSelect
              label="접근 권한"
              description="이 키를 사용할 서비스에 필요한 권한만 선택하세요."
              data={available}
              value={scopes}
              onChange={setScopes}
              searchable
              required
            />
            {!edit && (
              <NumberInput
                label="유효 기간 (일)"
                value={days}
                min={1}
                max={365}
                onChange={setDays}
                required
              />
            )}
            <Group justify="flex-end" mt="md">
              <Button variant="default" onClick={() => setOpened(false)}>
                취소
              </Button>
              <Button type="submit" loading={busy}>
                {edit ? "저장" : "키 발급"}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
      <Modal
        opened={!!token}
        onClose={() => setToken("")}
        title="API 키를 안전한 곳에 저장하세요"
        size="lg"
        closeOnClickOutside={false}
      >
        <Alert color="orange" mb="lg">
          전체 키는 지금 한 번만 표시됩니다. 이 창을 닫으면 다시 확인할 수
          없습니다.
        </Alert>
        <Code block style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
          {token}
        </Code>
        <Group justify="flex-end" mt="lg">
          <Button
            variant="light"
            leftSection={<IconCopy size={17} />}
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(token);
                success("키를 복사했습니다");
              } catch {
                showError(
                  new Error(
                    "브라우저의 복사 권한을 확인하거나 키를 직접 선택해 복사하세요.",
                  ),
                );
              }
            }}
          >
            복사
          </Button>
          <Button onClick={() => setToken("")}>저장 완료</Button>
        </Group>
      </Modal>
      <Modal
        opened={!!confirm}
        onClose={() => setConfirm(null)}
        title={
          confirm?.action === "rotate" ? "개인 API 키 회전" : "개인 API 키 폐기"
        }
      >
        <Text>
          ‘{confirm?.row.name}’ 키를{" "}
          {confirm?.action === "rotate" ? "회전" : "폐기"}하시겠습니까?
        </Text>
        <Alert mt="lg" color="orange">
          기존 키는 즉시 사용할 수 없게 됩니다.
          {confirm?.action === "rotate" &&
            " 연결된 서비스의 인증 키를 새 키로 변경해 주세요."}
        </Alert>
        <Group justify="flex-end" mt="xl">
          <Button variant="default" onClick={() => setConfirm(null)}>
            취소
          </Button>
          <Button
            color={confirm?.action === "revoke" ? "red" : "teal"}
            loading={busy}
            onClick={doConfirm}
          >
            {confirm?.action === "rotate" ? "키 회전" : "키 폐기"}
          </Button>
        </Group>
      </Modal>
    </>
  );
}
export function UsersPage() {
  const { data, loading, error, reload } = useData<Row[]>("/api/users");
  const view = useListView<Row>({
    rows: data || [],
    columns: [
      {
        key: "name",
        label: "사용자",
        value: (row) => row.name || row.username,
      },
      { key: "username", label: "아이디", value: (row) => row.username },
      { key: "team", label: "담당 조직", value: (row) => row.team || "미지정" },
      { key: "role", label: "역할", value: (row) => label(row.role) },
      {
        key: "status",
        label: "상태",
        value: (row) => (row.disabled ? "비활성" : "활성"),
      },
      {
        key: "created_at",
        label: "등록 일시",
        value: (row) => sortableDate(row.created_at),
      },
    ],
    searchValues: (row) => [
      row.role,
      row.sso ? "SSO 로그인" : "로컬 로그인",
      row.created_at,
      dateText(row.created_at),
    ],
    defaultSort: { key: "created_at", direction: "desc" },
    filters: {
      role: (row, value) => row.role === value,
      status: (row, value) => (row.disabled ? "disabled" : "active") === value,
      team: (row, value) => row.team === value,
    },
  });
  const teams = [
    ...new Set(
      (data || []).map((row) => String(row.team || "")).filter(Boolean),
    ),
  ].sort((a, b) => a.localeCompare(b, "ko"));
  const [opened, setOpened] = useState(false),
    [edit, setEdit] = useState<Row | null>(null),
    [values, setValues] = useState<Row>({}),
    [busy, setBusy] = useState(false);
  function open(row?: Row) {
    setEdit(row || null);
    setValues(
      row
        ? { ...row, password: "" }
        : {
            username: "",
            name: "",
            password: "",
            role: "viewer",
            disabled: false,
          },
    );
    setOpened(true);
  }
  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const body = { ...values };
      if (edit && !body.password) delete body.password;
      await api(`/api/users${edit ? `/${edit.id}` : ""}`, {
        method: edit ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      success("사용자 정보를 저장했습니다");
      setOpened(false);
      await reload();
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        eyebrow="IDENTITY & ACCESS"
        title="사용자 · 권한"
        description="서비스 사용자를 등록하고 역할과 계정 접근 상태를 관리합니다."
        action={
          <Button leftSection={<IconPlus size={18} />} onClick={() => open()}>
            사용자 등록
          </Button>
        }
      />
      <Paper className="data-panel">
        <div className="table-toolbar">
          <h2>
            사용자 목록{" "}
            <Badge ml="sm" color="gray" variant="light">
              {data?.length || 0}
            </Badge>
          </h2>
          <Group className="table-controls" gap="sm">
            <ListSearch
              view={view}
              label="사용자 검색"
              placeholder="이름 · 아이디 · 조직 · 역할 검색"
            />
            <Select
              aria-label="사용자 역할 필터"
              placeholder="모든 역할"
              data={["viewer", "analyst", "lead", "admin"].map((role) => ({
                value: role,
                label: label(role),
              }))}
              value={view.filters.role || null}
              onChange={(value) => view.setFilter("role", value || "")}
              clearable
              size="sm"
              w={135}
            />
            <Select
              aria-label="사용자 상태 필터"
              placeholder="모든 상태"
              data={[
                { value: "active", label: "활성" },
                { value: "disabled", label: "비활성" },
              ]}
              value={view.filters.status || null}
              onChange={(value) => view.setFilter("status", value || "")}
              clearable
              size="sm"
              w={130}
            />
            <Select
              aria-label="사용자 조직 필터"
              placeholder="모든 조직"
              data={teams}
              value={view.filters.team || null}
              onChange={(value) => view.setFilter("team", value || "")}
              clearable
              searchable
              size="sm"
              w={150}
            />
            <ListReset view={view} />
          </Group>
        </div>
        <ListTools
          view={view}
          loading={loading}
          failed={!!error}
          filterLabels={{
            role: { label: "역할" },
            status: {
              label: "상태",
              value: (value) =>
                value === "active"
                  ? "활성"
                  : value === "disabled"
                    ? "비활성"
                    : value,
            },
            team: { label: "담당 조직" },
          }}
        />
        <LoadState loading={loading} error={error} reload={reload} />
        {!loading &&
          !error &&
          (view.rows.length ? (
            <TableViewport view={view} label="사용자" minWidth={940}>
              <Table
                verticalSpacing="md"
                horizontalSpacing="lg"
                highlightOnHover
              >
                <Table.Thead>
                  <Table.Tr>
                    <SortHeader view={view} column="name">
                      사용자
                    </SortHeader>
                    <SortHeader view={view} column="username">
                      아이디
                    </SortHeader>
                    <SortHeader view={view} column="team">
                      담당 조직
                    </SortHeader>
                    <SortHeader view={view} column="role">
                      역할
                    </SortHeader>
                    <SortHeader view={view} column="status">
                      상태
                    </SortHeader>
                    <SortHeader view={view} column="created_at">
                      등록 일시
                    </SortHeader>
                    <Table.Th>관리</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {view.rows.map((u) => (
                    <Table.Tr key={u.id}>
                      <Table.Td>
                        <Group>
                          <span className="user-avatar">
                            {(u.name || u.username)[0]}
                          </span>
                          <Text fw={600}>{u.name}</Text>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Text>{u.username}</Text>
                        <Text size="xs" c="dimmed">
                          {u.sso ? "SSO 로그인" : "로컬 로그인"}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        {u.team || <Text c="dimmed">미지정</Text>}
                      </Table.Td>
                      <Table.Td>
                        <Badge
                          color={u.role === "admin" ? "teal" : "gray"}
                          variant="light"
                          size="lg"
                        >
                          {label(u.role)}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Badge
                          color={u.disabled ? "gray" : "teal"}
                          variant="light"
                        >
                          {u.disabled ? "비활성" : "활성"}
                        </Badge>
                      </Table.Td>
                      <Table.Td>{dateText(u.created_at)}</Table.Td>
                      <Table.Td>
                        <Button
                          variant="subtle"
                          size="compact-sm"
                          onClick={() => open(u)}
                        >
                          수정
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </TableViewport>
          ) : (
            <Empty
              title="일치하는 사용자가 없습니다"
              description="검색어나 역할·상태·조직 필터를 변경하세요."
            />
          ))}
        {!loading && !error && <ListPagination view={view} totalLabel="명" />}
      </Paper>
      <Alert mt="xl" color="teal" title="변경 가능한 역할 권한">
        역할별 기능 권한은 서비스 설정 → 역할 · 권한에서 변경할 수 있습니다.
        계정 비활성화 시 해당 사용자의 접근과 개인 API 키 사용이 제한됩니다.
      </Alert>
      <Modal
        opened={opened}
        onClose={() => setOpened(false)}
        title={edit ? "사용자 수정" : "새 사용자 등록"}
      >
        <form onSubmit={save}>
          <Stack>
            <TextInput
              label="아이디"
              required
              disabled={!!edit}
              value={values.username || ""}
              onChange={(e) =>
                setValues({ ...values, username: e.target.value })
              }
            />
            <TextInput
              label="이름"
              required
              value={values.name || ""}
              onChange={(e) => setValues({ ...values, name: e.target.value })}
            />
            <TextInput
              label="담당 조직"
              description="팀장은 이 조직의 서비스에만 접근합니다."
              value={values.team || ""}
              onChange={(e) => setValues({ ...values, team: e.target.value })}
            />
            <Select
              label="역할"
              data={["viewer", "analyst", "lead", "admin"].map((r) => ({
                value: r,
                label: label(r),
              }))}
              value={values.role}
              onChange={(v) => setValues({ ...values, role: v })}
            />
            <PasswordInput
              label={edit ? "비밀번호 재설정 (선택)" : "초기 비밀번호"}
              description="12자 이상 입력하세요."
              required={!edit}
              minLength={12}
              value={values.password || ""}
              autoComplete="new-password"
              onChange={(e) =>
                setValues({ ...values, password: e.target.value })
              }
            />
            {edit && (
              <Switch
                label="계정 비활성화"
                checked={!!values.disabled}
                onChange={(e) =>
                  setValues({ ...values, disabled: e.currentTarget.checked })
                }
              />
            )}
            <Group justify="flex-end" mt="md">
              <Button variant="default" onClick={() => setOpened(false)}>
                취소
              </Button>
              <Button loading={busy} type="submit">
                저장
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </>
  );
}
export function AuditPage() {
  const { data, loading, error, reload } = useData<Row[]>("/api/audit");
  const [detail, setDetail] = useState<Row | null>(null);
  const view = useListView<Row>({
    rows: data || [],
    columns: [
      {
        key: "created_at",
        label: "수행 일시",
        value: (row) => sortableDate(row.created_at),
      },
      {
        key: "username",
        label: "사용자",
        value: (row) => row.username || "시스템",
      },
      { key: "action", label: "작업", value: (row) => row.action },
      { key: "target", label: "대상", value: (row) => row.target || "—" },
    ],
    searchValues: (row) => [
      row.created_at,
      dateText(row.created_at),
      JSON.stringify(row.detail || {}),
    ],
    defaultSort: { key: "created_at", direction: "desc" },
    filters: {
      action: (row, value) => row.action === value,
      actor: (row, value) => (row.username || "시스템") === value,
      period: (row, value) => {
        const days = { day: 1, week: 7, month: 30 }[
          value as "day" | "week" | "month"
        ];
        return (
          !days ||
          (sortableDate(row.created_at) || 0) >= Date.now() - days * 86400000
        );
      },
    },
  });
  const actions = [
    ...new Set(
      (data || []).map((row) => String(row.action || "")).filter(Boolean),
    ),
  ].sort((a, b) => a.localeCompare(b, "ko"));
  const actors = [
    ...new Set((data || []).map((row) => String(row.username || "시스템"))),
  ].sort((a, b) => a.localeCompare(b, "ko"));
  return (
    <>
      <PageHeader
        eyebrow="AUDIT & TRACEABILITY"
        title="감사 기록"
        description="누가, 언제, 어떤 작업을 수행했는지 확인합니다. 민감한 인증 정보는 기록에서 제외됩니다."
        action={
          <Button
            variant="default"
            leftSection={<IconRefresh size={18} />}
            onClick={reload}
          >
            새로고침
          </Button>
        }
      />
      <Paper className="data-panel">
        <div className="table-toolbar">
          <h2>
            활동 기록{" "}
            <Badge variant="light" color="gray">
              {data?.length || 0}
            </Badge>
          </h2>
          <Group className="table-controls" gap="sm">
            <ListSearch
              view={view}
              label="감사 기록 검색"
              placeholder="사용자 · 작업 · 대상 · 상세 검색"
            />
            <Select
              aria-label="감사 작업 필터"
              placeholder="모든 작업"
              data={actions}
              value={view.filters.action || null}
              onChange={(value) => view.setFilter("action", value || "")}
              searchable
              clearable
              size="sm"
              w={175}
            />
            <Select
              aria-label="감사 사용자 필터"
              placeholder="모든 사용자"
              data={actors}
              value={view.filters.actor || null}
              onChange={(value) => view.setFilter("actor", value || "")}
              searchable
              clearable
              size="sm"
              w={150}
            />
            <Select
              aria-label="감사 기간 필터"
              placeholder="전체 기간"
              data={[
                { value: "day", label: "최근 24시간" },
                { value: "week", label: "최근 7일" },
                { value: "month", label: "최근 30일" },
              ]}
              value={view.filters.period || null}
              onChange={(value) => view.setFilter("period", value || "")}
              clearable
              size="sm"
              w={145}
            />
            <ListReset view={view} />
          </Group>
        </div>
        <ListTools
          view={view}
          loading={loading}
          failed={!!error}
          filterLabels={{
            action: { label: "작업" },
            actor: { label: "수행자" },
            period: {
              label: "기간",
              value: (value) =>
                ({ day: "최근 24시간", week: "최근 7일", month: "최근 30일" })[
                  value
                ] || value,
            },
          }}
        />
        <LoadState loading={loading} error={error} reload={reload} />
        {!loading &&
          !error &&
          (view.rows.length ? (
            <TableViewport view={view} label="감사 기록" minWidth={800}>
              <Table
                verticalSpacing="md"
                horizontalSpacing="lg"
                highlightOnHover
              >
                <Table.Thead>
                  <Table.Tr>
                    <SortHeader view={view} column="created_at">
                      수행 일시
                    </SortHeader>
                    <SortHeader view={view} column="username">
                      사용자
                    </SortHeader>
                    <SortHeader view={view} column="action">
                      작업
                    </SortHeader>
                    <SortHeader view={view} column="target">
                      대상
                    </SortHeader>
                    <Table.Th>상세</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {view.rows.map((r) => (
                    <Table.Tr key={r.id}>
                      <Table.Td>{dateText(r.created_at)}</Table.Td>
                      <Table.Td>{r.username || "시스템"}</Table.Td>
                      <Table.Td>
                        <Code>{r.action}</Code>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" maw={300} truncate>
                          {r.target || "—"}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Button
                          variant="subtle"
                          size="compact-sm"
                          onClick={() => setDetail(r)}
                        >
                          기록 보기
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </TableViewport>
          ) : (
            <Empty
              title={
                data?.length
                  ? "조건에 맞는 감사 기록이 없습니다"
                  : "감사 기록이 없습니다"
              }
              description={
                data?.length
                  ? "검색어나 작업·사용자·기간 필터를 변경하세요."
                  : "사용자의 관리 작업이 발생하면 감사 기록이 표시됩니다."
              }
            />
          ))}
        {!loading && !error && (
          <ListPagination view={view} totalLabel="건" limit={1000} />
        )}
      </Paper>
      <Modal
        opened={!!detail}
        onClose={() => setDetail(null)}
        title="감사 기록 상세"
        size="lg"
      >
        <Code block>{JSON.stringify(detail, null, 2)}</Code>
      </Modal>
    </>
  );
}
