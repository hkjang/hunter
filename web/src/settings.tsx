import { useEffect, useState } from "react";
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
  IconCheck,
  IconCopy,
  IconEdit,
  IconExternalLink,
  IconKey,
  IconLock,
  IconPlus,
  IconRefresh,
  IconRotateClockwise,
  IconSearch,
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
const scopesOptions = allScopes.map((s) => ({
  value: s,
  label: `${scopeNames[s]} · ${s}`,
}));
const settingGroups: [string, string, any][] = [
  ["general", "기본 정보", IconSettings],
  ["oidc", "SSO · 로그인", IconShieldCheck],
  ["ai", "AI 분석", IconSparkles],
  ["workflow", "검토 · 승인", IconAdjustments],
  ["security", "보안 · 세션", IconLock],
  ["roles", "역할 · 권한", IconUsers],
];
const settingFields: Record<string, Field[]> = {
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
        "Keycloak의 리다이렉트 URI와 쿠키 보안 설정에 사용합니다. 운영 환경에서는 HTTPS 주소를 지정하세요.",
    },
  ],
  oidc: [
    {
      key: "enabled",
      label: "Keycloak OIDC 로그인 사용",
      type: "switch",
      default: false,
    },
    {
      key: "issuer",
      label: "Issuer URL",
      placeholder: "https://keycloak.internal/realms/company",
      description:
        "Realm의 Issuer만 입력하면 OIDC 메타데이터와 서명키를 자동 검색합니다.",
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
        "사내 HTTPS 인증기관의 인증서 체인을 붙여 넣으세요. OIDC, AI, 연동 및 진단의 TLS 검증에 적용됩니다.",
    },
  ],
};
export function SettingsPage() {
  const { data, loading, error, reload } = useData<Row>("/api/settings");
  const { refreshConfig } = useSession();
  const [tab, setTab] = useState<string | null>("general"),
    [values, setValues] = useState<Row>({}),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    if (data) {
      const next: Row = {};
      for (const [g] of settingGroups)
        next[g] =
          g === "roles"
            ? data.roles || {}
            : initialValues(settingFields[g] || [], data[g]);
      setValues(next);
    }
  }, [data]);
  async function save() {
    if (!tab) return;
    setBusy(true);
    try {
      await api(`/api/settings/${tab}`, {
        method: "PUT",
        body: JSON.stringify(values[tab] || {}),
      });
      success("서비스 설정을 저장했습니다");
      refreshConfig();
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
        eyebrow="ADMINISTRATION"
        title="서비스 설정"
        description="서비스 운영에 필요한 모든 설정을 관리합니다. 변경 사항은 데이터베이스에 안전하게 저장됩니다."
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
              >
                <Icon size={20} />
                <span>{title}</span>
              </button>
            ))}
          </div>
          <Paper className="settings-panel">
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
                    : "워크스페이스의 설정을 확인하고 변경하세요."}
                </p>
              </div>
            </div>
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
            ) : (
              <FieldForm
                fields={settingFields[tab || "general"] || []}
                values={values[tab || "general"] || {}}
                setValues={(v) =>
                  setValues({ ...values, [tab || "general"]: v })
                }
              />
            )}
            {tab === "oidc" && (
              <Alert color="teal" mt="xl" title="Keycloak 연결 안내">
                <Text size="sm">
                  Client authentication을 활성화하고 Standard flow를 사용하세요.
                  Valid redirect URI에 다음 주소를 등록하면 됩니다.
                </Text>
                <Code
                  block
                  mt="sm"
                >{`${values.general?.public_url || window.location.origin}/api/auth/oidc/callback`}</Code>
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
                  SSO를 활성화해도 초기 로컬 관리자 계정은 로그인할 수 있습니다.
                </Text>
              </Alert>
            )}
            {tab === "ai" && (
              <Alert
                color="teal"
                mt="xl"
                title="기본 스트리밍 · 사람 중심의 분석"
              >
                <Text size="sm">
                  AI 응답은 SSE로 실시간 표시합니다. AI는 발견 내용을 설명하고
                  개선안을 제안하며, 임의 진단 실행이나 취약점 자동 확정은
                  수행하지 않습니다.
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
                  팀장 검토 사용 여부와 관계없이 네트워크 진단에는 관리자에게
                  승인받은 서비스와 유효한 진단 허용 범위가 필요합니다.
                </Text>
              </Alert>
            )}
            <Divider my="xl" />
            <Group justify="space-between">
              <Text size="sm" c="dimmed">
                환경변수 변경이나 재배포 없이 관리할 수 있습니다.
              </Text>
              <Button
                loading={busy}
                leftSection={<IconCheck size={18} />}
                onClick={save}
              >
                설정 저장
              </Button>
            </Group>
          </Paper>
        </div>
      )}
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
    [busy, setBusy] = useState(false);
  useEffect(() => {
    if (data) {
      setName(data.name || data.user?.name || "");
      setPref(data.preferences || data.user?.preferences || {});
    }
  }, [data]);
  async function save() {
    setBusy(true);
    try {
      await api("/api/profile", {
        method: "PUT",
        body: JSON.stringify({ name, preferences: pref }),
      });
      if (user) setUser({ ...user, name, preferences: pref });
      success("프로필을 저장했습니다");
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  async function changePassword(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      showError(new Error("새 비밀번호가 일치하지 않습니다."));
      return;
    }
    setBusy(true);
    try {
      await api("/api/profile/password", {
        method: "POST",
        body: JSON.stringify({
          current_password: current,
          new_password: password,
        }),
      });
      success("비밀번호를 변경했습니다");
      setCurrent("");
      setPassword("");
      setConfirm("");
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
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
            <Stack mt="xl">
              <TextInput label="아이디" value={user?.username || ""} disabled />
              <TextInput
                label="표시 이름"
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
              <Group justify="flex-end">
                <Button loading={busy} onClick={save}>
                  프로필 저장
                </Button>
              </Group>
            </Stack>
          </Paper>
          <Paper className="content-card">
            <h2>비밀번호 변경</h2>
            <Text c="dimmed" size="sm" mb="xl">
              로컬 계정의 비밀번호를 변경합니다. SSO 비밀번호는 사내 인증
              시스템에서 관리하세요.
            </Text>
            <form onSubmit={changePassword}>
              <Stack>
                <PasswordInput
                  label="현재 비밀번호"
                  required
                  autoComplete="current-password"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                />
                <PasswordInput
                  label="새 비밀번호"
                  description="12자 이상의 비밀번호를 사용하세요."
                  minLength={12}
                  required
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <PasswordInput
                  label="새 비밀번호 확인"
                  required
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                />
                <Group justify="flex-end" mt="sm">
                  <Button variant="light" type="submit" loading={busy}>
                    비밀번호 변경
                  </Button>
                </Group>
              </Stack>
            </form>
          </Paper>
        </SimpleGrid>
      )}
    </>
  );
}
export function KeysPage() {
  const { user } = useSession();
  const { data, loading, error, reload } = useData<Row[]>("/api/keys");
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
              {data?.filter((k) => !k.revoked_at).length || 0}개 활성
            </Badge>
          </Group>
          <ActionIcon
            aria-label="키 목록 새로고침"
            variant="default"
            onClick={reload}
          >
            <IconRefresh size={18} />
          </ActionIcon>
        </div>
        <LoadState loading={loading} error={error} reload={reload} />
        {!loading &&
          !error &&
          (data?.length ? (
            <Table.ScrollContainer minWidth={800}>
              <Table verticalSpacing="md" horizontalSpacing="lg">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>키 이름</Table.Th>
                    <Table.Th>권한</Table.Th>
                    <Table.Th>만료 일자</Table.Th>
                    <Table.Th>최근 사용</Table.Th>
                    <Table.Th>상태</Table.Th>
                    <Table.Th>관리</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data.map((k) => (
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
                      <Table.Td>{fullDate(k.expires_at)}</Table.Td>
                      <Table.Td>{dateText(k.last_used_at)}</Table.Td>
                      <Table.Td>
                        <Badge
                          color={
                            k.revoked_at
                              ? "gray"
                              : new Date(k.expires_at) < new Date()
                                ? "orange"
                                : "teal"
                          }
                          variant="light"
                        >
                          {k.revoked_at
                            ? "폐기됨"
                            : new Date(k.expires_at) < new Date()
                              ? "만료됨"
                              : "활성"}
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
            </Table.ScrollContainer>
          ) : (
            <Empty
              title="발급한 API 키가 없습니다"
              description="연동하려는 시스템에 필요한 권한을 선택하여 첫 번째 키를 발급하세요."
              action={
                <Button variant="light" onClick={create}>
                  새 키 발급
                </Button>
              }
            />
          ))}
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
  const [query, setQuery] = useState(""),
    [opened, setOpened] = useState(false),
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
          <TextInput
            placeholder="이름 또는 아이디 검색"
            aria-label="사용자 검색"
            leftSection={<IconSearch size={17} />}
            size="sm"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <LoadState loading={loading} error={error} reload={reload} />
        {!loading &&
          !error &&
          (data?.filter((u) => `${u.name} ${u.username}`.includes(query))
            .length ? (
            <Table.ScrollContainer minWidth={720}>
              <Table
                verticalSpacing="md"
                horizontalSpacing="lg"
                highlightOnHover
              >
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>사용자</Table.Th>
                    <Table.Th>아이디</Table.Th>
                    <Table.Th>역할</Table.Th>
                    <Table.Th>상태</Table.Th>
                    <Table.Th>등록 일시</Table.Th>
                    <Table.Th>관리</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data
                    .filter((u) => `${u.name} ${u.username}`.includes(query))
                    .map((u) => (
                      <Table.Tr key={u.id}>
                        <Table.Td>
                          <Group>
                            <span className="user-avatar">
                              {(u.name || u.username)[0]}
                            </span>
                            <Text fw={600}>{u.name}</Text>
                          </Group>
                        </Table.Td>
                        <Table.Td>{u.username}</Table.Td>
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
            </Table.ScrollContainer>
          ) : (
            <Empty title="일치하는 사용자가 없습니다" />
          ))}
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
  const [query, setQuery] = useState(""),
    [detail, setDetail] = useState<Row | null>(null);
  const rows = (data || []).filter((r) =>
    JSON.stringify(r).toLowerCase().includes(query.toLowerCase()),
  );
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
          <TextInput
            aria-label="감사 기록 검색"
            placeholder="사용자 · 작업 · 대상 검색"
            leftSection={<IconSearch size={17} />}
            value={query}
            size="sm"
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <LoadState loading={loading} error={error} reload={reload} />
        {!loading &&
          !error &&
          (rows.length ? (
            <Table.ScrollContainer minWidth={800}>
              <Table
                verticalSpacing="md"
                horizontalSpacing="lg"
                highlightOnHover
              >
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>수행 일시</Table.Th>
                    <Table.Th>사용자</Table.Th>
                    <Table.Th>작업</Table.Th>
                    <Table.Th>대상</Table.Th>
                    <Table.Th>상세</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {rows.map((r) => (
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
            </Table.ScrollContainer>
          ) : (
            <Empty
              title="감사 기록이 없습니다"
              description="사용자의 관리 작업이 발생하면 감사 기록이 표시됩니다."
            />
          ))}
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
