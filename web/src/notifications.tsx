import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Checkbox,
  Code,
  Divider,
  Drawer,
  Group,
  JsonInput,
  Modal,
  MultiSelect,
  NumberInput,
  Pagination,
  Paper,
  PasswordInput,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  TagsInput,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import {
  IconArrowDown,
  IconArrowUp,
  IconArrowsSort,
  IconBell,
  IconCheck,
  IconEdit,
  IconExternalLink,
  IconHistory,
  IconMail,
  IconMessage,
  IconPlayerPlay,
  IconPlus,
  IconRefresh,
  IconSend,
  IconSettings,
  IconTrash,
  IconX,
} from "@tabler/icons-react";
import {
  APIError,
  api,
  dateText,
  label,
  showError,
  success,
  useCan,
  useData,
  type Row,
} from "./api";
import { Empty, LoadState, PageHeader } from "./components";
import { FormFeedback, SaveStatus, useUnsavedChanges } from "./form-feedback";
import { changed } from "./form-state";
import {
  WorkflowTable,
  Metric,
  type WorkflowColumn,
} from "./workflow-components";
import { switchWorkflowTab } from "./workflow-navigation";
import { copyText } from "./list-export";
import {
  channelConfigDefaults,
  channelDraft,
  channelKinds,
  channelPayload,
  deliveryStatuses,
  notificationEvents,
  notificationHistoryQuery,
  notificationPayloadPresets,
  notificationTabs,
  notificationVariables,
  ruleDraft,
  rulePayload,
  type ChannelDraft,
  type ChannelKind,
  type NotificationTab,
  type RuleDraft,
  type SecretMode,
} from "./notification-state";
import {
  notificationAPI,
  type NotificationChannel,
  type NotificationRule,
  type NotificationDelivery,
  type DeliveryDetail,
  type DeliveryList,
  type NotificationPreview,
} from "./notification-api";
import "./notifications.css";

const typeLabel = (value: string) =>
  channelKinds.find((item) => item.value === value)?.label || value;
const eventLabel = (value: string) =>
  value === "manual.test"
    ? "관리자 수동 테스트"
    : notificationEvents.find((item) => item.value === value)?.label || value;
const bytes = (value: string) => new TextEncoder().encode(value).length;
function DeliveryStatus({ status }: { status: string }) {
  const value = deliveryStatuses.find((item) => item.value === status);
  return (
    <Badge color={value?.color || "gray"} variant="light" size="lg">
      {value?.label || status}
    </Badge>
  );
}
function ChannelIcon({ type }: { type: string }) {
  const Icon =
    type === "smtp"
      ? IconMail
      : type === "sms"
        ? IconMessage
        : type === "kakao"
          ? IconMessage
          : IconSend;
  return (
    <span className="notification-type-icon">
      <Icon size={21} />
    </span>
  );
}
function GuardedEditor({
  title,
  children,
  dirty,
  busy,
  error,
  onClose,
  onSubmit,
  submitLabel,
  extra,
}: {
  title: string;
  children: ReactNode;
  dirty: boolean;
  busy: boolean;
  error: string;
  onClose: () => void;
  onSubmit: (event: React.FormEvent) => void;
  submitLabel: string;
  extra?: ReactNode;
}) {
  const [confirm, setConfirm] = useState(false);
  useUnsavedChanges(dirty || busy);
  const close = () => {
    if (busy) return;
    if (dirty) setConfirm(true);
    else onClose();
  };
  return (
    <>
      <Modal
        opened
        onClose={close}
        title={<strong>{title}</strong>}
        size="xl"
        closeOnEscape={!busy}
        closeOnClickOutside={!busy}
        withCloseButton={!busy}
      >
        <form noValidate onSubmit={onSubmit}>
          <Stack gap="lg">
            <FormFeedback error={error} />
            {dirty && <SaveStatus dirty saving={busy} />}
            <fieldset className="form-fields" disabled={busy}>
              <Stack gap="lg">{children}</Stack>
            </fieldset>
            <Group
              justify="space-between"
              className="notification-action-footer"
            >
              <Group>{extra}</Group>
              <Group>
                <Button variant="default" onClick={close} disabled={busy}>
                  취소
                </Button>
                <Button type="submit" loading={busy}>
                  {submitLabel}
                </Button>
              </Group>
            </Group>
          </Stack>
        </form>
      </Modal>
      <Modal
        opened={confirm}
        onClose={() => setConfirm(false)}
        title="작성 중인 내용을 닫을까요?"
        zIndex={350}
        size="sm"
      >
        <Text>
          저장하지 않은 입력이 있습니다. 계속 작성하거나 입력을 버리고 닫을 수
          있습니다.
        </Text>
        <Group justify="flex-end" mt="lg">
          <Button variant="default" onClick={() => setConfirm(false)}>
            계속 작성
          </Button>
          <Button color="red" onClick={onClose}>
            입력 버리고 닫기
          </Button>
        </Group>
      </Modal>
    </>
  );
}
function ConflictReview<T extends { name: string; updated_at: string }>({
  load,
  onUse,
}: {
  load: () => Promise<T>;
  onUse: (value: T) => void;
}) {
  const [latest, setLatest] = useState<T | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  return (
    <>
      <Alert color="orange" title="다른 변경 사항을 먼저 확인하세요">
        <Text size="sm">
          내 입력을 유지했습니다. 최신 자료를 확인한 뒤 선택한 경우에만 입력을
          교체합니다.
        </Text>
        <Button
          variant="light"
          mt="sm"
          loading={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              setLatest(await load());
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          최신 자료 확인
        </Button>
        {error && (
          <Text c="red" mt="xs">
            {error}
          </Text>
        )}
      </Alert>
      <Modal
        opened={!!latest}
        onClose={() => setLatest(null)}
        title="최신 자료 확인"
        zIndex={350}
      >
        <Stack>
          <Text fw={700}>{latest?.name}</Text>
          <Text>최근 수정 {dateText(latest?.updated_at)}</Text>
          <Alert color="orange">
            최신 자료로 다시 작성하면 현재 입력을 교체합니다.
          </Alert>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setLatest(null)}>
              입력 유지
            </Button>
            <Button
              onClick={() => {
                if (latest) onUse(latest);
                setLatest(null);
              }}
            >
              최신 자료로 다시 작성
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
function SecretField({
  draft,
  onChange,
  configured,
  existing,
}: {
  draft: ChannelDraft;
  onChange: (next: ChannelDraft) => void;
  configured: boolean;
  existing: boolean;
}) {
  const noAuth =
    draft.type === "smtp"
      ? draft.config.security === "none"
      : draft.config.auth === "none";
  return (
    <section className="notification-section notification-secret-choice">
      <Group justify="space-between" mb="sm">
        <h3>인증 비밀값</h3>
        <Badge variant="light" color={configured ? "teal" : "gray"}>
          {configured ? "저장된 비밀값 있음" : "미설정"}
        </Badge>
      </Group>
      <Text className="notification-subtle" mb="md">
        암호화하여 저장하며 조회 화면에 원문을 반환하지 않습니다. 정적 헤더에는
        비밀번호나 인증 토큰을 입력하지 마세요.
      </Text>
      {existing && (
        <SegmentedControl
          value={draft.secretMode}
          onChange={(value) =>
            onChange({ ...draft, secretMode: value as SecretMode, secret: "" })
          }
          data={[
            { value: "keep", label: "기존 값 유지" },
            { value: "replace", label: "새 값으로 교체" },
            { value: "clear", label: "저장한 값 삭제" },
          ]}
        />
      )}
      {draft.secretMode === "replace" && (
        <PasswordInput
          mt="md"
          label={
            draft.type === "smtp"
              ? "SMTP 비밀번호"
              : draft.config.auth === "headers"
                ? "인증 헤더 JSON"
                : "API 인증 비밀값"
          }
          description={
            draft.config.auth === "headers"
              ? '예: {"X-API-Key":"토큰","X-API-Secret":"비밀값"}'
              : draft.config.auth === "ncp"
                ? "NCP API 서명용 Secret Key"
                : noAuth
                  ? "인증을 사용하지 않는 연결에서는 비워 두세요."
                  : "비워 두면 기존 값을 유지합니다."
          }
          value={draft.secret}
          disabled={noAuth}
          onChange={(event) =>
            onChange({ ...draft, secret: event.currentTarget.value })
          }
          autoComplete="new-password"
        />
      )}
      {draft.secretMode === "clear" && (
        <Alert mt="md" color="orange">
          저장하면 기존 비밀값을 삭제합니다. 인증이 필요한 채널은 새 값을
          지정하기 전까지 발송할 수 없습니다.
        </Alert>
      )}
    </section>
  );
}
function ChannelEditor({
  source,
  onClose,
  onSaved,
}: {
  source: NotificationChannel | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [original, setOriginal] = useState(source),
    [draft, setDraft] = useState<ChannelDraft>(() =>
      channelDraft(source || undefined),
    );
  const baseline = useRef(draft),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [conflict, setConflict] = useState(false);
  const submitting = useRef(false);
  const [preset, setPreset] = useState<string | null>(null);
  const config: Record<string, unknown> = {
    ...channelConfigDefaults(draft.type),
    ...draft.config,
  };
  const update = (key: string, value: unknown) =>
    setDraft({ ...draft, config: { ...config, [key]: value } });
  const input = (key: string, caption: string, description?: string) => (
    <TextInput
      label={caption}
      description={description}
      value={String(config[key] ?? "")}
      onChange={(event) => update(key, event.currentTarget.value)}
    />
  );
  const restore = (latest: NotificationChannel) => {
    const next = channelDraft(latest);
    setOriginal(latest);
    setDraft(next);
    baseline.current = next;
    setConflict(false);
    setError("");
  };
  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    setError("");
    setConflict(false);
    try {
      const payload = channelPayload(draft, original || undefined);
      submitting.current = true;
      setBusy(true);
      await notificationAPI.saveChannel(payload, original?.id);
      success("알림 채널을 저장했습니다.");
      await onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
      setConflict(e instanceof APIError && e.status === 409);
    } finally {
      setBusy(false);
      submitting.current = false;
    }
  }
  return (
    <GuardedEditor
      title={original ? "발송 채널 수정" : "발송 채널 추가"}
      dirty={changed(baseline.current, draft)}
      busy={busy}
      error={error}
      onClose={onClose}
      onSubmit={save}
      submitLabel="채널 저장"
    >
      {conflict && original && (
        <ConflictReview
          load={async () => {
            const list = await api<{ items: NotificationChannel[] }>(
              "/api/notification-channels",
            );
            const row = list.items.find((item) => item.id === original.id);
            if (!row)
              throw new Error("채널이 삭제되었거나 조회할 수 없습니다.");
            return row;
          }}
          onUse={restore}
        />
      )}
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        <TextInput
          label="채널 이름"
          required
          value={draft.name}
          onChange={(event) =>
            setDraft({ ...draft, name: event.currentTarget.value })
          }
          description="운영자가 구분할 이름 · 최대 200바이트"
        />
        <Select
          label="채널 방식"
          data={channelKinds}
          value={draft.type}
          allowDeselect={false}
          disabled={!!original}
          onChange={(value) => {
            const type = value as ChannelKind;
            setDraft({
              ...channelDraft(),
              name: draft.name,
              type,
              config: channelConfigDefaults(type),
            });
          }}
        />
      </SimpleGrid>
      <Switch
        label="규칙에 연결한 자동 발송 사용"
        description="새 채널은 비활성으로 시작합니다. 저장한 채널을 테스트한 뒤 활성화하세요."
        checked={draft.enabled}
        onChange={(event) =>
          setDraft({ ...draft, enabled: event.currentTarget.checked })
        }
      />
      {draft.type === "smtp" ? (
        <section className="notification-section">
          <h3>SMTP 연결</h3>
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            {input(
              "host",
              "SMTP 서버",
              "호스트 이름 또는 사내 IP. 포트는 아래에서 지정합니다.",
            )}
            <NumberInput
              label="SMTP 포트"
              value={Number(config.port) || 587}
              min={1}
              max={65535}
              allowDecimal={false}
              onChange={(value) => update("port", Number(value))}
            />
            <Select
              label="전송 보안"
              value={String(config.security)}
              allowDeselect={false}
              data={[
                { value: "starttls", label: "필수 STARTTLS · 보통 587" },
                { value: "tls", label: "TLS · 보통 465" },
                { value: "none", label: "암호화 없는 사내 릴레이" },
              ]}
              onChange={(value) => {
                const next: Record<string, unknown> = {
                  ...config,
                  security: value,
                };
                if (value === "none") next.username = "";
                setDraft({
                  ...draft,
                  config: next,
                  secret: value === "none" ? "" : draft.secret,
                  secretMode:
                    value === "none" && original?.secret_configured
                      ? "clear"
                      : draft.secretMode,
                });
              }}
            />
            {input(
              "from",
              "발신 주소",
              '이메일 주소 또는 "보안팀 <security@example.internal>"',
            )}
            {config.security !== "none" && (
              <>
                {input(
                  "username",
                  "SMTP 계정",
                  "인증 없는 TLS 릴레이는 계정을 비워 두세요.",
                )}
                <Select
                  label="인증 방식"
                  value={String(config.auth || "plain")}
                  data={[
                    { value: "plain", label: "PLAIN" },
                    { value: "login", label: "LOGIN" },
                  ]}
                  allowDeselect={false}
                  onChange={(value) => update("auth", value)}
                />
              </>
            )}
          </SimpleGrid>
          {config.security === "none" && (
            <Alert mt="md" color="orange">
              인증 정보를 보내지 않는 사내 SMTP 릴레이에만 사용하세요. 비밀번호
              인증은 TLS 연결에서 설정합니다.
            </Alert>
          )}
        </section>
      ) : (
        <>
          <section className="notification-section">
            <h3>
              {draft.type === "sms"
                ? "문자 API 연결"
                : draft.type === "kakao"
                  ? "카카오톡 API 연결"
                  : "HTTP 연결"}
            </h3>
            <Text className="notification-subtle" mb="md">
              {draft.type === "kakao"
                ? "조직이 계약한 게이트웨이의 승인된 발신 프로필·템플릿 코드와 치환값을 요청 본문에 설정하세요."
                : draft.type === "sms"
                  ? "조직이 사용하는 문자 게이트웨이의 발신번호·수신번호·본문 필드에 맞춰 설정하세요."
                  : "수신 시스템의 API 문서에 따라 주소·인증·성공 판정을 설정하세요."}
            </Text>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              {input(
                "endpoint",
                "사내 API 주소",
                "예: https://notify.internal/v1/messages",
              )}
              <Select
                label="요청 메서드"
                value={String(config.method)}
                data={["POST", "PUT"]}
                allowDeselect={false}
                onChange={(value) => update("method", value)}
              />
              <Select
                label="본문 전송 방식"
                value={String(config.format)}
                allowDeselect={false}
                data={[
                  { value: "json", label: "JSON" },
                  { value: "form", label: "Form URL encoded" },
                ]}
                onChange={(value) => update("format", value)}
              />
              <Select
                label="API 인증 방식"
                value={String(config.auth)}
                allowDeselect={false}
                data={[
                  { value: "none", label: "인증 없음" },
                  { value: "bearer", label: "Bearer 토큰" },
                  { value: "basic", label: "Basic 인증" },
                  { value: "header", label: "사용자 정의 인증 헤더" },
                  { value: "headers", label: "여러 인증 헤더 · 비밀 JSON" },
                  { value: "ncp", label: "NCP API 서명" },
                ]}
                onChange={(value) => update("auth", value)}
              />
              {["basic", "ncp"].includes(String(config.auth)) &&
                input(
                  "username",
                  config.auth === "ncp" ? "NCP Access Key" : "API 사용자 이름",
                )}
              {config.auth === "header" &&
                input("auth_header", "인증 헤더 이름", "예: X-API-Key")}
            </SimpleGrid>
          </section>
          <section className="notification-section">
            <h3>요청 구성</h3>
            <Group gap="xs" mb="sm">
              {notificationPayloadPresets.map((item) => (
                <Button
                  variant="light"
                  size="compact-sm"
                  key={item.id}
                  onClick={() => setPreset(item.id)}
                >
                  {item.label}
                </Button>
              ))}
            </Group>
            <Text className="notification-subtle" mb="md">
              예시는 시작점입니다. 사용하는 게이트웨이의 필드 이름과 승인된 발신
              정보로 바꿔 주세요.
            </Text>
            <Modal
              opened={!!preset}
              onClose={() => setPreset(null)}
              title="본문 예시 적용"
              zIndex={350}
            >
              <Stack>
                <Text>
                  선택한 예시로 현재 요청 본문 템플릿을 교체합니다. 다른 채널
                  설정과 인증 비밀값은 유지합니다.
                </Text>
                <Group justify="flex-end">
                  <Button variant="default" onClick={() => setPreset(null)}>
                    기존 본문 유지
                  </Button>
                  <Button
                    onClick={() => {
                      const item = notificationPayloadPresets.find(
                        (value) => value.id === preset,
                      );
                      if (item)
                        setDraft({
                          ...draft,
                          bodyJSON: JSON.stringify(item.value, null, 2),
                        });
                      setPreset(null);
                    }}
                  >
                    예시로 교체
                  </Button>
                </Group>
              </Stack>
            </Modal>
            <JsonInput
              label="정적 헤더 JSON"
              description="비밀이 아닌 헤더만 입력하세요. 인증 헤더는 위의 인증 방식과 비밀값에서 관리합니다."
              autosize
              minRows={3}
              maxRows={8}
              value={draft.headersJSON}
              onChange={(value) => setDraft({ ...draft, headersJSON: value })}
              formatOnBlur
            />
            <JsonInput
              mt="md"
              label="요청 본문 템플릿 JSON"
              description="{{message.recipient}}, {{message.subject}}, {{message.body}}, {{message.id}}를 수신 API의 필드에 배치하세요. Form 방식은 문자열 값만 지원합니다."
              autosize
              minRows={7}
              maxRows={16}
              value={draft.bodyJSON}
              onChange={(value) => setDraft({ ...draft, bodyJSON: value })}
              formatOnBlur
            />
            <Text size="sm" c="dimmed" mt="xs">
              {bytes(draft.bodyJSON).toLocaleString()} / 65,536바이트
            </Text>
          </section>
          <section className="notification-section">
            <h3>응답 판정과 중복 방지</h3>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              {input(
                "success_path",
                "성공 값 경로 (선택)",
                "점으로 구분합니다. 예: header.isSuccessful",
              )}
              {input(
                "success_value",
                "성공으로 인정할 값 (선택)",
                "예: true, 0, 200",
              )}
              {input(
                "id_path",
                "게이트웨이 접수 ID 경로 (선택)",
                "예: messages.0.messageId",
              )}
              {input(
                "idempotency_header",
                "중복 방지 헤더 이름 (선택)",
                "예: Idempotency-Key",
              )}
            </SimpleGrid>
            <Switch
              mt="md"
              label="수신 API의 중복 방지 키 지원 확인"
              description="해당 API가 같은 키의 재요청을 중복 처리하지 않는다고 명시한 경우에만 켜세요."
              checked={!!config.idempotency_supported}
              onChange={(event) =>
                update("idempotency_supported", event.currentTarget.checked)
              }
            />
          </section>
        </>
      )}
      <SecretField
        draft={{ ...draft, config }}
        onChange={setDraft}
        configured={!!original?.secret_configured}
        existing={!!original}
      />
      <Group justify="space-between">
        <NumberInput
          label="연결 제한 시간 (초)"
          min={1}
          max={30}
          allowDecimal={false}
          value={Number(config.timeout_seconds) || 20}
          onChange={(value) => update("timeout_seconds", Number(value))}
        />
        <Button
          component="a"
          href="/admin/settings?tab=security"
          target="_blank"
          rel="noopener noreferrer"
          variant="subtle"
          leftSection={<IconExternalLink size={16} />}
        >
          사내 CA 설정 (새 탭)
        </Button>
      </Group>
      {original && (
        <Text className="notification-subtle">
          채널 설정을 변경하면 이전 설정으로 대기 중이던 발송을 취소합니다. 이미
          전송 중인 요청의 수신 여부는 이력에서 확인하세요.
        </Text>
      )}
    </GuardedEditor>
  );
}
function RuleEditor({
  source,
  channels,
  services,
  onClose,
  onSaved,
}: {
  source: NotificationRule | null;
  channels: NotificationChannel[];
  services: Row[];
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [original, setOriginal] = useState(source),
    [draft, setDraft] = useState<RuleDraft>(() =>
      ruleDraft(source || undefined),
    ),
    [preview, setPreview] = useState<NotificationPreview | null>(null);
  const baseline = useRef(draft),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [conflict, setConflict] = useState(false),
    [showVariables, setShowVariables] = useState(false);
  const submitting = useRef(false);
  const update = (next: RuleDraft) => {
    setDraft(next);
    setPreview(null);
  };
  const restore = (latest: NotificationRule) => {
    const next = ruleDraft(latest);
    setOriginal(latest);
    setDraft(next);
    baseline.current = next;
    setConflict(false);
    setError("");
    setPreview(null);
  };
  const selectedChannel = channels.find(
    (channel) => channel.id === draft.channel_id,
  );
  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    setError("");
    setConflict(false);
    try {
      const payload = rulePayload(draft, original || undefined);
      submitting.current = true;
      setBusy(true);
      await notificationAPI.saveRule(payload, original?.id);
      success("발송 규칙을 저장했습니다.");
      await onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
      setConflict(e instanceof APIError && e.status === 409);
    } finally {
      setBusy(false);
      submitting.current = false;
    }
  }
  async function renderPreview() {
    if (busy) return;
    setError("");
    setPreview(null);
    try {
      const body = rulePayload(draft);
      setBusy(true);
      setPreview(await notificationAPI.preview(body));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const options = [
    ...services.map((service) => ({
      value: service.id,
      label: service.name || service.id,
    })),
    ...draft.filters.service_ids
      .filter((id) => !services.some((service) => service.id === id))
      .map((id) => ({ value: id, label: id })),
  ];
  return (
    <GuardedEditor
      title={original ? "발송 규칙 수정" : "발송 규칙 추가"}
      dirty={changed(baseline.current, draft)}
      busy={busy}
      error={error}
      onClose={onClose}
      onSubmit={save}
      submitLabel="규칙 저장"
      extra={
        <Button
          type="button"
          variant="light"
          disabled={busy}
          onClick={renderPreview}
        >
          템플릿 미리보기
        </Button>
      }
    >
      {conflict && original && (
        <ConflictReview
          load={async () => {
            const list = await api<{ items: NotificationRule[] }>(
              "/api/notification-rules",
            );
            const row = list.items.find((item) => item.id === original.id);
            if (!row)
              throw new Error("규칙이 삭제되었거나 조회할 수 없습니다.");
            return row;
          }}
          onUse={restore}
        />
      )}
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        <TextInput
          label="규칙 이름"
          required
          description="최대 200바이트"
          value={draft.name}
          onChange={(event) =>
            update({ ...draft, name: event.currentTarget.value })
          }
        />
        <Select
          label="발송 채널"
          required
          searchable
          data={channels.map((channel) => ({
            value: channel.id,
            label: `${channel.name}${channel.enabled ? "" : " · 자동 발송 비활성"}`,
          }))}
          value={draft.channel_id || null}
          onChange={(value) => update({ ...draft, channel_id: value || "" })}
          nothingFoundMessage="채널을 먼저 등록하세요"
        />
      </SimpleGrid>
      <Switch
        label="이 규칙의 자동 발송 사용"
        checked={draft.enabled}
        onChange={(event) =>
          update({ ...draft, enabled: event.currentTarget.checked })
        }
      />
      {selectedChannel && !selectedChannel.enabled && (
        <Alert color="yellow">
          선택한 채널의 자동 발송이 비활성 상태입니다. 규칙과 채널을 모두
          활성화해야 새 이벤트에 알림을 생성합니다.
        </Alert>
      )}
      <section className="notification-section">
        <h3>이벤트와 적용 대상</h3>
        <MultiSelect
          label="발송 이벤트"
          required
          data={notificationEvents}
          value={draft.events}
          onChange={(value) => update({ ...draft, events: value })}
        />
        <Text className="notification-subtle" mt="sm">
          이벤트 중 하나에 해당하고 아래 필터에 일치하면 발송합니다. 필터를 비워
          두면 해당 조건으로 제한하지 않습니다.
        </Text>
        <SimpleGrid mt="md" cols={{ base: 1, sm: 2 }}>
          <MultiSelect
            label="발견 건 심각도 (선택)"
            data={["critical", "high", "medium", "low", "info"].map(
              (value) => ({ value, label: label(value) }),
            )}
            value={draft.filters.severities}
            onChange={(value) =>
              update({
                ...draft,
                filters: { ...draft.filters, severities: value },
              })
            }
          />
          {options.length ? (
            <MultiSelect
              label="대상 서비스 (선택)"
              searchable
              data={options}
              value={draft.filters.service_ids}
              onChange={(value) =>
                update({
                  ...draft,
                  filters: { ...draft.filters, service_ids: value },
                })
              }
              nothingFoundMessage="조건에 맞는 서비스가 없습니다"
            />
          ) : (
            <TagsInput
              label="대상 서비스 ID (선택)"
              value={draft.filters.service_ids}
              onChange={(value) =>
                update({
                  ...draft,
                  filters: { ...draft.filters, service_ids: value },
                })
              }
              description="서비스 조회 권한이 없다면 관리자가 확인한 ID를 입력하세요."
            />
          )}
          <TagsInput
            label="담당 팀 (선택)"
            data={
              [
                ...new Set(
                  services.map((service) => service.team).filter(Boolean),
                ),
              ] as string[]
            }
            value={draft.filters.teams}
            onChange={(value) =>
              update({ ...draft, filters: { ...draft.filters, teams: value } })
            }
            description="서비스의 담당 팀 이름과 정확히 일치하는 항목을 입력하세요."
          />
          <NumberInput
            label="최대 발송 시도 횟수"
            description="최초 시도를 포함합니다. 결과가 불명확하면 자동 재시도하지 않습니다."
            value={draft.max_attempts}
            min={1}
            max={5}
            allowDecimal={false}
            onChange={(value) =>
              update({ ...draft, max_attempts: Number(value) })
            }
          />
        </SimpleGrid>
        {draft.events.includes("finding.due") && (
          <Alert mt="md" color="teal">
            조치 기한에 도달했거나 지난 미조치 발견 건을 하루에 한 번 알립니다.
            관리자의 SLA 정책 기한도 적용합니다.
          </Alert>
        )}
      </section>
      <section className="notification-section">
        <h3>고정 수신자</h3>
        <TagsInput
          label="수신자 목록"
          required
          description={
            selectedChannel?.type === "smtp"
              ? "이메일 주소를 입력하고 Enter를 누르세요. 최대 100명, 동적 수신자 치환은 지원하지 않습니다."
              : "게이트웨이에 전달할 전화번호 또는 수신자 식별자를 입력하고 Enter를 누르세요. 최대 100명."
          }
          value={draft.recipients}
          onChange={(value) => update({ ...draft, recipients: value })}
          splitChars={[",", ";"]}
        />
        <Text className="notification-subtle" mt="sm">
          발송 이력에는 마스킹한 수신자만 표시합니다. 수신자 원문은 이 규칙 편집
          화면에서 관리합니다.
        </Text>
      </section>
      <section className="notification-section">
        <Group justify="space-between" mb="md">
          <h3>메시지 템플릿</h3>
          <Button
            variant="subtle"
            size="compact-md"
            onClick={() => setShowVariables(!showVariables)}
          >
            {showVariables ? "변수 목록 닫기" : "사용할 수 있는 변수"}
          </Button>
        </Group>
        {showVariables && (
          <>
            <Text size="sm" mb="sm">
              변수를 누르면 본문 끝에 추가합니다. 값이 없는 변수는 빈 문자열로
              표시합니다.
            </Text>
            <div className="notification-variables">
              {notificationVariables.map((variable) => (
                <Button
                  className="notification-variable"
                  key={variable}
                  variant="default"
                  size="compact-xs"
                  onClick={() =>
                    update({
                      ...draft,
                      body_template: draft.body_template + `{{${variable}}}`,
                    })
                  }
                >{`{{${variable}}}`}</Button>
              ))}
            </div>
            <Divider my="md" />
          </>
        )}
        <TextInput
          label="제목 템플릿"
          required
          value={draft.subject_template}
          onChange={(event) =>
            update({ ...draft, subject_template: event.currentTarget.value })
          }
          description={`${bytes(draft.subject_template)} / 200바이트`}
        />
        <Textarea
          mt="md"
          label="본문 템플릿"
          required
          minRows={7}
          autosize
          maxRows={18}
          value={draft.body_template}
          onChange={(event) =>
            update({ ...draft, body_template: event.currentTarget.value })
          }
          description={`${bytes(draft.body_template).toLocaleString()} / 16,000바이트 · {{변수명}} 치환만 사용하며 HTML·스크립트를 실행하지 않습니다.`}
        />
      </section>
      {preview && (
        <section className="notification-preview" aria-label="메시지 미리보기">
          <Group justify="space-between">
            <Text fw={700}>메시지 미리보기</Text>
            <Badge color="teal" variant="light">
              합성 예시 · 발송하지 않음
            </Badge>
          </Group>
          <Text fw={600} mt="md">
            {preview.subject}
          </Text>
          <pre>{preview.body}</pre>
          <Text className="notification-subtle" mt="md">
            현재 수신자 {preview.recipients_count}명 · 실제 이벤트 값은 발송
            대기 생성 시 채워집니다.
          </Text>
        </section>
      )}
      <Alert color="teal" title="알림의 상세 주소 기준">
        {"{{resource.url}}"}은 관리자 기본 정보의 서비스 공개 주소를 사용합니다.
        수신자가 접근할 수 있는 정확한 사내 주소를 설정하세요.{" "}
        <a
          href="/admin/settings?tab=general"
          target="_blank"
          rel="noopener noreferrer"
        >
          서비스 공개 주소 확인
        </a>
      </Alert>
      <Text className="notification-subtle">
        규칙을 변경하면 이전 규칙으로 대기 중이던 발송을 취소합니다. 변경한
        내용은 이후 발생하는 이벤트부터 적용합니다.
      </Text>
    </GuardedEditor>
  );
}
function ChannelTest({
  channel,
  onClose,
  onQueued,
}: {
  channel: NotificationChannel;
  onClose: () => void;
  onQueued: (delivery: NotificationDelivery) => void;
}) {
  const [recipient, setRecipient] = useState(""),
    [subject, setSubject] = useState("[Hunter] 알림 채널 연결 테스트"),
    [body, setBody] = useState("관리자가 요청한 알림 채널 연결 테스트입니다."),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const submitting = useRef(false);
  const dirty =
    !!recipient ||
    subject !== "[Hunter] 알림 채널 연결 테스트" ||
    body !== "관리자가 요청한 알림 채널 연결 테스트입니다.";
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    setError("");
    if (!recipient.trim()) {
      setError("테스트 수신자 한 명을 입력하세요.");
      return;
    }
    try {
      submitting.current = true;
      setBusy(true);
      const delivery = await notificationAPI.test(channel.id, {
        recipient: recipient.trim(),
        subject,
        body,
      });
      success("테스트 메시지를 발송 대기열에 등록했습니다.");
      onQueued(delivery);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  return (
    <GuardedEditor
      title="저장한 채널 테스트"
      dirty={dirty}
      busy={busy}
      error={error}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="테스트 발송"
    >
      <Alert color="orange" title="입력한 수신자에게 실제 발송을 요청합니다">
        현재 저장된 ‘{channel.name}’ 채널 설정으로 한 건을 요청합니다. 채널이
        비활성이어도 이 수동 테스트는 실행합니다.
      </Alert>
      <TextInput
        label="테스트 수신자"
        required
        description={
          channel.type === "smtp"
            ? "테스트용 이메일 주소 한 개를 직접 입력하세요."
            : "게이트웨이에 전달할 테스트용 전화번호 또는 식별자 한 개를 직접 입력하세요."
        }
        value={recipient}
        onChange={(event) => setRecipient(event.currentTarget.value)}
      />
      <TextInput
        label="테스트 제목"
        value={subject}
        onChange={(event) => setSubject(event.currentTarget.value)}
      />
      <Textarea
        label="테스트 본문"
        autosize
        minRows={4}
        maxRows={10}
        value={body}
        onChange={(event) => setBody(event.currentTarget.value)}
      />
      <Text className="notification-subtle">
        큐 등록 후 발송 이력에서 결과를 확인하세요. SMTP·HTTP 게이트웨이 접수가
        최종 수신을 보장하지는 않습니다.
      </Text>
    </GuardedEditor>
  );
}
function DeliveryActions({
  delivery,
  onRetry,
  onCancel,
}: {
  delivery: NotificationDelivery;
  onRetry: (row: NotificationDelivery) => void;
  onCancel: (row: NotificationDelivery) => void;
}) {
  return (
    <Group gap="xs" className="notification-history-actions">
      {delivery.can_retry && (
        <Button
          size="compact-sm"
          variant="light"
          color={delivery.status === "uncertain" ? "orange" : "teal"}
          onClick={() => onRetry(delivery)}
        >
          재시도
        </Button>
      )}
      {delivery.can_cancel && (
        <Button
          size="compact-sm"
          variant="default"
          onClick={() => onCancel(delivery)}
        >
          취소
        </Button>
      )}
    </Group>
  );
}
function DeliveryHistory({
  channels,
  onOpen,
  onRetry,
  onCancel,
}: {
  channels: NotificationChannel[];
  onOpen: (row: NotificationDelivery) => void;
  onRetry: (row: NotificationDelivery) => void;
  onCancel: (row: NotificationDelivery) => void;
}) {
  const [params, setParams] = useSearchParams(),
    location = useLocation();
  const query = notificationHistoryQuery(params),
    result = useData<DeliveryList>(`/api/notification-deliveries?${query}`);
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (!document.hidden) void result.reload();
    }, 10000);
    return () => clearInterval(timer);
  }, [result.reload]);
  const change = (values: Record<string, string | null>, replace = false) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(values)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    if (!("page" in values)) next.delete("page");
    setParams(next, {
      replace,
      preventScrollReset: true,
      state: location.state,
    });
  };
  useEffect(() => {
    if (!result.data || result.error || result.loading) return;
    const last = Math.max(
      1,
      Math.ceil(result.data.total / result.data.page_size),
    );
    if (result.data.page > last) {
      const next = new URLSearchParams(params);
      if (last === 1) next.delete("page");
      else next.set("page", String(last));
      setParams(next, {
        replace: true,
        preventScrollReset: true,
        state: location.state,
      });
    }
  }, [
    result.data,
    result.error,
    result.loading,
    params,
    setParams,
    location.state,
  ]);
  const search = new URLSearchParams(query),
    sort = search.get("sort") || "created_at",
    direction = search.get("dir") || "desc";
  const order = (key: string) =>
    change({
      sort: key,
      dir: sort === key && direction === "desc" ? "asc" : "desc",
    });
  const heading = (key: string, caption: string) => {
    const selected = sort === key,
      Icon = selected
        ? direction === "desc"
          ? IconArrowDown
          : IconArrowUp
        : IconArrowsSort;
    return (
      <Table.Th
        aria-sort={
          selected
            ? direction === "desc"
              ? "descending"
              : "ascending"
            : "none"
        }
      >
        <button className="list-sort" onClick={() => order(key)}>
          <span>{caption}</span>
          <Icon size={16} aria-hidden />
          <span className="sr-only">
            {selected && direction === "desc" ? "오름차순" : "내림차순"} 정렬
          </span>
        </button>
      </Table.Th>
    );
  };
  const reset = () =>
    change(
      Object.fromEntries(
        [
          "q",
          "status",
          "channel_id",
          "event_type",
          "sort",
          "dir",
          "page",
          "size",
        ].map((key) => [key, null]),
      ),
    );
  return (
    <>
      <Alert
        color="teal"
        mt="lg"
        mb="lg"
        title="게이트웨이 접수와 실제 수신을 구분합니다"
      >
        이력은 저장한 채널에 전달을 요청한 결과입니다. ‘결과 확인 필요’ 항목은
        수신 시스템에서 먼저 확인한 뒤 재시도하세요. 모호한 결과는 자동으로 다시
        보내지 않습니다.
      </Alert>
      {result.data && !result.error && (
        <section aria-label="전체 발송 이력 현황">
          <Text size="sm" c="dimmed">
            전체 발송 이력 기준 · 검색 필터와 별도 집계
          </Text>
          <SimpleGrid
            cols={{ base: 2, md: 4 }}
            className="notification-summary"
          >
            <Metric
              label="발송 대기"
              value={
                (result.data.summary.queued || 0) +
                (result.data.summary.retry || 0)
              }
            />
            <Metric
              label="게이트웨이 접수"
              value={result.data.summary.sent || 0}
            />
            <Metric label="발송 실패" value={result.data.summary.failed || 0} />
            <Metric
              label="결과 확인 필요"
              value={result.data.summary.uncertain || 0}
            />
          </SimpleGrid>
        </section>
      )}
      <Paper className="data-panel">
        <div className="notification-history-toolbar">
          <TextInput
            aria-label="발송 이력 검색"
            placeholder="채널, 규칙, 이벤트, 발송 ID 검색"
            value={params.get("q") || ""}
            onChange={(event) => change({ q: event.currentTarget.value }, true)}
          />
          <Select
            aria-label="발송 상태 필터"
            placeholder="모든 상태"
            clearable
            data={deliveryStatuses}
            value={search.get("status")}
            onChange={(value) => change({ status: value })}
          />
          <Select
            aria-label="발송 채널 필터"
            placeholder="모든 채널"
            clearable
            searchable
            data={channels.map((channel) => ({
              value: channel.id,
              label: channel.name,
            }))}
            value={params.get("channel_id")}
            onChange={(value) => change({ channel_id: value })}
          />
          <Select
            aria-label="발송 이벤트 필터"
            placeholder="모든 이벤트"
            clearable
            data={[
              ...notificationEvents,
              { value: "manual.test", label: "관리자 수동 테스트" },
            ]}
            value={params.get("event_type")}
            onChange={(value) => change({ event_type: value })}
          />
        </div>
        <Group justify="space-between" px="lg" pb="md">
          <Text size="sm" role="status">
            {result.loading
              ? "이력을 불러오는 중"
              : result.error
                ? "이력을 불러오지 못했습니다"
                : `검색 조건에 맞는 발송 ${result.data?.total.toLocaleString() || 0}건`}
          </Text>
          <Group gap="sm">
            <Button variant="subtle" size="compact-md" onClick={reset}>
              조건 초기화
            </Button>
            <Button
              variant="default"
              leftSection={<IconRefresh size={16} />}
              onClick={result.reload}
            >
              이력 새로고침
            </Button>
          </Group>
        </Group>
        <LoadState
          loading={result.loading}
          error={result.error}
          reload={result.reload}
        />
        {!result.loading &&
          !result.error &&
          result.data &&
          (result.data.items.length ? (
            <>
              <div
                className="notification-history-scroll"
                role="region"
                tabIndex={0}
                aria-label="발송 이력 표"
              >
                <Table
                  verticalSpacing="md"
                  horizontalSpacing="lg"
                  highlightOnHover
                >
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>제목 · 이벤트</Table.Th>
                      <Table.Th>채널 · 수신자</Table.Th>
                      {heading("status", "발송 상태")}
                      {heading("attempts", "발송 시도")}
                      {heading("created_at", "등록 시각")}
                      {heading("available_at", "다음 시도")}
                      <Table.Th>작업</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {result.data.items.map((row) => (
                      <Table.Tr key={row.id}>
                        <Table.Td>
                          <Button
                            variant="subtle"
                            className="notification-message-title"
                            onClick={() => onOpen(row)}
                          >
                            {row.subject || "제목 없음"}
                          </Button>
                          <Text size="sm" c="dimmed">
                            {eventLabel(row.event_type)}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          <Text>{row.channel_name || "삭제된 채널"}</Text>
                          <Text size="sm" c="dimmed">
                            {row.recipient_masked || "—"}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          <DeliveryStatus status={row.status} />
                        </Table.Td>
                        <Table.Td>
                          {row.attempts} / {row.max_attempts}회
                        </Table.Td>
                        <Table.Td>{dateText(row.created_at)}</Table.Td>
                        <Table.Td>
                          {["queued", "retry"].includes(row.status)
                            ? dateText(row.available_at)
                            : "—"}
                        </Table.Td>
                        <Table.Td>
                          <DeliveryActions
                            delivery={row}
                            onRetry={onRetry}
                            onCancel={onCancel}
                          />
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </div>
              <Group justify="space-between" p="lg">
                <Select
                  aria-label="발송 이력 표시 수"
                  value={String(result.data.page_size)}
                  data={[10, 25, 50, 100].map((value) => ({
                    value: String(value),
                    label: `${value}개씩`,
                  }))}
                  w={110}
                  allowDeselect={false}
                  onChange={(value) => change({ size: value })}
                />
                <Pagination
                  size="sm"
                  siblings={1}
                  total={Math.max(
                    1,
                    Math.ceil(result.data.total / result.data.page_size),
                  )}
                  value={result.data.page}
                  onChange={(value) => change({ page: String(value) })}
                />
              </Group>
            </>
          ) : (
            <Empty
              title="발송 이력이 없습니다"
              description="저장한 채널로 테스트하거나, 활성 채널과 규칙에 맞는 새 이벤트가 발생하면 이력이 생성됩니다."
            />
          ))}
      </Paper>
    </>
  );
}
function DeliveryDrawer({
  id,
  onClose,
  onRetry,
  onCancel,
}: {
  id: string;
  onClose: () => void;
  onRetry: (row: NotificationDelivery) => void;
  onCancel: (row: NotificationDelivery) => void;
}) {
  const result = useData<DeliveryDetail>(
    `/api/notification-deliveries/${encodeURIComponent(id)}`,
  );
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (!document.hidden) void result.reload();
    }, 10000);
    return () => clearInterval(timer);
  }, [result.reload]);
  const row = result.data;
  return (
    <Drawer
      opened
      onClose={onClose}
      title="발송 이력 상세"
      position="right"
      size="lg"
    >
      <LoadState
        loading={result.loading}
        error={result.error}
        reload={result.reload}
      />
      {row && !result.loading && !result.error && (
        <Stack gap="lg">
          <Group justify="space-between">
            <DeliveryStatus status={row.status} />
            <Button
              variant="subtle"
              leftSection={<IconRefresh size={16} />}
              onClick={result.reload}
            >
              새로고침
            </Button>
          </Group>
          <Text fw={700} size="lg">
            {row.subject}
          </Text>
          <dl className="workflow-kv">
            <dt>발송 채널</dt>
            <dd>
              {row.channel_name} · {typeLabel(row.channel_type)}
            </dd>
            <dt>연결 규칙</dt>
            <dd>{row.rule_name || "수동 테스트"}</dd>
            <dt>수신자</dt>
            <dd>{row.recipient_masked}</dd>
            <dt>이벤트</dt>
            <dd>{eventLabel(row.event_type)}</dd>
            <dt>등록 시각</dt>
            <dd>{dateText(row.created_at)}</dd>
            <dt>발송 시도</dt>
            <dd>
              {row.attempts} / {row.max_attempts}회
            </dd>
            <dt>접수 시각</dt>
            <dd>{dateText(row.sent_at)}</dd>
          </dl>
          {row.cancel_requested && (
            <Alert color="yellow">
              취소 요청을 전달했습니다. 이미 전송 중이던 요청은 게이트웨이에서
              접수될 수 있으므로 최종 상태를 확인하세요.
            </Alert>
          )}
          {row.last_error && (
            <Alert
              color={
                row.status === "sent"
                  ? "teal"
                  : row.status === "uncertain" || row.status === "retry"
                    ? "yellow"
                    : row.status === "cancelled"
                      ? "gray"
                      : "red"
              }
              title="최근 처리 결과"
            >
              {row.last_error}
            </Alert>
          )}
          <section className="notification-preview">
            <Text fw={700}>발송 메시지</Text>
            <pre>{row.body}</pre>
          </section>
          <Text className="notification-subtle">
            본문은 일반 텍스트로 표시합니다. 게이트웨이 응답 원문과 인증
            비밀값은 표시하지 않습니다.
          </Text>
          <DeliveryActions
            delivery={row}
            onRetry={onRetry}
            onCancel={onCancel}
          />
          <Divider />
          <Text fw={700}>시도별 기록</Text>
          {row.attempt_log?.length ? (
            row.attempt_log.map((attempt, index) => (
              <Paper withBorder p="md" key={`${attempt.attempt}-${index}`}>
                <Group justify="space-between">
                  <Text fw={600}>{attempt.attempt}차 시도</Text>
                  <DeliveryStatus status={attempt.status} />
                </Group>
                <Text size="sm" c="dimmed" mt="xs">
                  {dateText(attempt.started_at)} →{" "}
                  {dateText(attempt.finished_at)}
                </Text>
                <Text mt="sm" className="notification-detail-value">
                  {attempt.detail || "처리 상세 없음"}
                </Text>
                {attempt.code && (
                  <Text size="sm" mt="xs">
                    응답 코드 {attempt.code}
                  </Text>
                )}
                {attempt.provider_id && (
                  <Text size="sm" mt="xs" className="notification-detail-value">
                    게이트웨이 접수 ID {attempt.provider_id}
                  </Text>
                )}
              </Paper>
            ))
          ) : (
            <Text c="dimmed">아직 발송을 시도하지 않았습니다.</Text>
          )}
          <Button
            variant="default"
            onClick={async () => {
              try {
                await copyText(
                  `${location.origin}/admin/notifications?tab=history&delivery=${encodeURIComponent(row.id)}`,
                );
                success("발송 이력 주소를 복사했습니다.");
              } catch (e) {
                showError(e);
              }
            }}
          >
            상세 주소 복사
          </Button>
        </Stack>
      )}
    </Drawer>
  );
}
export function NotificationsPage() {
  const can = useCan(),
    [params, setParams] = useSearchParams(),
    location = useLocation();
  const tab = (notificationTabs as readonly string[]).includes(
    params.get("tab") || "",
  )
    ? (params.get("tab") as NotificationTab)
    : "channels";
  const channels = useData<{ items: NotificationChannel[] }>(
      "/api/notification-channels",
    ),
    rules = useData<{ items: NotificationRule[] }>("/api/notification-rules");
  const services = useData<Row[]>(
    can("services:read") ? "/api/services" : null,
  );
  const [channelEdit, setChannelEdit] = useState<{
      source: NotificationChannel | null;
    } | null>(null),
    [ruleEdit, setRuleEdit] = useState<{
      source: NotificationRule | null;
    } | null>(null),
    [test, setTest] = useState<NotificationChannel | null>(null);
  const [removal, setRemoval] = useState<{
      kind: "channels" | "rules";
      id: string;
      name: string;
    } | null>(null),
    [operation, setOperation] = useState<{
      type: "retry" | "cancel";
      row: NotificationDelivery;
    } | null>(null);
  const [busy, setBusy] = useState(false),
    [actionError, setActionError] = useState(""),
    [reason, setReason] = useState(""),
    [duplicateConfirmed, setDuplicateConfirmed] = useState(false),
    [historyRevision, setHistoryRevision] = useState(0);
  const switchTab = (next: NotificationTab) =>
    setParams(
      switchWorkflowTab(params, tab, next, notificationTabs, {
        channels: ["f_type", "f_enabled"],
        rules: ["f_channel_id", "f_enabled"],
        history: ["status", "channel_id", "event_type", "delivery"],
      }),
      { preventScrollReset: true, state: location.state },
    );
  const openDelivery = (delivery: NotificationDelivery) => {
    const next = switchWorkflowTab(params, tab, "history", notificationTabs, {
      channels: ["f_type", "f_enabled"],
      rules: ["f_channel_id", "f_enabled"],
      history: ["status", "channel_id", "event_type", "delivery"],
    });
    next.set("tab", "history");
    next.set("delivery", delivery.id);
    setParams(next, { preventScrollReset: true, state: location.state });
  };
  const closeDelivery = () => {
    const next = new URLSearchParams(params);
    next.delete("delivery");
    setParams(next, {
      replace: true,
      preventScrollReset: true,
      state: location.state,
    });
  };
  const beginOperation = (
    type: "retry" | "cancel",
    row: NotificationDelivery,
  ) => {
    setActionError("");
    setReason("");
    setDuplicateConfirmed(false);
    setOperation({ type, row });
  };
  const refresh = async () => {
    await Promise.all([channels.reload(), rules.reload()]);
    setHistoryRevision((value) => value + 1);
  };
  async function remove() {
    if (!removal || busy) return;
    setBusy(true);
    setActionError("");
    try {
      await notificationAPI.remove(removal.kind, removal.id);
      success("알림 설정을 삭제했습니다.");
      setRemoval(null);
      await refresh();
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function runOperation() {
    if (!operation || busy) return;
    setActionError("");
    if (operation.type === "retry" && !reason.trim()) {
      setActionError("재시도 사유를 입력하세요.");
      return;
    }
    if (
      operation.type === "retry" &&
      operation.row.status === "uncertain" &&
      !duplicateConfirmed
    ) {
      setActionError("수신 시스템 확인과 중복 발송 가능성에 동의해야 합니다.");
      return;
    }
    setBusy(true);
    try {
      if (operation.type === "retry")
        await notificationAPI.retry(
          operation.row.id,
          reason.trim(),
          duplicateConfirmed,
        );
      else await notificationAPI.cancel(operation.row.id);
      success(
        operation.type === "retry"
          ? "재시도를 요청했습니다."
          : operation.row.status === "sending"
            ? "전송 중인 발송의 취소를 요청했습니다. 이력에서 최종 결과를 확인하세요."
            : "대기 중인 발송을 취소했습니다.",
      );
      setOperation(null);
      setHistoryRevision((value) => value + 1);
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const channelColumns: WorkflowColumn<NotificationChannel>[] = [
    {
      key: "name",
      label: "채널",
      value: (row) => row.name,
      render: (row) => (
        <Group wrap="nowrap">
          <ChannelIcon type={row.type} />
          <div>
            <Text fw={600}>{row.name}</Text>
            <Text size="sm" c="dimmed">
              {typeLabel(row.type)}
            </Text>
          </div>
        </Group>
      ),
    },
    {
      key: "enabled",
      label: "자동 발송",
      value: (row) => (row.enabled ? "활성" : "비활성"),
      render: (row) => (
        <Badge color={row.enabled ? "teal" : "gray"} variant="light">
          {row.enabled ? "활성" : "비활성"}
        </Badge>
      ),
    },
    {
      key: "secret",
      label: "인증 비밀값",
      value: (row) => (row.secret_configured ? "설정됨" : "미설정"),
      render: (row) => (
        <Text size="sm">
          {row.secret_configured ? "저장됨 · 원문 비공개" : "미설정"}
        </Text>
      ),
    },
    {
      key: "updated_at",
      label: "최근 수정",
      value: (row) => new Date(row.updated_at).getTime(),
      render: (row) => dateText(row.updated_at),
    },
    {
      key: "actions",
      label: "관리",
      value: () => "",
      render: (row) => (
        <Group gap="xs" wrap="nowrap">
          <Tooltip label="채널 수정">
            <ActionIcon
              variant="default"
              aria-label={`${row.name} 수정`}
              onClick={() => setChannelEdit({ source: row })}
            >
              <IconEdit size={17} />
            </ActionIcon>
          </Tooltip>
          <Button
            variant="light"
            size="compact-sm"
            onClick={() => setTest(row)}
          >
            테스트 발송
          </Button>
          <Tooltip label="채널 삭제">
            <ActionIcon
              color="red"
              variant="subtle"
              aria-label={`${row.name} 삭제`}
              onClick={() => {
                setActionError("");
                setRemoval({ kind: "channels", id: row.id, name: row.name });
              }}
            >
              <IconTrash size={17} />
            </ActionIcon>
          </Tooltip>
        </Group>
      ),
    },
  ];
  const ruleColumns: WorkflowColumn<NotificationRule>[] = [
    {
      key: "name",
      label: "규칙",
      value: (row) => row.name,
      render: (row) => (
        <div>
          <Text fw={600}>{row.name}</Text>
          <Text size="sm" c="dimmed">
            수신자 {row.recipients.length}명
          </Text>
        </div>
      ),
    },
    {
      key: "channel",
      label: "발송 채널",
      value: (row) =>
        channels.data?.items.find((channel) => channel.id === row.channel_id)
          ?.name || row.channel_id,
    },
    {
      key: "events",
      label: "이벤트",
      value: (row) => row.events.map(eventLabel),
      render: (row) => (
        <Text size="sm" style={{ maxWidth: 250 }}>
          {row.events.map(eventLabel).join(" · ")}
        </Text>
      ),
    },
    {
      key: "enabled",
      label: "규칙 상태",
      value: (row) => (row.enabled ? "활성" : "비활성"),
      render: (row) => (
        <Badge color={row.enabled ? "teal" : "gray"} variant="light">
          {row.enabled ? "활성" : "비활성"}
        </Badge>
      ),
    },
    {
      key: "updated_at",
      label: "최근 수정",
      value: (row) => new Date(row.updated_at).getTime(),
      render: (row) => dateText(row.updated_at),
    },
    {
      key: "actions",
      label: "관리",
      value: () => "",
      render: (row) => (
        <Group gap="xs" wrap="nowrap">
          <Button
            size="compact-sm"
            variant="default"
            onClick={() => setRuleEdit({ source: row })}
          >
            규칙 수정
          </Button>
          <ActionIcon
            color="red"
            variant="subtle"
            aria-label={`${row.name} 삭제`}
            onClick={() => {
              setActionError("");
              setRemoval({ kind: "rules", id: row.id, name: row.name });
            }}
          >
            <IconTrash size={17} />
          </ActionIcon>
        </Group>
      ),
    },
  ];
  return (
    <>
      <PageHeader
        eyebrow="ADMINISTRATION"
        title="알림센터"
        description="채널과 발송 규칙을 연결하고, 테스트부터 처리 이력까지 관리합니다."
        action={
          <Group>
            <Button
              component={Link}
              to="/admin/settings?tab=security"
              variant="default"
              leftSection={<IconSettings size={17} />}
            >
              사내 CA 설정
            </Button>
            {tab !== "history" && (
              <Button
                leftSection={<IconPlus size={18} />}
                onClick={() =>
                  tab === "channels"
                    ? setChannelEdit({ source: null })
                    : setRuleEdit({ source: null })
                }
                disabled={
                  tab === "rules" &&
                  (!channels.data?.items.length || !!channels.error)
                }
              >
                {tab === "channels" ? "발송 채널 추가" : "발송 규칙 추가"}
              </Button>
            )}
          </Group>
        }
      />
      <div className="notification-hint">
        ① 채널을 저장하고 테스트하세요.　② 이벤트·대상·고정 수신자를 규칙으로
        지정하세요.　③ 채널과 규칙을 활성화한 뒤 이력에서 결과를 확인하세요.
      </div>
      <Tabs
        value={tab}
        onChange={(value) => switchTab(value as NotificationTab)}
        className="notification-tabs"
        mt="xl"
        keepMounted={false}
      >
        <Tabs.List mb="lg">
          <Tabs.Tab value="channels" leftSection={<IconSend size={17} />}>
            발송 채널
          </Tabs.Tab>
          <Tabs.Tab value="rules" leftSection={<IconBell size={17} />}>
            발송 규칙
          </Tabs.Tab>
          <Tabs.Tab value="history" leftSection={<IconHistory size={17} />}>
            발송 이력
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="channels">
          <WorkflowTable
            rows={channels.data?.items || []}
            columns={channelColumns}
            rowKey={(row) => row.id}
            name="발송 채널"
            loading={channels.loading}
            error={channels.error}
            reload={channels.reload}
            defaultSort={{ key: "name", direction: "asc" }}
            preferenceContext="channels"
            empty="SMTP 또는 사내 API 채널을 추가하세요. 채널은 비활성 상태로 시작하며 저장 후 테스트할 수 있습니다."
          />
        </Tabs.Panel>
        <Tabs.Panel value="rules">
          {!channels.loading &&
            !channels.error &&
            !channels.data?.items.length && (
              <Alert color="teal" mb="lg">
                규칙에서 사용할 발송 채널을 먼저 등록하세요.
                <Button variant="subtle" onClick={() => switchTab("channels")}>
                  발송 채널로 이동
                </Button>
              </Alert>
            )}
          <WorkflowTable
            rows={rules.data?.items || []}
            columns={ruleColumns}
            rowKey={(row) => row.id}
            name="발송 규칙"
            loading={rules.loading}
            error={rules.error}
            reload={rules.reload}
            defaultSort={{ key: "updated_at", direction: "desc" }}
            preferenceContext="rules"
            empty="발송 채널을 등록한 뒤 이벤트와 수신자, 메시지 템플릿을 지정하세요."
          />
        </Tabs.Panel>
        <Tabs.Panel value="history">
          <DeliveryHistory
            key={historyRevision}
            channels={channels.data?.items || []}
            onOpen={openDelivery}
            onRetry={(row) => beginOperation("retry", row)}
            onCancel={(row) => beginOperation("cancel", row)}
          />
        </Tabs.Panel>
      </Tabs>
      {channelEdit && (
        <ChannelEditor
          source={channelEdit.source}
          onClose={() => setChannelEdit(null)}
          onSaved={refresh}
        />
      )}
      {ruleEdit && (
        <RuleEditor
          source={ruleEdit.source}
          channels={channels.data?.items || []}
          services={services.data || []}
          onClose={() => setRuleEdit(null)}
          onSaved={refresh}
        />
      )}
      {test && (
        <ChannelTest
          channel={test}
          onClose={() => setTest(null)}
          onQueued={(delivery) => {
            setTest(null);
            setHistoryRevision((value) => value + 1);
            openDelivery(delivery);
          }}
        />
      )}
      {tab === "history" && params.get("delivery") && (
        <DeliveryDrawer
          key={`${params.get("delivery")}:${historyRevision}`}
          id={params.get("delivery")!}
          onClose={closeDelivery}
          onRetry={(row) => beginOperation("retry", row)}
          onCancel={(row) => beginOperation("cancel", row)}
        />
      )}
      <Modal
        opened={!!removal}
        onClose={() => {
          if (!busy) setRemoval(null);
        }}
        title="알림 설정 삭제"
        closeOnEscape={!busy}
        closeOnClickOutside={!busy}
        withCloseButton={!busy}
      >
        <Stack>
          <FormFeedback error={actionError} />
          <Text>
            ‘{removal?.name}’ {removal?.kind === "channels" ? "채널" : "규칙"}을
            삭제하시겠습니까?
          </Text>
          <Text size="sm" c="dimmed">
            삭제한 설정은 이 화면에서 복구할 수 없습니다. 연결된 대기 발송의
            처리는 서버 정책에 따라 취소합니다.
          </Text>
          <Group justify="flex-end">
            <Button
              variant="default"
              disabled={busy}
              onClick={() => setRemoval(null)}
            >
              취소
            </Button>
            <Button color="red" loading={busy} onClick={remove}>
              삭제
            </Button>
          </Group>
        </Stack>
      </Modal>
      <Modal
        opened={!!operation}
        zIndex={350}
        onClose={() => {
          if (!busy) setOperation(null);
        }}
        title={operation?.type === "retry" ? "발송 재시도" : "대기 발송 취소"}
        closeOnEscape={!busy}
        closeOnClickOutside={!busy}
        withCloseButton={!busy}
      >
        <Stack>
          <FormFeedback error={actionError} />
          <Text fw={600}>{operation?.row.subject}</Text>
          {operation?.type === "retry" ? (
            <>
              <Text size="sm">
                발송 채널·규칙의 현재 설정과 재시도 가능 여부를 서버에서 다시
                확인합니다.
              </Text>
              <Textarea
                label="재시도 사유"
                required
                minRows={3}
                value={reason}
                disabled={busy}
                onChange={(event) => setReason(event.currentTarget.value)}
              />
              {operation.row.status === "uncertain" && (
                <>
                  <Alert color="orange">
                    이전 요청이 실제로 접수되었을 수 있습니다. 게이트웨이 기록과
                    수신 결과를 먼저 확인하세요.
                  </Alert>
                  <Checkbox
                    label="수신 시스템을 확인했으며 중복 발송 가능성을 이해했습니다"
                    checked={duplicateConfirmed}
                    disabled={busy}
                    onChange={(event) =>
                      setDuplicateConfirmed(event.currentTarget.checked)
                    }
                  />
                </>
              )}
            </>
          ) : (
            <Text>
              발송 대기열에서 이 요청을 취소합니다. 이미 전송 중이면 취소 요청만
              기록하며, 게이트웨이가 접수한 경우 최종 상태가 접수 완료로 바뀔 수
              있습니다.
            </Text>
          )}
          <Group justify="flex-end">
            <Button
              variant="default"
              disabled={busy}
              onClick={() => setOperation(null)}
            >
              닫기
            </Button>
            <Button
              color={operation?.type === "cancel" ? "red" : "teal"}
              loading={busy}
              onClick={runOperation}
            >
              {operation?.type === "retry" ? "재시도 요청" : "발송 취소"}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
