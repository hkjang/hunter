import { useRef, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  NumberInput,
  PasswordInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  TagsInput,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { Link } from "react-router-dom";
import { dateText, success, useData } from "./api";
import { LoadState } from "./components";
import { WorkflowTable, type WorkflowColumn } from "./workflow-components";
import { copyText } from "./list-export";
import {
  AutomationEditor,
  AutomationSection,
  AutomationStatus,
  AutomationValues,
} from "./automation-ui";
import type { NotificationChannel } from "./notification-api";
import { channelKinds } from "./notification-state";
import {
  channelOperationDefaults,
  operationsAPI,
  operationsBody,
  type ChannelOperation,
  type NotificationOperationsDocument,
  type OperationReceipt,
  type OperationsStatus,
} from "./notification-operations-api";

export function NotificationOperationsPanel() {
  const settings = useData<NotificationOperationsDocument>(
      "/api/notification-operations",
    ),
    channels = useData<{ items: NotificationChannel[] }>(
      "/api/notification-channels",
    ),
    status = useData<OperationsStatus>("/api/notification-operations/status");
  const [edit, setEdit] = useState<NotificationChannel | null>(null),
    [general, setGeneral] = useState(false),
    [operation, setOperation] = useState<{
      kind: "reset" | "refresh";
      id: string;
      name: string;
    } | null>(null),
    [reason, setReason] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const name = (id: string) =>
    channels.data?.items.find((row) => row.id === id)?.name || id;
  const reload = async () => {
    await Promise.all([settings.reload(), status.reload(), channels.reload()]);
  };
  const configFor = (id: string) =>
    settings.data?.config.channels.find((row) => row.channel_id === id);
  const channelColumns: WorkflowColumn<NotificationChannel>[] = [
    {
      key: "name",
      label: "발송 채널",
      value: (row) => row.name,
      render: (row) => (
        <Button variant="subtle" onClick={() => setEdit(row)}>
          {row.name}
        </Button>
      ),
    },
    {
      key: "type",
      label: "방식",
      value: (row) =>
        channelKinds.find((v) => v.value === row.type)?.label || row.type,
    },
    {
      key: "tracking",
      label: "결과 추적",
      value: (row) => {
        const cfg = configFor(row.id);
        return cfg?.tracking.enabled || cfg?.tracking.callback_enabled
          ? "사용"
          : "사용 안 함";
      },
    },
    {
      key: "fallback",
      label: "대체 채널",
      value: (row) => {
        const id = configFor(row.id)?.fallback_channel_id;
        return id ? name(id) : "미설정";
      },
    },
    {
      key: "protection",
      label: "채널 보호 상태",
      value: (row) =>
        status.data?.channels.find((v) => v.channel_id === row.id)?.state ||
        "미사용",
      render: (row) => {
        const cfg = configFor(row.id),
          state = status.data?.channels.find((v) => v.channel_id === row.id);
        return cfg?.protection.enabled ? (
          <AutomationStatus status={state?.state || "closed"} />
        ) : (
          <Text size="sm" c="dimmed">
            사용 안 함
          </Text>
        );
      },
    },
    {
      key: "actions",
      label: "관리",
      value: () => "",
      render: (row) => (
        <Group wrap="nowrap">
          <Button
            size="compact-sm"
            variant="default"
            onClick={() => setEdit(row)}
          >
            운영 설정
          </Button>
          {configFor(row.id)?.protection.enabled &&
            status.data?.channels.some(
              (value) => value.channel_id === row.id,
            ) && (
              <Button
                size="compact-sm"
                variant="subtle"
                color="orange"
                onClick={() => {
                  setOperation({ kind: "reset", id: row.id, name: row.name });
                  setReason("");
                  setError("");
                }}
              >
                보호 상태 초기화
              </Button>
            )}
        </Group>
      ),
    },
  ];
  const receiptColumns: WorkflowColumn<OperationReceipt>[] = [
    {
      key: "updated_at",
      label: "최근 확인",
      value: (row) => row.updated_at,
      render: (row) => dateText(row.updated_at),
    },
    { key: "channel", label: "채널", value: (row) => name(row.channel_id) },
    {
      key: "state",
      label: "공급자 결과",
      value: (row) => row.state,
      render: (row) => (
        <AutomationStatus
          status={
            row.state === "pending"
              ? "receipt_pending"
              : row.state === "conflict"
                ? "receipt_conflict"
                : row.state
          }
        />
      ),
    },
    { key: "checks", label: "조회 횟수", value: (row) => row.checks },
    {
      key: "provider_id",
      label: "공급자 접수 ID",
      value: (row) => row.provider_id || "—",
    },
    {
      key: "last_code",
      label: "최근 분류",
      value: (row) => row.last_code || "—",
    },
    {
      key: "next_check",
      label: "다음 확인",
      value: (row) => row.next_check_at,
      render: (row) => dateText(row.next_check_at),
    },
    {
      key: "actions",
      label: "확인",
      value: () => "",
      render: (row) => (
        <Group wrap="nowrap">
          <Button
            component={Link}
            to={
              "/admin/notifications?tab=history&delivery=" +
              encodeURIComponent(row.delivery_id)
            }
            variant="default"
            size="compact-sm"
          >
            발송 이력
          </Button>
          <Button
            variant="light"
            size="compact-sm"
            disabled={
              !settings.data?.config.enabled ||
              !configFor(row.channel_id)?.tracking.enabled ||
              !["pending", "unavailable"].includes(row.state)
            }
            onClick={() => {
              setOperation({
                kind: "refresh",
                id: row.delivery_id,
                name: name(row.channel_id),
              });
              setError("");
            }}
          >
            결과 재조회
          </Button>
        </Group>
      ),
    },
  ];
  const fallbackColumns: WorkflowColumn<{
    parent_id: string;
    child_id: string;
    created_at: string;
  }>[] = [
    {
      key: "created_at",
      label: "연결 시각",
      value: (row) => row.created_at,
      render: (row) => dateText(row.created_at),
    },
    {
      key: "parent_id",
      label: "원래 발송",
      value: (row) => row.parent_id,
      render: (row) => (
        <Button
          variant="subtle"
          component={Link}
          to={
            "/admin/notifications?tab=history&delivery=" +
            encodeURIComponent(row.parent_id)
          }
        >
          {row.parent_id.slice(0, 12)}
        </Button>
      ),
    },
    {
      key: "child_id",
      label: "대체 채널 발송",
      value: (row) => row.child_id,
      render: (row) => (
        <Button
          variant="subtle"
          component={Link}
          to={
            "/admin/notifications?tab=history&delivery=" +
            encodeURIComponent(row.child_id)
          }
        >
          {row.child_id.slice(0, 12)}
        </Button>
      ),
    },
  ];
  async function run() {
    if (!operation || busy) return;
    setError("");
    try {
      if (operation.kind === "reset" && !reason.trim())
        throw new Error("초기화 사유를 입력하세요.");
      setBusy(true);
      if (operation.kind === "reset")
        await operationsAPI.reset(operation.id, reason);
      else await operationsAPI.refresh(operation.id);
      success(
        operation.kind === "reset"
          ? "채널 보호 상태를 초기화했습니다."
          : "공급자 결과 조회를 예약했습니다. 새 메시지를 발송하지 않습니다.",
      );
      setOperation(null);
      await reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Stack gap="lg">
      <LoadState
        loading={settings.loading}
        error={settings.error}
        reload={settings.reload}
      />
      {settings.data && (
        <AutomationSection
          title="공급자 결과와 채널 보호"
          enabled={settings.data.config.enabled}
          description="발송 접수 이후의 결과를 추적하고 확정 실패 시 대체 채널을 연결합니다."
          onEdit={() => setGeneral(true)}
        >
          <AutomationValues
            items={[
              {
                label: "채널별 운영 설정",
                value: `${settings.data.config.channels.length}개`,
              },
              {
                label: "결과 추적 이력",
                value: `최근 ${status.data?.receipts?.length || 0}개`,
              },
              {
                label: "대체 발송 연결",
                value: `최근 ${status.data?.fallbacks?.length || 0}개`,
              },
            ]}
          />
        </AutomationSection>
      )}
      <Alert color="teal">
        게이트웨이 접수·공급자 배달 결과·사용자의 업무 확인은 서로 다릅니다.
        결과를 확인할 수 없는 발송은 자동으로 대체 발송하지 않습니다. 대체
        발송은 같은 계열의 활성 채널로 한 번만 연결합니다.
      </Alert>
      <WorkflowTable
        rows={channels.data?.items || []}
        columns={channelColumns}
        name="채널 운영"
        rowKey={(row) => row.id}
        loading={channels.loading}
        error={channels.error}
        reload={reload}
        preferenceContext="automation-providers"
        defaultSort={{ key: "name", direction: "asc" }}
        empty="알림센터에서 SMTP나 사내 API 채널을 먼저 등록하세요."
      />
      <AutomationSection
        title="공급자 결과 추적"
        description="최근 100개 기록입니다. 검색과 정렬은 조회한 기록에 적용됩니다."
      >
        <WorkflowTable
          rows={status.data?.receipts || []}
          columns={receiptColumns}
          name="공급자 결과"
          rowKey={(row) => row.delivery_id}
          loading={status.loading}
          error={status.error}
          reload={status.reload}
          preferenceContext="automation-receipts"
          defaultSort={{ key: "updated_at", direction: "desc" }}
          empty="추적할 공급자 결과가 없습니다. 채널별 결과 조회나 서명 콜백을 설정하세요."
        />
      </AutomationSection>
      <AutomationSection
        title="대체 채널 연결 이력"
        description="최근 100개 연결입니다. 원래 발송과 대체 발송의 처리 결과를 각각 확인하세요."
      >
        <WorkflowTable
          rows={status.data?.fallbacks || []}
          columns={fallbackColumns}
          name="대체 발송"
          rowKey={(row) => row.parent_id + "|" + row.child_id}
          loading={status.loading}
          error={status.error}
          reload={status.reload}
          preferenceContext="automation-fallbacks"
          defaultSort={{ key: "created_at", direction: "desc" }}
          empty="대체 발송 연결 이력이 없습니다."
        />
      </AutomationSection>
      {edit && settings.data && (
        <ChannelOperationsEditor
          channel={edit}
          document={settings.data}
          channels={channels.data?.items || []}
          onClose={() => setEdit(null)}
          onSaved={reload}
        />
      )}{" "}
      {general && settings.data && (
        <AutomationEditor
          title="채널 운영 자동화 사용"
          value={settings.data}
          revision={settings.data.updated_at}
          onClose={() => setGeneral(false)}
          onSave={async (value, revision) => {
            await operationsAPI.save(operationsBody(value, revision));
            success("채널 운영 자동화 설정을 저장했습니다.");
            await reload();
          }}
          loadLatest={async () => {
            const doc = await operationsAPI.config();
            return { value: doc, revision: doc.updated_at };
          }}
        >
          {(value, setValue) => (
            <Stack>
              <Switch
                label="공급자 결과 추적·대체 채널·보호 기능 사용"
                checked={value.config.enabled}
                onChange={(e) =>
                  setValue({
                    ...value,
                    config: {
                      ...value.config,
                      enabled: e.currentTarget.checked,
                    },
                  })
                }
              />
              <Text c="dimmed">
                채널별 설정도 함께 사용 상태여야 적용됩니다. 기존 발송 채널의
                활성 상태는 알림센터에서 관리합니다.
              </Text>
            </Stack>
          )}
        </AutomationEditor>
      )}
      <Modal
        opened={!!operation}
        onClose={() => {
          if (!busy) setOperation(null);
        }}
        title={
          operation?.kind === "reset"
            ? "채널 보호 상태 초기화"
            : "공급자 결과 다시 조회"
        }
        zIndex={350}
        closeOnEscape={!busy}
        closeOnClickOutside={!busy}
        withCloseButton={!busy}
      >
        <Stack>
          <Text fw={700}>{operation?.name}</Text>
          <Text>
            {operation?.kind === "reset"
              ? "연속 실패와 일시 중단 상태를 초기화합니다. 사내 게이트웨이 상태를 확인한 뒤 진행하세요."
              : "저장한 조회 설정으로 결과를 다시 확인하도록 예약합니다. 메시지를 새로 보내지 않습니다."}
          </Text>
          {operation?.kind === "reset" && (
            <Textarea
              label="초기화 사유"
              required
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
            />
          )}{" "}
          {error && <Alert color="red">{error}</Alert>}
          <Group justify="flex-end">
            <Button
              variant="default"
              onClick={() => setOperation(null)}
              disabled={busy}
            >
              취소
            </Button>
            <Button loading={busy} onClick={run}>
              {operation?.kind === "reset"
                ? "보호 상태 초기화"
                : "결과 재조회 예약"}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
function ChannelOperationsEditor({
  channel,
  document,
  channels,
  onClose,
  onSaved,
}: {
  channel: NotificationChannel;
  document: NotificationOperationsDocument;
  channels: NotificationChannel[];
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document),
    cfg =
      document.config.channels.find((row) => row.channel_id === channel.id) ||
      channelOperationDefaults(channel.id);
  const value = {
    config: structuredClone(cfg),
    query: JSON.stringify(cfg.tracking.query || {}, null, 2),
    body: JSON.stringify(cfg.tracking.body_template || {}, null, 2),
    secretMode: "keep",
    secret: "",
  };
  return (
    <AutomationEditor
      title={channel.name + " 운영 설정"}
      value={value}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (draft, revision) => {
        const config = structuredClone(draft.config);
        try {
          const query: unknown = JSON.parse(draft.query),
            body: unknown = JSON.parse(draft.body);
          if (
            !query ||
            Array.isArray(query) ||
            typeof query !== "object" ||
            Object.values(query).some((value) => typeof value !== "string") ||
            !body ||
            Array.isArray(body) ||
            typeof body !== "object"
          )
            throw new Error();
          config.tracking.query = query as Record<string, unknown>;
          config.tracking.body_template = body as Record<string, unknown>;
        } catch {
          throw new Error(
            "조회 매개변수는 문자열 값으로만 구성한 JSON 객체, 본문 템플릿은 JSON 객체로 입력하세요.",
          );
        }
        config.tracking.callback_secret = "";
        config.tracking.clear_callback_secret = false;
        if (draft.secretMode === "clear")
          config.tracking.clear_callback_secret = true;
        else if (draft.secretMode === "replace") {
          if (
            new TextEncoder().encode(draft.secret).length < 32 ||
            new TextEncoder().encode(draft.secret).length > 1000
          )
            throw new Error("콜백 서명 키는 32~1,000바이트로 입력하세요.");
          config.tracking.callback_secret = draft.secret;
        }
        const next = {
          ...base.current,
          config: {
            ...base.current.config,
            channels: [
              ...base.current.config.channels.filter(
                (row) => row.channel_id !== channel.id,
              ),
              config,
            ],
          },
        };
        await operationsAPI.save(operationsBody(next, revision));
        success("채널 운영 설정을 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const next = await operationsAPI.config();
        base.current = next;
        const config =
          next.config.channels.find((row) => row.channel_id === channel.id) ||
          channelOperationDefaults(channel.id);
        return {
          value: {
            config,
            query: JSON.stringify(config.tracking.query || {}, null, 2),
            body: JSON.stringify(config.tracking.body_template || {}, null, 2),
            secretMode: "keep",
            secret: "",
          },
          revision: next.updated_at,
        };
      }}
    >
      {(draft, setDraft) => {
        const cfg = draft.config,
          t = cfg.tracking,
          p = cfg.protection,
          tracking = (patch: Partial<typeof t>) =>
            setDraft({
              ...draft,
              config: { ...cfg, tracking: { ...t, ...patch } },
            }),
          protection = (patch: Partial<typeof p>) =>
            setDraft({
              ...draft,
              config: { ...cfg, protection: { ...p, ...patch } },
            });
        return (
          <Stack gap="lg">
            <div className="automation-form-block">
              <h3>공급자 배달 결과</h3>
              {channel.type !== "smtp" ? (
                <Stack gap="md">
                  <Switch
                    label="공급자 결과 정기 조회 사용"
                    checked={t.enabled}
                    onChange={(e) =>
                      tracking({ enabled: e.currentTarget.checked })
                    }
                  />
                  <TextInput
                    label="결과 조회 주소"
                    value={t.endpoint}
                    onChange={(e) =>
                      tracking({ endpoint: e.currentTarget.value })
                    }
                    description="발송 채널과 같은 주소 체계·호스트를 사용하며 인증도 재사용합니다. 경로에 {{provider_id}}, {{delivery_id}}를 사용할 수 있습니다."
                  />
                  <Select
                    label="결과 조회 방식"
                    data={["GET", "POST"]}
                    value={t.method}
                    onChange={(value) =>
                      tracking({ method: value === "POST" ? "POST" : "GET" })
                    }
                  />
                  <Textarea
                    label="조회 매개변수 JSON"
                    autosize
                    minRows={3}
                    maxRows={8}
                    value={draft.query}
                    onChange={(e) =>
                      setDraft({ ...draft, query: e.currentTarget.value })
                    }
                    description={
                      '예: {"messageId":"{{provider_id}}"}. 비밀값은 넣지 마세요.'
                    }
                  />
                  {t.method === "POST" && (
                    <Textarea
                      label="조회 본문 템플릿 JSON"
                      autosize
                      minRows={3}
                      maxRows={8}
                      value={draft.body}
                      onChange={(e) =>
                        setDraft({ ...draft, body: e.currentTarget.value })
                      }
                    />
                  )}
                  <TextInput
                    label="결과 상태 필드 경로"
                    value={t.state_path}
                    onChange={(e) =>
                      tracking({ state_path: e.currentTarget.value })
                    }
                    placeholder="data.status"
                  />
                  <SimpleGrid cols={{ base: 1, sm: 2 }}>
                    <NumberInput
                      label="조회 주기 (초)"
                      min={60}
                      max={86400}
                      allowDecimal={false}
                      value={t.poll_interval_seconds}
                      onChange={(value) =>
                        tracking({ poll_interval_seconds: Number(value) })
                      }
                    />
                    <NumberInput
                      label="최대 조회 횟수"
                      min={1}
                      max={100}
                      allowDecimal={false}
                      value={t.max_checks}
                      onChange={(value) =>
                        tracking({ max_checks: Number(value) })
                      }
                    />
                  </SimpleGrid>
                  <TagsInput
                    label="배달 완료 값"
                    value={t.delivered_values}
                    onChange={(value) => tracking({ delivered_values: value })}
                  />
                  <TagsInput
                    label="배달 실패 값"
                    value={t.failed_values}
                    onChange={(value) => tracking({ failed_values: value })}
                  />
                  <TagsInput
                    label="처리 대기 값"
                    value={t.pending_values}
                    onChange={(value) => tracking({ pending_values: value })}
                  />
                </Stack>
              ) : (
                <Text c="dimmed">
                  SMTP는 서명한 사내 게이트웨이 콜백으로 결과를 받습니다. HTTP
                  상태 조회는 제공하지 않습니다.
                </Text>
              )}
            </div>
            <div className="automation-form-block">
              <h3>서명 콜백</h3>
              <Stack gap="md">
                <Switch
                  label="사내 게이트웨이 서명 콜백 사용"
                  checked={t.callback_enabled}
                  onChange={(e) =>
                    tracking({ callback_enabled: e.currentTarget.checked })
                  }
                />
                <TextInput
                  label="콜백 수신 경로"
                  readOnly
                  value={"/api/notification-receipts/" + channel.id}
                />
                <Select
                  label="콜백 서명 키 관리"
                  data={[
                    { value: "keep", label: "저장한 값 유지" },
                    { value: "replace", label: "새 값으로 교체" },
                    { value: "clear", label: "저장한 값 삭제" },
                  ]}
                  value={draft.secretMode}
                  onChange={(value) =>
                    setDraft({
                      ...draft,
                      secretMode: value || "keep",
                      secret: "",
                    })
                  }
                />
                {draft.secretMode === "replace" && (
                  <PasswordInput
                    label="새 콜백 서명 키"
                    description="32~1,000바이트. 저장한 원문은 다시 표시하지 않습니다."
                    value={draft.secret}
                    onChange={(e) =>
                      setDraft({ ...draft, secret: e.currentTarget.value })
                    }
                  />
                )}
                <Text c="dimmed" size="sm">
                  저장 상태:{" "}
                  {t.callback_secret_configured ? "설정됨" : "미설정"}. 콜백은
                  X-Hunter-Timestamp와 본문 원문을 HMAC SHA-256으로 서명해야
                  합니다. 요청 형식은 관리자 가이드를 확인하세요.
                </Text>
              </Stack>
            </div>
            <div className="automation-form-block">
              <h3>대체 채널</h3>
              <Select
                label="확정 실패 시 사용할 채널"
                clearable
                searchable
                data={channels
                  .filter(
                    (row) =>
                      row.id !== channel.id &&
                      row.enabled &&
                      sameFamily(row, channel),
                  )
                  .map((row) => ({ value: row.id, label: row.name }))}
                value={cfg.fallback_channel_id || null}
                onChange={(value) =>
                  setDraft({
                    ...draft,
                    config: { ...cfg, fallback_channel_id: value || "" },
                  })
                }
                description="같은 수신자 계열의 활성 채널로 한 번만 연결합니다. 불명확한 결과에는 대체 발송하지 않습니다."
              />
            </div>
            <div className="automation-form-block">
              <h3>연속 실패 보호</h3>
              <Stack gap="md">
                <Switch
                  label="연속 실패 시 채널 보호 사용"
                  checked={p.enabled}
                  onChange={(e) =>
                    protection({ enabled: e.currentTarget.checked })
                  }
                />
                <SimpleGrid cols={{ base: 1, sm: 3 }}>
                  <NumberInput
                    label="연속 실패 기준"
                    min={2}
                    max={100}
                    allowDecimal={false}
                    value={p.consecutive_failures}
                    onChange={(value) =>
                      protection({ consecutive_failures: Number(value) })
                    }
                  />
                  <NumberInput
                    label="일시 중단 시간 (초)"
                    min={30}
                    max={86400}
                    allowDecimal={false}
                    value={p.open_seconds}
                    onChange={(value) =>
                      protection({ open_seconds: Number(value) })
                    }
                  />
                  <NumberInput
                    label="최소 발송 간격 (초)"
                    min={0}
                    max={3600}
                    allowDecimal={false}
                    value={p.min_interval_seconds}
                    onChange={(value) =>
                      protection({ min_interval_seconds: Number(value) })
                    }
                  />
                </SimpleGrid>
              </Stack>
            </div>
          </Stack>
        );
      }}
    </AutomationEditor>
  );
}
function sameFamily(a: NotificationChannel, b: NotificationChannel) {
  const family = (type: string) =>
    type === "sms" || type === "kakao" ? "phone" : type;
  return family(a.type) === family(b.type);
}
