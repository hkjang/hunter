import { useRef, useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  TagsInput,
  Text,
  TextInput,
} from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, dateText, label, success, useData, type Row } from "./api";
import { LoadState, Empty } from "./components";
import {
  WorkflowTable,
  Metric,
  type WorkflowColumn,
} from "./workflow-components";
import {
  AutomationEditor,
  AutomationSection,
  AutomationValues,
  AutomationRefresh,
} from "./automation-ui";
import {
  automationAPI,
  type NotificationAutomationDocument,
  type Simulation,
} from "./automation-api";
import {
  isoDateTime,
  localDateTime,
  notificationAutomationDraft,
  notificationAutomationPayload,
  weekdayOptions,
  simulationReasonLabels,
  type AutomationContact,
  type NotificationAutomationConfig,
  type OnCallAssignment,
} from "./automation-state";
import { notificationEvents } from "./notification-state";
import type { NotificationRule } from "./notification-api";

type Section =
  | "general"
  | "grouping"
  | "calendar"
  | "acknowledgement"
  | "weekly"
  | "retention";
const sectionTitles: Record<Section, string> = {
  general: "알림 자동화 기본 설정",
  grouping: "묶음 발송과 수신 한도",
  calendar: "영업일과 기한 예고",
  acknowledgement: "업무 확인과 후속 알림",
  weekly: "팀 주간 보고",
  retention: "본문 보존 정책",
};
export function NotificationAutomationPanel({
  view,
}: {
  view: "recipients" | "notifications" | "retention";
}) {
  const data = useData<NotificationAutomationDocument>(
      "/api/notification-automation",
    ),
    users = useData<Row[]>("/api/users");
  const [section, setSection] = useState<Section | null>(null),
    [contact, setContact] = useState<AutomationContact | null | undefined>(),
    [onCall, setOnCall] = useState<OnCallAssignment | null | undefined>(),
    [removal, setRemoval] = useState<{
      kind: "contact" | "on_call";
      value: AutomationContact | OnCallAssignment;
    } | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const doc = data.data,
    config = doc ? notificationAutomationDraft(doc.config) : undefined;
  const userOptions = (users.data || []).map((user) => ({
    value: user.id,
    label: `${user.name || user.username}${user.team ? " · " + user.team : ""}`,
  }));
  const userName = (id: string) =>
    userOptions.find((user) => user.value === id)?.label || id;
  const reload = async () => {
    await data.reload();
  };
  async function save(value: NotificationAutomationConfig, revision: string) {
    await automationAPI.saveNotificationConfig(
      notificationAutomationPayload(value, revision),
    );
    success("알림 자동화 설정을 저장했습니다.");
    await reload();
  }
  async function remove() {
    if (!doc || !removal || busy) return;
    setBusy(true);
    setError("");
    try {
      const next = notificationAutomationDraft(doc.config);
      if (removal.kind === "contact")
        next.contacts = next.contacts.filter(
          (value) =>
            value.user_id !== (removal.value as AutomationContact).user_id,
        );
      else
        next.on_call = next.on_call.filter(
          (value) => !sameOnCall(value, removal.value as OnCallAssignment),
        );
      await save(next, doc.updated_at);
      setRemoval(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const contactColumns: WorkflowColumn<AutomationContact>[] = [
    {
      key: "name",
      label: "사용자",
      value: (row) => userName(row.user_id),
      render: (row) => (
        <Button variant="subtle" onClick={() => setContact(row)}>
          {userName(row.user_id)}
        </Button>
      ),
    },
    { key: "email", label: "이메일", value: (row) => row.email || "—" },
    { key: "phone", label: "전화번호", value: (row) => row.phone || "—" },
    {
      key: "webhook_id",
      label: "API 수신자 ID",
      value: (row) => row.webhook_id || "—",
    },
    {
      key: "verified",
      label: "연락처 확인",
      value: (row) => (row.verified ? "관리자 확인 완료" : "미확인"),
    },
    {
      key: "actions",
      label: "관리",
      value: () => "",
      render: (row) => (
        <Group wrap="nowrap">
          <Button
            variant="default"
            size="compact-sm"
            onClick={() => setContact(row)}
          >
            수정
          </Button>
          <Button
            color="red"
            variant="subtle"
            size="compact-sm"
            aria-label={userName(row.user_id) + " 연락처 삭제"}
            onClick={() => {
              setRemoval({ kind: "contact", value: row });
              setError("");
            }}
          >
            삭제
          </Button>
        </Group>
      ),
    },
  ];
  const onCallColumns: WorkflowColumn<OnCallAssignment>[] = [
    { key: "team", label: "담당 팀", value: (row) => row.team },
    { key: "user", label: "당직자", value: (row) => userName(row.user_id) },
    {
      key: "starts_at",
      label: "당직 시작",
      value: (row) => row.starts_at,
      render: (row) => dateText(row.starts_at),
    },
    {
      key: "ends_at",
      label: "당직 종료",
      value: (row) => row.ends_at,
      render: (row) => dateText(row.ends_at),
    },
    {
      key: "actions",
      label: "관리",
      value: () => "",
      render: (row) => (
        <Group wrap="nowrap">
          <Button
            variant="default"
            size="compact-sm"
            onClick={() => setOnCall(row)}
          >
            수정
          </Button>
          <Button
            variant="subtle"
            color="red"
            size="compact-sm"
            onClick={() => {
              setRemoval({ kind: "on_call", value: row });
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
      {config && doc && (
        <>
          {view === "recipients" && (
            <>
              <Alert color="teal">
                현재 담당자·서비스 소유자·담당 팀·당직자에게 보내려면 사용자
                연락처와 발송 규칙의 동적 수신자 선택을 함께 설정하세요. 연락처
                확인은 관리자가 직접 수행합니다.
              </Alert>
              <Group justify="space-between">
                <Text fw={700}>사용자 연락처</Text>
                <Button
                  leftSection={<IconPlus size={16} />}
                  onClick={() => setContact(null)}
                >
                  연락처 등록
                </Button>
              </Group>
              <WorkflowTable
                rows={config.contacts}
                columns={contactColumns}
                name="사용자 연락처"
                rowKey={(row) => row.user_id}
                reload={reload}
                defaultSort={{ key: "name", direction: "asc" }}
                preferenceContext="automation-contacts"
                empty="등록한 연락처가 없습니다. 사용자를 선택하고 사내 수신 정보를 등록하세요."
              />
              <Group justify="space-between" mt="md">
                <div>
                  <Text fw={700}>팀 당직표</Text>
                  <Text c="dimmed" size="sm">
                    서비스의 팀 이름과 정확히 일치해야 합니다. 입력 시각은 현재
                    브라우저 시간대 기준입니다.
                  </Text>
                </div>
                <Button
                  leftSection={<IconPlus size={16} />}
                  onClick={() => setOnCall(null)}
                >
                  당직 등록
                </Button>
              </Group>
              <WorkflowTable
                rows={config.on_call}
                columns={onCallColumns}
                name="팀 당직표"
                rowKey={(row) =>
                  [row.team, row.user_id, row.starts_at, row.ends_at].join("|")
                }
                reload={reload}
                defaultSort={{ key: "starts_at", direction: "asc" }}
                preferenceContext="automation-oncall"
                empty="등록한 당직표가 없습니다. 팀과 당직 기간을 지정하세요."
              />
              <Button
                component={Link}
                to="/admin/notifications?tab=rules"
                variant="light"
                w="fit-content"
              >
                발송 규칙의 수신자 설정
              </Button>
            </>
          )}
          {view === "notifications" && (
            <>
              <AutomationSection
                title={sectionTitles.general}
                enabled={config.enabled}
                description="신규 자동화 기능의 시간대와 사용 여부를 관리합니다. 사용 안 함이어도 기존 고정 수신자 규칙의 발송은 유지됩니다."
                onEdit={() => setSection("general")}
              >
                <AutomationValues
                  items={[
                    { label: "기준 시간대", value: config.timezone },
                    {
                      label: "확인한 연락처",
                      value: `${config.contacts.filter((row) => row.verified).length}명`,
                    },
                    {
                      label: "등록한 당직",
                      value: `${config.on_call.length}개`,
                    },
                  ]}
                />
              </AutomationSection>
              <AutomationSection
                title={sectionTitles.grouping}
                enabled={config.grouping.enabled}
                description="반복 이벤트를 묶고 같은 수신자에게 집중되는 발송을 제한합니다."
                onEdit={() => setSection("grouping")}
              >
                <AutomationValues
                  items={[
                    {
                      label: "묶음 대기 시간",
                      value: `${config.grouping.window_minutes}분`,
                    },
                    {
                      label: "수신자별 시간당 한도",
                      value: `${config.grouping.recipient_hourly_limit}건`,
                    },
                    {
                      label: "즉시 처리 심각도",
                      value:
                        config.grouping.emergency_severities
                          .map(label)
                          .join(" · ") || "없음",
                    },
                  ]}
                />
              </AutomationSection>
              <AutomationSection
                title={sectionTitles.calendar}
                enabled={config.calendar.enabled}
                description="영업일과 휴일을 기준으로 조치 기한을 미리 알립니다."
                onEdit={() => setSection("calendar")}
              >
                <AutomationValues
                  items={[
                    {
                      label: "영업일",
                      value:
                        weekdayOptions
                          .filter((day) =>
                            config.calendar.weekdays.includes(
                              Number(day.value),
                            ),
                          )
                          .map((day) => day.label)
                          .join(" · ") || "미설정",
                    },
                    {
                      label: "기한 예고",
                      value: `${config.calendar.remind_business_days}영업일 전`,
                    },
                    {
                      label: "지정 휴일",
                      value: `${config.calendar.holidays.length}일`,
                    },
                  ]}
                />
              </AutomationSection>
              <SimpleGrid cols={{ base: 1, lg: 2 }}>
                <AutomationSection
                  title={sectionTitles.acknowledgement}
                  enabled={config.acknowledgement.enabled}
                  description="개인 업무 알림에서 명시적으로 확인하고 미확인 알림을 후속 규칙으로 처리합니다."
                  onEdit={() => setSection("acknowledgement")}
                >
                  <AutomationValues
                    items={[
                      {
                        label: "업무 확인 제한 시간",
                        value: `${config.acknowledgement.timeout_minutes}분`,
                      },
                    ]}
                  />
                </AutomationSection>
                <AutomationSection
                  title={sectionTitles.weekly}
                  enabled={config.weekly.enabled}
                  description="팀 주간 보고 이벤트를 만들며 발송 규칙으로 대상과 수신자를 선택합니다."
                  onEdit={() => setSection("weekly")}
                >
                  <AutomationValues
                    items={[
                      {
                        label: "정기 보고 시각",
                        value: `${weekdayOptions.find((day) => Number(day.value) === config.weekly.weekday)?.label} ${String(config.weekly.hour).padStart(2, "0")}:00`,
                      },
                    ]}
                  />
                </AutomationSection>
              </SimpleGrid>
              <Alert color="teal">
                기한 예고·미확인 후속·주간 보고는 알림센터에서 해당 이벤트의
                발송 규칙을 등록해야 전달됩니다. 업무 확인은 발견 건의 해결이나
                팀장 승인을 대신하지 않습니다.
              </Alert>
            </>
          )}
          {view === "retention" && (
            <>
              <AutomationSection
                title={sectionTitles.retention}
                enabled={config.retention.enabled}
                description="기한이 지난 알림 본문을 자동 정리합니다. 개별 이력은 사유를 기록해 보존할 수 있습니다."
                onEdit={() => setSection("retention")}
              >
                <AutomationValues
                  items={[
                    {
                      label: "본문 보존 기간",
                      value: `${config.retention.payload_days}일`,
                    },
                    { label: "개별 보존", value: "발송 이력 상세에서 지정" },
                  ]}
                />
              </AutomationSection>
              <Alert color="orange">
                보존 기간 이후 삭제한 본문은 화면에서 복구할 수 없습니다. 필요한
                알림은 정리 전에 발송 이력 상세에서 보존을 지정하세요.
              </Alert>
              <Button
                component={Link}
                to="/admin/notifications?tab=history"
                variant="light"
                w="fit-content"
              >
                발송 이력의 보존 상태 확인
              </Button>
            </>
          )}
          {section && (
            <AutomationEditor
              title={sectionTitles[section]}
              value={notificationAutomationDraft(config)}
              revision={doc.updated_at}
              onClose={() => setSection(null)}
              onSave={save}
              loadLatest={async () => {
                const next = await automationAPI.notificationConfig();
                return {
                  value: notificationAutomationDraft(next.config),
                  revision: next.updated_at,
                };
              }}
            >
              {(draft, setDraft) => (
                <ConfigFields
                  section={section}
                  value={draft}
                  onChange={setDraft}
                />
              )}
            </AutomationEditor>
          )}
          {contact !== undefined && (
            <ContactEditor
              source={contact}
              document={doc}
              users={userOptions}
              onClose={() => setContact(undefined)}
              onSaved={reload}
            />
          )}
          {onCall !== undefined && (
            <OnCallEditor
              source={onCall}
              document={doc}
              users={userOptions}
              onClose={() => setOnCall(undefined)}
              onSaved={reload}
            />
          )}
        </>
      )}
      <Modal
        opened={!!removal}
        onClose={() => {
          if (!busy) setRemoval(null);
        }}
        title={removal?.kind === "contact" ? "연락처 삭제" : "당직 삭제"}
        zIndex={350}
      >
        <Stack>
          <Alert color="orange">
            이 항목을 삭제하면 이후 자동 수신자 선정에 사용하지 않습니다.
          </Alert>
          {error && <Alert color="red">{error}</Alert>}
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
    </Stack>
  );
}
function ConfigFields({
  section,
  value,
  onChange,
}: {
  section: Section;
  value: NotificationAutomationConfig;
  onChange: (value: NotificationAutomationConfig) => void;
}) {
  const v = value;
  return (
    <Stack gap="lg">
      {section === "general" && (
        <>
          <Switch
            label="알림 자동화 사용"
            checked={v.enabled}
            onChange={(e) =>
              onChange({ ...v, enabled: e.currentTarget.checked })
            }
          />
          <TextInput
            label="기준 시간대"
            required
            value={v.timezone}
            onChange={(e) =>
              onChange({ ...v, timezone: e.currentTarget.value })
            }
            description="예: Asia/Seoul. 영업일과 주간 보고의 기준 시간대입니다."
          />
        </>
      )}
      {section === "grouping" && (
        <>
          <Switch
            label="묶음 발송 사용"
            checked={v.grouping.enabled}
            onChange={(e) =>
              onChange({
                ...v,
                grouping: { ...v.grouping, enabled: e.currentTarget.checked },
              })
            }
          />
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <NumberInput
              label="묶음 대기 시간 (분)"
              min={5}
              max={1440}
              allowDecimal={false}
              value={v.grouping.window_minutes}
              onChange={(x) =>
                onChange({
                  ...v,
                  grouping: { ...v.grouping, window_minutes: Number(x) },
                })
              }
            />
            <NumberInput
              label="수신자별 시간당 한도"
              min={1}
              max={1000}
              allowDecimal={false}
              value={v.grouping.recipient_hourly_limit}
              onChange={(x) =>
                onChange({
                  ...v,
                  grouping: {
                    ...v.grouping,
                    recipient_hourly_limit: Number(x),
                  },
                })
              }
            />
          </SimpleGrid>
          <MultiSelect
            label="즉시 처리할 심각도"
            data={["critical", "high", "medium", "low", "info"].map(
              (value) => ({ value, label: label(value) }),
            )}
            value={v.grouping.emergency_severities}
            onChange={(x) =>
              onChange({
                ...v,
                grouping: { ...v.grouping, emergency_severities: x },
              })
            }
          />
        </>
      )}
      {section === "calendar" && (
        <>
          <Switch
            label="영업일 기준 기한 예고 사용"
            checked={v.calendar.enabled}
            onChange={(e) =>
              onChange({
                ...v,
                calendar: { ...v.calendar, enabled: e.currentTarget.checked },
              })
            }
          />
          <MultiSelect
            label="영업일"
            data={weekdayOptions}
            value={v.calendar.weekdays.map(String)}
            onChange={(x) =>
              onChange({
                ...v,
                calendar: { ...v.calendar, weekdays: x.map(Number) },
              })
            }
          />
          <TagsInput
            label="휴일 목록"
            description="YYYY-MM-DD 날짜를 입력하고 Enter를 누르세요. 최대 1,000개."
            value={v.calendar.holidays}
            onChange={(x) =>
              onChange({ ...v, calendar: { ...v.calendar, holidays: x } })
            }
          />
          <NumberInput
            label="기한 예고 영업일"
            min={1}
            max={30}
            allowDecimal={false}
            value={v.calendar.remind_business_days}
            onChange={(x) =>
              onChange({
                ...v,
                calendar: { ...v.calendar, remind_business_days: Number(x) },
              })
            }
          />
        </>
      )}
      {section === "acknowledgement" && (
        <>
          <Switch
            label="명시적 업무 확인과 후속 알림 사용"
            checked={v.acknowledgement.enabled}
            onChange={(e) =>
              onChange({
                ...v,
                acknowledgement: {
                  ...v.acknowledgement,
                  enabled: e.currentTarget.checked,
                },
              })
            }
          />
          <NumberInput
            label="업무 확인 제한 시간 (분)"
            min={5}
            max={10080}
            allowDecimal={false}
            value={v.acknowledgement.timeout_minutes}
            onChange={(x) =>
              onChange({
                ...v,
                acknowledgement: {
                  ...v.acknowledgement,
                  timeout_minutes: Number(x),
                },
              })
            }
          />
          <Alert color="teal">
            개인 업무 알림에서 확인 버튼을 눌러야 확인 완료로 기록됩니다. 미확인
            후속 알림에는 별도 발송 규칙이 필요합니다.
          </Alert>
        </>
      )}
      {section === "weekly" && (
        <>
          <Switch
            label="팀 주간 보고 사용"
            checked={v.weekly.enabled}
            onChange={(e) =>
              onChange({
                ...v,
                weekly: { ...v.weekly, enabled: e.currentTarget.checked },
              })
            }
          />
          <Select
            label="보고 요일"
            data={weekdayOptions}
            value={String(v.weekly.weekday)}
            onChange={(x) =>
              onChange({ ...v, weekly: { ...v.weekly, weekday: Number(x) } })
            }
          />
          <NumberInput
            label="보고 시각 (시)"
            min={0}
            max={23}
            allowDecimal={false}
            value={v.weekly.hour}
            onChange={(x) =>
              onChange({ ...v, weekly: { ...v.weekly, hour: Number(x) } })
            }
          />
          <Text c="dimmed">
            {v.timezone} 기준이며 팀 주간 보고 이벤트의 알림 규칙으로 실제 발송
            대상을 정합니다.
          </Text>
        </>
      )}
      {section === "retention" && (
        <>
          <Switch
            label="알림 본문 자동 정리 사용"
            checked={v.retention.enabled}
            onChange={(e) =>
              onChange({
                ...v,
                retention: { ...v.retention, enabled: e.currentTarget.checked },
              })
            }
          />
          <NumberInput
            label="본문 보존 기간 (일)"
            min={1}
            max={3650}
            allowDecimal={false}
            value={v.retention.payload_days}
            onChange={(x) =>
              onChange({
                ...v,
                retention: { ...v.retention, payload_days: Number(x) },
              })
            }
          />
          <Alert color="orange">
            기간이 지난 본문은 자동 정리 대상이 됩니다. 발송 이력 상세에서
            보존을 지정한 항목은 제외합니다.
          </Alert>
        </>
      )}
    </Stack>
  );
}
function ContactEditor({
  source,
  document,
  users,
  onClose,
  onSaved,
}: {
  source: AutomationContact | null;
  document: NotificationAutomationDocument;
  users: { value: string; label: string }[];
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document),
    value = source || {
      user_id: "",
      email: "",
      phone: "",
      webhook_id: "",
      verified: false,
    };
  return (
    <AutomationEditor
      title={source ? "사용자 연락처 수정" : "사용자 연락처 등록"}
      value={value}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (draft, revision) => {
        const next = notificationAutomationDraft(base.current.config);
        next.contacts = source
          ? next.contacts.map((v) => (v.user_id === source.user_id ? draft : v))
          : [...next.contacts, draft];
        await automationAPI.saveNotificationConfig(
          notificationAutomationPayload(next, revision),
        );
        success("연락처를 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = await automationAPI.notificationConfig();
        const row = source
          ? latest.config.contacts.find((v) => v.user_id === source.user_id)
          : value;
        if (!row)
          throw new Error(
            "연락처가 삭제되었습니다. 입력을 확인한 뒤 편집창을 닫고 다시 등록하세요.",
          );
        base.current = latest;
        return { value: row, revision: latest.updated_at };
      }}
    >
      {(draft, setDraft) => (
        <Stack gap="lg">
          <Select
            label="사용자"
            required
            searchable
            data={users}
            value={draft.user_id || null}
            disabled={!!source}
            onChange={(id) => setDraft({ ...draft, user_id: id || "" })}
          />
          <TextInput
            label="이메일"
            type="email"
            value={draft.email}
            onChange={(e) =>
              setDraft({ ...draft, email: e.currentTarget.value })
            }
          />
          <TextInput
            label="전화번호"
            value={draft.phone}
            onChange={(e) =>
              setDraft({ ...draft, phone: e.currentTarget.value })
            }
          />
          <TextInput
            label="API 수신자 ID"
            value={draft.webhook_id}
            onChange={(e) =>
              setDraft({ ...draft, webhook_id: e.currentTarget.value })
            }
            description="사내 일반 HTTP 게이트웨이가 사용하는 수신자 식별자입니다."
          />
          <Checkbox
            label="관리자가 연락처의 정확성을 확인했습니다"
            checked={draft.verified}
            onChange={(e) =>
              setDraft({ ...draft, verified: e.currentTarget.checked })
            }
          />
          <Alert color="teal">
            이 확인은 관리자가 수행한 확인을 기록합니다. 이메일이나 전화번호로
            인증 메시지를 자동 발송하지 않습니다.
          </Alert>
        </Stack>
      )}
    </AutomationEditor>
  );
}
const sameOnCall = (a: OnCallAssignment, b: OnCallAssignment) =>
  a.team === b.team &&
  a.user_id === b.user_id &&
  a.starts_at === b.starts_at &&
  a.ends_at === b.ends_at;
function OnCallEditor({
  source,
  document,
  users,
  onClose,
  onSaved,
}: {
  source: OnCallAssignment | null;
  document: NotificationAutomationDocument;
  users: { value: string; label: string }[];
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document),
    value = source || { team: "", user_id: "", starts_at: "", ends_at: "" };
  return (
    <AutomationEditor
      title={source ? "당직 수정" : "당직 등록"}
      value={value}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (draft, revision) => {
        const next = notificationAutomationDraft(base.current.config);
        next.on_call = source
          ? next.on_call.map((v) => (sameOnCall(v, source) ? draft : v))
          : [...next.on_call, draft];
        await automationAPI.saveNotificationConfig(
          notificationAutomationPayload(next, revision),
        );
        success("당직표를 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = await automationAPI.notificationConfig();
        const row = source
          ? latest.config.on_call.find((v) => sameOnCall(v, source))
          : value;
        if (!row)
          throw new Error(
            "당직 항목이 변경되었거나 삭제되었습니다. 입력을 확인하고 목록에서 다시 편집하세요.",
          );
        base.current = latest;
        return { value: row, revision: latest.updated_at };
      }}
    >
      {(draft, setDraft) => (
        <Stack gap="lg">
          <TextInput
            label="담당 팀"
            required
            value={draft.team}
            onChange={(e) =>
              setDraft({ ...draft, team: e.currentTarget.value })
            }
            description="서비스의 담당 팀 이름과 정확히 일치하게 입력하세요."
          />
          <Select
            label="당직자"
            required
            searchable
            data={users}
            value={draft.user_id || null}
            onChange={(id) => setDraft({ ...draft, user_id: id || "" })}
          />
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <TextInput
              type="datetime-local"
              label="당직 시작"
              required
              value={localDateTime(draft.starts_at)}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  starts_at: isoDateTime(e.currentTarget.value),
                })
              }
            />
            <TextInput
              type="datetime-local"
              label="당직 종료"
              required
              value={localDateTime(draft.ends_at)}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  ends_at: isoDateTime(e.currentTarget.value),
                })
              }
            />
          </SimpleGrid>
          <Text c="dimmed">
            입력은 브라우저 시간대 기준이며 서버에는 시간대를 포함한 시각으로
            저장합니다.
          </Text>
        </Stack>
      )}
    </AutomationEditor>
  );
}
export function NotificationSimulationPanel() {
  const rules = useData<{ items: NotificationRule[] }>(
      "/api/notification-rules",
    ),
    history = useData<{ items: Simulation[] }>(
      "/api/notification-automation/simulations",
    );
  const [rule, setRule] = useState<string | null>(null),
    [from, setFrom] = useState(() =>
      localDateTime(new Date(Date.now() - 7 * 86400000).toISOString()),
    ),
    [to, setTo] = useState(() =>
      localDateTime(new Date(Date.now() + 60000).toISOString()),
    ),
    [limit, setLimit] = useState(500),
    [result, setResult] = useState<Simulation | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  async function simulate() {
    if (busy) return;
    setError("");
    try {
      if (!rule) throw new Error("발송 규칙을 선택하세요.");
      if (!from || !to || Date.parse(from) >= Date.parse(to))
        throw new Error("조회 시작과 종료 시각을 확인하세요.");
      setBusy(true);
      setResult(
        await automationAPI.simulate({
          rule_id: rule,
          from: isoDateTime(from),
          to: isoDateTime(to),
          limit,
        }),
      );
      await history.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const columns: WorkflowColumn<Simulation>[] = [
    {
      key: "created_at",
      label: "검사 시각",
      value: (row) => row.created_at,
      render: (row) => (
        <Button variant="subtle" onClick={() => setResult(row)}>
          {dateText(row.created_at)}
        </Button>
      ),
    },
    {
      key: "rule",
      label: "발송 규칙",
      value: (row) =>
        rules.data?.items.find((v) => v.id === row.rule_id)?.name ||
        row.rule_id,
    },
    { key: "scanned", label: "대조 이벤트", value: (row) => row.scanned },
    { key: "matched", label: "일치 이벤트", value: (row) => row.matched },
    {
      key: "estimated_deliveries",
      label: "예상 발송",
      value: (row) => row.estimated_deliveries,
    },
    {
      key: "truncated",
      label: "조회 범위",
      value: (row) => (row.truncated ? "한도 도달" : "전체 대조"),
    },
  ];
  return (
    <Stack gap="lg">
      <Alert color="teal" title="실제 발송 없이 조건 확인">
        보관한 이벤트를 현재 규칙·연락처·정책과 대조합니다. 과거 발송을
        재현하거나 외부 메시지를 보내지 않습니다. 한도 도달 여부와 제외 사유를
        함께 확인하세요.
      </Alert>
      <AutomationSection title="발송 규칙 모의 검사">
        <LoadState
          loading={rules.loading}
          error={rules.error}
          reload={rules.reload}
        />
        <Stack>
          <Select
            label="발송 규칙"
            searchable
            required
            data={(rules.data?.items || []).map((row) => ({
              value: row.id,
              label: row.name,
            }))}
            value={rule}
            onChange={setRule}
          />
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <TextInput
              type="datetime-local"
              label="조회 시작"
              value={from}
              onChange={(e) => setFrom(e.currentTarget.value)}
            />
            <TextInput
              type="datetime-local"
              label="조회 종료"
              description="종료 시각 미만의 이벤트를 조회합니다. 기본값은 현재 분을 포함합니다."
              value={to}
              onChange={(e) => setTo(e.currentTarget.value)}
            />
            <NumberInput
              label="대조 이벤트 한도"
              min={1}
              max={500}
              allowDecimal={false}
              value={limit}
              onChange={(v) => setLimit(Number(v))}
            />
          </SimpleGrid>
          {error && <Alert color="red">{error}</Alert>}
          <Button w="fit-content" loading={busy} onClick={simulate}>
            발송 없이 모의 검사
          </Button>
        </Stack>
      </AutomationSection>
      {result && (
        <AutomationSection title="모의 검사 결과">
          <SimpleGrid cols={{ base: 2, sm: 4 }}>
            <Metric label="대조 이벤트" value={result.scanned} />
            <Metric label="일치 이벤트" value={result.matched} />
            <Metric label="선정 수신자" value={result.recipient_count} />
            <Metric label="예상 발송" value={result.estimated_deliveries} />
          </SimpleGrid>
          {result.truncated && (
            <Alert color="yellow" mt="md">
              조회 한도에 도달했습니다. 이 결과는 지정 기간 전체가 아닐 수
              있습니다.
            </Alert>
          )}
          <Stack mt="lg">
            {(result.reasons || []).map((row) => (
              <Group key={row.code} justify="space-between">
                <Text>{simulationReasonLabels[row.code] || row.code}</Text>
                <Text fw={700}>{row.count}건</Text>
              </Group>
            ))}
          </Stack>
          <Text c="dimmed" mt="md">
            조건은 검사 시점 기준입니다. 실제 이벤트 처리 시 현재 대상과 권한을
            다시 확인합니다.
          </Text>
        </AutomationSection>
      )}
      <WorkflowTable
        rows={history.data?.items || []}
        columns={columns}
        name="모의 검사 이력"
        rowKey={(row) => row.id}
        loading={history.loading}
        error={history.error}
        reload={history.reload}
        defaultSort={{ key: "created_at", direction: "desc" }}
        preferenceContext="automation-simulations"
        empty="모의 검사 이력이 없습니다. 최근 보관 이벤트로 규칙을 먼저 확인하세요."
      />
    </Stack>
  );
}
