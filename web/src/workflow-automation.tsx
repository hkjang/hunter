import { useEffect, useRef, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  Pagination,
  Paper,
  PasswordInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  TagsInput,
  Text,
  TextInput,
} from "@mantine/core";
import { IconExternalLink, IconPlus } from "@tabler/icons-react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { api, dateText, success, useCan, useData, type Row } from "./api";
import { Empty, LoadState } from "./components";
import { WorkflowTable, type WorkflowColumn } from "./workflow-components";
import { switchWorkflowTab } from "./workflow-navigation";
import {
  AutomationEditor,
  AutomationRefresh,
  AutomationSection,
  AutomationStatus,
  AutomationValues,
} from "./automation-ui";
import { boundedPageQuery, changeEvidenceEntries } from "./automation-state";
import {
  changeEventOptions,
  newChangeRule,
  newTicketRule,
  profileOptions,
  workflowAutomationAPI,
  workflowConfigBody,
  workflowConfigDraft,
  type ChangeRule,
  type TicketRule,
  type WorkflowAutomationDocument,
  type WorkflowPreview,
  type WorkflowRun,
  type WorkflowRunPage,
} from "./workflow-automation-api";

type Dependencies = {
  services: Row[];
  integrations: Row[];
  scopes: Row[];
  scenarios: Row[];
};
export function WorkflowAutomationPanel() {
  const can = useCan(),
    [params, setParams] = useSearchParams(),
    location = useLocation(),
    mode = params.get("workflow") === "tickets" ? "tickets" : "changes";
  const data = useData<WorkflowAutomationDocument>("/api/workflow-automation"),
    services = useData<Row[]>(can("services:read") ? "/api/services" : null),
    integrations = useData<Row[]>(
      can("integrations:manage") ? "/api/integrations" : null,
    ),
    scopes = useData<Row[]>(can("services:read") ? "/api/scopes" : null),
    scenarios = useData<Row[]>(can("services:read") ? "/api/scenarios" : null);
  const [change, setChange] = useState<ChangeRule | null | undefined>(),
    [ticket, setTicket] = useState<TicketRule | null | undefined>(),
    [general, setGeneral] = useState(false),
    [preview, setPreview] = useState(false),
    [sync, setSync] = useState(false),
    [removal, setRemoval] = useState<{
      kind: "change" | "ticket";
      id: string;
      name: string;
    } | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const doc = data.data ? workflowConfigDraft(data.data) : undefined,
    deps = {
      services: services.data || [],
      integrations: integrations.data || [],
      scopes: scopes.data || [],
      scenarios: scenarios.data || [],
    };
  const serviceName = (id: string) =>
    deps.services.find((row) => row.id === id)?.name || id;
  const integrationName = (id: string) =>
    deps.integrations.find((row) => row.id === id)?.name || id;
  const reload = async () => {
    await data.reload();
  };
  function changeMode(next: string) {
    const mapped = new URLSearchParams(params);
    mapped.set("tab", mode);
    const output = switchWorkflowTab(mapped, mode, next, [
      "changes",
      "tickets",
    ]);
    output.set("workflow", next);
    output.set("tab", "workflows");
    setParams(output, { preventScrollReset: true, state: location.state });
  }
  const changeColumns: WorkflowColumn<ChangeRule>[] = [
    {
      key: "name",
      label: "변경 영향 규칙",
      value: (row) => row.name,
      render: (row) => (
        <Button variant="subtle" onClick={() => setChange(row)}>
          {row.name}
        </Button>
      ),
    },
    {
      key: "service",
      label: "대상 서비스",
      value: (row) => serviceName(row.service_id),
    },
    {
      key: "integration",
      label: "변경 연동",
      value: (row) => integrationName(row.integration_id),
    },
    {
      key: "events",
      label: "이벤트",
      value: (row) =>
        row.event_types
          .map(
            (value) =>
              changeEventOptions.find((event) => event.value === value)
                ?.label || value,
          )
          .join(" · "),
    },
    {
      key: "profile",
      label: "진단 프로파일",
      value: (row) =>
        profileOptions.find((option) => option.value === row.profile)?.label ||
        row.profile,
    },
    {
      key: "enabled",
      label: "사용 상태",
      value: (row) => (row.enabled ? "사용 중" : "사용 안 함"),
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
            onClick={() => setChange(row)}
          >
            수정
          </Button>
          <Button
            variant="subtle"
            color="red"
            size="compact-sm"
            onClick={() => {
              setRemoval({ kind: "change", id: row.id, name: row.name });
              setError("");
            }}
          >
            삭제
          </Button>
        </Group>
      ),
    },
  ];
  const ticketColumns: WorkflowColumn<TicketRule>[] = [
    {
      key: "name",
      label: "ITSM 동기화 규칙",
      value: (row) => row.name,
      render: (row) => (
        <Button variant="subtle" onClick={() => setTicket(row)}>
          {row.name}
        </Button>
      ),
    },
    {
      key: "service",
      label: "대상 서비스",
      value: (row) => serviceName(row.service_id),
    },
    {
      key: "integration",
      label: "ITSM 연동",
      value: (row) => integrationName(row.integration_id),
    },
    {
      key: "poll",
      label: "조회 주기",
      value: (row) => row.poll_interval_minutes,
      render: (row) => `${row.poll_interval_minutes}분`,
    },
    {
      key: "retest",
      label: "배포 후 재검증",
      value: (row) => (row.retest_on_deploy ? "사용" : "사용 안 함"),
    },
    {
      key: "enabled",
      label: "사용 상태",
      value: (row) => (row.enabled ? "사용 중" : "사용 안 함"),
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
            onClick={() => setTicket(row)}
          >
            수정
          </Button>
          <Button
            variant="subtle"
            color="red"
            size="compact-sm"
            onClick={() => {
              setRemoval({ kind: "ticket", id: row.id, name: row.name });
              setError("");
            }}
          >
            삭제
          </Button>
        </Group>
      ),
    },
  ];
  async function remove() {
    if (!doc || !removal || busy) return;
    setBusy(true);
    setError("");
    try {
      await workflowAutomationAPI.save(
        workflowConfigBody(
          {
            ...doc,
            change_rules:
              removal.kind === "change"
                ? doc.change_rules.filter((row) => row.id !== removal.id)
                : doc.change_rules,
            ticket_rules:
              removal.kind === "ticket"
                ? doc.ticket_rules.filter((row) => row.id !== removal.id)
                : doc.ticket_rules,
          },
          doc.updated_at,
        ),
      );
      success("자동화 규칙을 삭제했습니다.");
      await reload();
      setRemoval(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
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
            title="변경·ITSM 자동화"
            enabled={doc.enabled}
            description="허용한 변경 이벤트를 진단으로 연결하고 개선 요청의 외부 상태를 동기화합니다."
            onEdit={() => setGeneral(true)}
          >
            <AutomationValues
              items={[
                {
                  label: "변경 영향 규칙",
                  value: `${doc.change_rules.length}개`,
                },
                {
                  label: "ITSM 동기화 규칙",
                  value: `${doc.ticket_rules.length}개`,
                },
                {
                  label: "서명 키",
                  value: doc.signing_secret_configured ? "설정됨" : "미설정",
                },
              ]}
            />
          </AutomationSection>
          <Group justify="space-between">
            <Group>
              <Button
                variant={mode === "changes" ? "filled" : "default"}
                onClick={() => changeMode("changes")}
              >
                변경 영향 규칙
              </Button>
              <Button
                variant={mode === "tickets" ? "filled" : "default"}
                onClick={() => changeMode("tickets")}
              >
                ITSM 동기화 규칙
              </Button>
            </Group>
            <Group>
              {mode === "changes" ? (
                <Button variant="light" onClick={() => setPreview(true)}>
                  변경 조건 미리보기
                </Button>
              ) : (
                <Button
                  variant="light"
                  disabled={
                    !can("integrations:manage") ||
                    !can("findings:read") ||
                    !can("findings:write")
                  }
                  onClick={() => setSync(true)}
                >
                  개선 요청 동기화
                </Button>
              )}
              <Button
                leftSection={<IconPlus size={16} />}
                onClick={() =>
                  mode === "changes" ? setChange(null) : setTicket(null)
                }
              >
                규칙 추가
              </Button>
            </Group>
          </Group>
          {mode === "changes" ? (
            <>
              <Alert color="teal">
                이벤트 종류가 일치하고 변경 경로·API·구성요소·권한 패턴 중 하나
                이상이 맞으면 진단 후보가 됩니다. 실제 실행 전 현재 권한·대상
                범위·승인 설정을 다시 확인합니다.
              </Alert>
              <WorkflowTable
                rows={doc.change_rules}
                columns={changeColumns}
                name="변경 영향 규칙"
                rowKey={(row) => row.id}
                reload={reload}
                preferenceContext="automation-change"
                defaultSort={{ key: "name", direction: "asc" }}
                empty="변경 영향 규칙을 추가해 필요한 서비스와 변경 패턴을 지정하세요."
              />
            </>
          ) : (
            <>
              <Alert color="teal">
                외부 담당자·기한과 로컬 변경이 충돌하면 보존합니다. 외부 티켓의
                완료 상태만으로 발견 건을 해결하지 않습니다. 배포 후 재검증도
                별도 실행 조건을 따릅니다.
              </Alert>
              <WorkflowTable
                rows={doc.ticket_rules}
                columns={ticketColumns}
                name="ITSM 동기화 규칙"
                rowKey={(row) => row.id}
                reload={reload}
                preferenceContext="automation-tickets"
                defaultSort={{ key: "name", direction: "asc" }}
                empty="기존 REST 연동과 서비스에 맞는 티켓 조회 규칙을 등록하세요."
              />
            </>
          )}
          {change !== undefined && (
            <WorkflowRuleEditor
              kind="change"
              source={change}
              document={doc}
              deps={deps}
              onClose={() => setChange(undefined)}
              onSaved={reload}
            />
          )}
          {ticket !== undefined && (
            <WorkflowRuleEditor
              kind="ticket"
              source={ticket}
              document={doc}
              deps={deps}
              onClose={() => setTicket(undefined)}
              onSaved={reload}
            />
          )}
          {general && (
            <WorkflowGeneralEditor
              document={doc}
              onClose={() => setGeneral(false)}
              onSaved={reload}
            />
          )}
        </>
      )}
      {preview && (
        <WorkflowPreviewModal deps={deps} onClose={() => setPreview(false)} />
      )}{" "}
      {sync && <TicketSyncModal onClose={() => setSync(false)} />}
      <Modal
        opened={!!removal}
        onClose={() => {
          if (!busy) setRemoval(null);
        }}
        title="자동화 규칙 삭제"
        zIndex={350}
      >
        <Stack>
          <Text>
            {removal?.name} 규칙을 삭제합니다. 이후 이벤트부터 이 규칙을
            적용하지 않습니다.
          </Text>
          {error && <Alert color="red">{error}</Alert>}
          <Group justify="flex-end">
            <Button
              variant="default"
              onClick={() => setRemoval(null)}
              disabled={busy}
            >
              취소
            </Button>
            <Button color="red" loading={busy} onClick={remove}>
              규칙 삭제
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
function WorkflowGeneralEditor({
  document,
  onClose,
  onSaved,
}: {
  document: WorkflowAutomationDocument;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document);
  return (
    <AutomationEditor
      title="변경·ITSM 자동화 기본 설정"
      value={{ enabled: document.enabled, secretMode: "keep", secret: "" }}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (draft, revision) => {
        const body: Row = {
          ...workflowConfigBody(
            { ...base.current, enabled: draft.enabled },
            revision,
          ),
        };
        if (draft.secretMode === "clear") body.clear_secret = true;
        else if (draft.secretMode === "replace") {
          if (!draft.secret.trim()) throw new Error("새 서명 키를 입력하세요.");
          body.signing_secret = draft.secret;
        }
        await workflowAutomationAPI.save(body);
        success("변경·ITSM 자동화 설정을 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const next = workflowConfigDraft(await workflowAutomationAPI.config());
        base.current = next;
        return {
          value: { enabled: next.enabled, secretMode: "keep", secret: "" },
          revision: next.updated_at,
        };
      }}
    >
      {(draft, setDraft) => (
        <Stack gap="lg">
          <Switch
            label="변경·ITSM 자동화 사용"
            checked={draft.enabled}
            onChange={(e) =>
              setDraft({ ...draft, enabled: e.currentTarget.checked })
            }
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
              setDraft({ ...draft, secretMode: value || "keep", secret: "" })
            }
          />
          {draft.secretMode === "replace" && (
            <PasswordInput
              label="새 콜백 서명 키"
              description="32바이트 이상. 사내 게이트웨이와 동일한 서명 키를 사용하세요."
              value={draft.secret}
              onChange={(e) =>
                setDraft({ ...draft, secret: e.currentTarget.value })
              }
            />
          )}
          <Text c="dimmed">
            서명 키는 사내 ITSM 콜백을 검증합니다. 저장한 원문은 다시 표시하지
            않습니다. 요청 형식과 서명 방법은 관리자 가이드를 확인하세요.
          </Text>
        </Stack>
      )}
    </AutomationEditor>
  );
}
function WorkflowRuleEditor({
  kind,
  source,
  document,
  deps,
  onClose,
  onSaved,
}: {
  kind: "change" | "ticket";
  source: ChangeRule | TicketRule | null;
  document: WorkflowAutomationDocument;
  deps: Dependencies;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const base = useRef(document),
    initial = useRef(
      source || (kind === "change" ? newChangeRule() : newTicketRule()),
    );
  return (
    <AutomationEditor
      title={
        (kind === "change" ? "변경 영향 규칙" : "ITSM 동기화 규칙") +
        (source ? " 수정" : " 추가")
      }
      value={initial.current}
      revision={document.updated_at}
      onClose={onClose}
      onSave={async (draft, revision) => {
        if (!draft.name.trim() || !draft.service_id || !draft.integration_id)
          throw new Error("규칙 이름·대상 서비스·연동을 모두 지정하세요.");
        const next = { ...base.current };
        if (kind === "change") {
          const rule = draft as ChangeRule;
          if (!rule.event_types.length)
            throw new Error("변경 이벤트를 하나 이상 선택하세요.");
          if (rule.profile === "authorization" && !rule.scenario_id)
            throw new Error("업무 권한 검증 시나리오를 선택하세요.");
          next.change_rules = source
            ? next.change_rules.map((row) =>
                row.id === source.id ? rule : row,
              )
            : [...next.change_rules, rule];
        } else {
          const rule = draft as TicketRule;
          if (!rule.read_url_template.trim())
            throw new Error("티켓 조회 주소를 입력하세요.");
          next.ticket_rules = source
            ? next.ticket_rules.map((row) =>
                row.id === source.id ? rule : row,
              )
            : [...next.ticket_rules, rule];
        }
        await workflowAutomationAPI.save(workflowConfigBody(next, revision));
        success("자동화 규칙을 저장했습니다.");
        await onSaved();
      }}
      loadLatest={async () => {
        const latest = workflowConfigDraft(
          await workflowAutomationAPI.config(),
        );
        const row = source
          ? (kind === "change"
              ? latest.change_rules
              : latest.ticket_rules
            ).find((row) => row.id === source.id)
          : initial.current;
        if (!row)
          throw new Error(
            "규칙이 삭제되었습니다. 현재 입력을 확인한 뒤 다시 등록하세요.",
          );
        base.current = latest;
        return { value: row, revision: latest.updated_at };
      }}
    >
      {(draft, setDraft) => (
        <Stack gap="lg">
          <TextInput
            label="규칙 이름"
            required
            value={draft.name}
            onChange={(e) =>
              setDraft({ ...draft, name: e.currentTarget.value })
            }
          />
          <Switch
            label="이 규칙 사용"
            checked={draft.enabled}
            onChange={(e) =>
              setDraft({ ...draft, enabled: e.currentTarget.checked })
            }
          />
          <DependencyFields
            deps={{
              ...deps,
              integrations: deps.integrations.filter(
                (row) => row.type === (kind === "change" ? "webhook" : "rest"),
              ),
            }}
            serviceId={draft.service_id}
            integrationId={draft.integration_id}
            onService={(id) =>
              setDraft({
                ...draft,
                service_id: id,
                scope_id: "",
                ...("scenario_id" in draft ? { scenario_id: "" } : {}),
              })
            }
            onIntegration={(id) => setDraft({ ...draft, integration_id: id })}
          />
          {kind === "change" ? (
            <ChangeFields
              value={draft as ChangeRule}
              onChange={setDraft}
              deps={deps}
            />
          ) : (
            <TicketFields
              value={draft as TicketRule}
              onChange={setDraft}
              deps={deps}
            />
          )}
        </Stack>
      )}
    </AutomationEditor>
  );
}
function DependencyFields({
  deps,
  serviceId,
  integrationId,
  onService,
  onIntegration,
}: {
  deps: Dependencies;
  serviceId: string;
  integrationId: string;
  onService: (id: string) => void;
  onIntegration: (id: string) => void;
}) {
  return (
    <SimpleGrid cols={{ base: 1, sm: 2 }}>
      {deps.services.length ? (
        <Select
          label="대상 서비스"
          required
          searchable
          data={deps.services.map((row) => ({
            value: row.id,
            label: row.name,
          }))}
          value={serviceId || null}
          onChange={(value) => onService(value || "")}
        />
      ) : (
        <TextInput
          label="대상 서비스 ID"
          required
          value={serviceId}
          onChange={(e) => onService(e.currentTarget.value)}
        />
      )}{" "}
      {deps.integrations.length ? (
        <Select
          label="연동"
          required
          searchable
          data={deps.integrations.map((row) => ({
            value: row.id,
            label: row.name,
          }))}
          value={integrationId || null}
          onChange={(value) => onIntegration(value || "")}
        />
      ) : (
        <TextInput
          label="연동 ID"
          required
          value={integrationId}
          onChange={(e) => onIntegration(e.currentTarget.value)}
        />
      )}
    </SimpleGrid>
  );
}
function ScopeSelect({
  deps,
  serviceId,
  value,
  onChange,
}: {
  deps: Dependencies;
  serviceId: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <Select
      label="진단 허용 범위 (선택)"
      description="비워 두면 서버가 현재 유효한 허용 범위를 확인합니다."
      searchable
      clearable
      data={deps.scopes
        .filter((row) => row.service_id === serviceId)
        .map((row) => ({ value: row.id, label: row.name }))}
      value={value || null}
      onChange={(value) => onChange(value || "")}
    />
  );
}
function ChangeFields({
  value: v,
  onChange,
  deps,
}: {
  value: ChangeRule;
  onChange: (value: ChangeRule) => void;
  deps: Dependencies;
}) {
  return (
    <>
      <MultiSelect
        label="변경 이벤트"
        required
        data={changeEventOptions}
        value={v.event_types}
        onChange={(value) => onChange({ ...v, event_types: value })}
      />
      <div className="automation-form-block">
        <h3>변경 일치 조건</h3>
        <Text size="sm" c="dimmed" mb="md">
          그룹 중 하나 이상이 일치하면 대상이 됩니다. *, **, ? 패턴을 사용할 수
          있습니다. 예: src/**, /api/**
        </Text>
        <Stack>
          {(
            [
              ["paths", "파일 경로 패턴"],
              ["api_paths", "API 경로 패턴"],
              ["components", "구성요소 패턴"],
              ["permissions", "권한 패턴"],
            ] as const
          ).map(([key, label]) => (
            <TagsInput
              key={key}
              label={label}
              value={v.match[key]}
              onChange={(value) =>
                onChange({ ...v, match: { ...v.match, [key]: value } })
              }
              description="패턴을 입력하고 Enter를 누르세요."
            />
          ))}
        </Stack>
      </div>
      <Select
        label="진단 프로파일"
        data={profileOptions}
        value={v.profile}
        onChange={(value) =>
          onChange({ ...v, profile: value || "http-baseline", scenario_id: "" })
        }
      />
      {v.profile === "authorization" && (
        <Select
          label="권한 검증 시나리오"
          required
          searchable
          data={deps.scenarios
            .filter((row) => row.service_id === v.service_id)
            .map((row) => ({ value: row.id, label: row.name }))}
          value={v.scenario_id || null}
          onChange={(value) => onChange({ ...v, scenario_id: value || "" })}
        />
      )}
      <ScopeSelect
        deps={deps}
        serviceId={v.service_id}
        value={v.scope_id}
        onChange={(value) => onChange({ ...v, scope_id: value })}
      />
    </>
  );
}
function TicketFields({
  value: v,
  onChange,
  deps,
}: {
  value: TicketRule;
  onChange: (value: TicketRule) => void;
  deps: Dependencies;
}) {
  return (
    <>
      <NumberInput
        label="티켓 조회 주기 (분)"
        min={5}
        max={10080}
        allowDecimal={false}
        value={v.poll_interval_minutes}
        onChange={(value) =>
          onChange({ ...v, poll_interval_minutes: Number(value) })
        }
      />
      <TextInput
        label="티켓 조회 주소 템플릿"
        required
        value={v.read_url_template}
        onChange={(e) =>
          onChange({ ...v, read_url_template: e.currentTarget.value })
        }
        placeholder="https://itsm.internal/tickets/{{external_id}}"
        description="선택한 REST 연동과 같은 주소 체계·호스트를 사용합니다. 외부 ID는 경로에만 치환하세요."
      />
      <div className="automation-form-block">
        <h3>외부 응답 필드 연결</h3>
        <Text c="dimmed" size="sm" mb="md">
          JSON 응답의 점 경로를 입력하세요. 외부 수정 시각은 RFC3339
          문자열이어야 합니다.
        </Text>
        <SimpleGrid cols={{ base: 1, sm: 2 }}>
          {(
            [
              ["external_id", "외부 티켓 ID"],
              ["assignee", "담당자"],
              ["due_date", "조치 기한"],
              ["status", "티켓 상태"],
              ["updated_at", "외부 수정 시각"],
              ["deployment_reference", "배포 참조"],
              ["deployment_confirmed", "배포 확인 값"],
            ] as const
          ).map(([key, label]) => (
            <TextInput
              key={key}
              label={label}
              value={v.field_map[key]}
              onChange={(e) =>
                onChange({
                  ...v,
                  field_map: { ...v.field_map, [key]: e.currentTarget.value },
                })
              }
            />
          ))}
        </SimpleGrid>
      </div>
      <TagsInput
        label="외부 완료 상태"
        value={v.complete_statuses}
        onChange={(value) => onChange({ ...v, complete_statuses: value })}
        description="외부 완료 상태도 발견 건을 자동 해결하지 않습니다."
      />
      <Switch
        label="배포 확인 후 재검증 사용"
        checked={v.retest_on_deploy}
        onChange={(e) =>
          onChange({ ...v, retest_on_deploy: e.currentTarget.checked })
        }
      />
      {v.retest_on_deploy && (
        <ScopeSelect
          deps={deps}
          serviceId={v.service_id}
          value={v.scope_id}
          onChange={(value) => onChange({ ...v, scope_id: value })}
        />
      )}
    </>
  );
}
function WorkflowPreviewModal({
  deps,
  onClose,
}: {
  deps: Dependencies;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState({
      service_id: "",
      integration_id: "",
      event_type: "push",
      changes: {
        paths: [],
        api_paths: [],
        components: [],
        permissions: [],
      } as Record<string, string[]>,
    }),
    [result, setResult] = useState<WorkflowPreview | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  async function preview() {
    if (busy) return;
    setError("");
    try {
      if (!draft.service_id || !draft.integration_id)
        throw new Error("서비스와 연동을 선택하세요.");
      setBusy(true);
      setResult(await workflowAutomationAPI.preview(draft));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      opened
      title="변경 조건 미리보기"
      onClose={() => {
        if (!busy) onClose();
      }}
      size="xl"
      withCloseButton={!busy}
      closeOnEscape={!busy}
      closeOnClickOutside={!busy}
    >
      <Stack gap="lg">
        <Alert color="teal">
          현재 규칙과 실행 조건만 확인하며 진단을 생성하지 않습니다.
        </Alert>
        <DependencyFields
          deps={deps}
          serviceId={draft.service_id}
          integrationId={draft.integration_id}
          onService={(value) => setDraft({ ...draft, service_id: value })}
          onIntegration={(value) =>
            setDraft({ ...draft, integration_id: value })
          }
        />
        <Select
          label="변경 이벤트"
          data={changeEventOptions}
          value={draft.event_type}
          onChange={(value) =>
            setDraft({ ...draft, event_type: value || "push" })
          }
        />
        {(
          [
            ["paths", "변경 파일 경로"],
            ["api_paths", "변경 API 경로"],
            ["components", "변경 구성요소"],
            ["permissions", "변경 권한"],
          ] as const
        ).map(([key, label]) => (
          <TagsInput
            key={key}
            label={label}
            value={draft.changes[key]}
            onChange={(value) =>
              setDraft({
                ...draft,
                changes: { ...draft.changes, [key]: value },
              })
            }
          />
        ))}
        {error && <Alert color="red">{error}</Alert>}
        <Button loading={busy} onClick={preview}>
          진단 없이 조건 검사
        </Button>
        {result && (
          <div className="automation-result">
            <Text fw={700}>실행 가능 후보 {result.scan_count}개</Text>
            {result.matched?.length ? (
              result.matched.map((row) => (
                <Stack key={row.rule_id} gap="xs" mt="md">
                  <Group>
                    <Text fw={700}>{row.rule_name}</Text>
                    <Badge color={row.allowed ? "teal" : "orange"}>
                      {row.allowed ? "현재 조건 허용" : "현재 조건 차단"}
                    </Badge>
                  </Group>
                  <Text size="sm">{row.reason}</Text>
                  {changeEvidenceEntries(row.matched_changes).map(
                    ({ key, label, values }) => (
                      <Text key={key} size="sm">
                        {label}: {values.join(", ")}
                      </Text>
                    ),
                  )}
                </Stack>
              ))
            ) : (
              <Text mt="sm">일치하는 규칙이 없습니다.</Text>
            )}
          </div>
        )}
      </Stack>
    </Modal>
  );
}
function TicketSyncModal({ onClose }: { onClose: () => void }) {
  const remediations = useData<Row[]>("/api/remediations"),
    [id, setId] = useState<string | null>(null),
    [result, setResult] = useState<WorkflowRun | null>(null),
    [accept, setAccept] = useState(false),
    [findingRevision, setFindingRevision] = useState(""),
    [findingPreview, setFindingPreview] = useState<Row | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  async function sync(replace = false) {
    if (!id || busy) return;
    setBusy(true);
    setError("");
    try {
      const row = await api<Row>("/api/remediations/" + encodeURIComponent(id));
      const body: Row = {
        remediation_id: id,
        expected_updated_at: row.updated_at,
      };
      if (replace) {
        if (!accept) throw new Error("외부 값으로 대체하는 내용을 확인하세요.");
        if (!findingRevision || !result?.result.external_updated_at)
          throw new Error(
            "현재 상태를 다시 동기화하여 충돌 내용을 확인하세요.",
          );
        body.accept_external = true;
        body.expected_finding_updated_at = findingRevision;
        body.expected_external_updated_at = result.result.external_updated_at;
      } else {
        const finding = await api<Row>(
          "/api/findings/" + encodeURIComponent(row.finding_id),
        );
        setFindingRevision(finding.updated_at);
        setFindingPreview({
          assignee: finding.assignee,
          due_date: finding.due_date,
        });
      }
      setResult(await workflowAutomationAPI.sync(body));
      setAccept(false);
    } catch (e) {
      setError(
        (e as Error).message +
          " 현재 상태를 다시 동기화하여 최신 내용을 확인하세요.",
      );
      setAccept(false);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      opened
      title="개선 요청 동기화"
      onClose={() => {
        if (!busy) onClose();
      }}
      size="lg"
      withCloseButton={!busy}
      closeOnEscape={!busy}
      closeOnClickOutside={!busy}
    >
      <Stack gap="lg">
        <Alert color="orange">
          저장한 ITSM 조회 규칙으로 사내 시스템을 조회하고 로컬 담당자·기한·외부
          상태를 동기화합니다. 충돌은 자동 덮어쓰지 않습니다.
        </Alert>
        <LoadState
          loading={remediations.loading}
          error={remediations.error}
          reload={remediations.reload}
        />
        <Select
          label="개선 요청"
          disabled={busy}
          searchable
          data={(remediations.data || []).map((row) => ({
            value: row.id,
            label: row.name || row.id,
          }))}
          value={id}
          onChange={(value) => {
            setId(value);
            setResult(null);
            setAccept(false);
            setFindingRevision("");
            setFindingPreview(null);
          }}
        />
        {error && <Alert color="red">{error}</Alert>}
        <Button disabled={!id} loading={busy} onClick={() => sync()}>
          현재 상태 동기화
        </Button>
        {result && (
          <div className="automation-result">
            <WorkflowRunResult run={result} />
            {result.status === "conflict" && (
              <Stack mt="md">
                <AutomationValues
                  items={[
                    {
                      label: "로컬 담당자 (확인 시점)",
                      value: findingPreview?.assignee || "미지정",
                    },
                    {
                      label: "로컬 조치 기한 (확인 시점)",
                      value: dateText(findingPreview?.due_date),
                    },
                  ]}
                />
                <Checkbox
                  label="표시한 외부 담당자·기한으로 로컬 값을 대체하는 데 동의합니다"
                  checked={accept}
                  onChange={(e) => setAccept(e.currentTarget.checked)}
                />
                <Button
                  color="orange"
                  loading={busy}
                  disabled={!accept}
                  onClick={() => sync(true)}
                >
                  외부 값으로 명시적 대체
                </Button>
              </Stack>
            )}
          </div>
        )}
      </Stack>
    </Modal>
  );
}
export function WorkflowHistoryPanel() {
  const [params, setParams] = useSearchParams(),
    location = useLocation(),
    query = boundedPageQuery(params, {
      kind: ["change", "ticket_sync"],
      status: [
        "completed",
        "partial",
        "blocked",
        "no_match",
        "conflict",
        "unchanged",
      ],
    });
  const data = useData<WorkflowRunPage>(
      "/api/workflow-automation/runs?" + query.toString(),
    ),
    [detail, setDetail] = useState<WorkflowRun | null>(null);
  function update(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "page") next.delete("page");
    setParams(next, { preventScrollReset: true, state: location.state });
  }
  const total = data.data?.total || 0,
    pages = Math.max(1, Math.ceil(total / (data.data?.page_size || 25)));
  useEffect(() => {
    if (data.loading || !data.data || (data.data.page || 1) <= pages) return;
    const next = new URLSearchParams(params);
    next.set("page", String(pages));
    setParams(next, {
      replace: true,
      preventScrollReset: true,
      state: location.state,
    });
  }, [data.loading, data.data, pages, params, setParams, location.state]);
  return (
    <Stack gap="lg">
      <Alert color="teal">
        실제 자동화 결정과 동기화 결과를 최근 실행 순으로 표시합니다. 차단·변경
        없음·충돌도 실행 기록으로 남깁니다.
      </Alert>
      <Paper withBorder radius="lg">
        <div className="automation-paged-toolbar">
          <Select
            label="자동화 종류"
            clearable
            data={[
              { value: "change", label: "변경 기반 진단" },
              { value: "ticket_sync", label: "ITSM 동기화" },
            ]}
            value={query.get("kind")}
            onChange={(value) => update("kind", value || "")}
          />
          <Select
            label="실행 상태"
            clearable
            data={[
              { value: "completed", label: "완료" },
              { value: "partial", label: "일부 완료" },
              { value: "blocked", label: "조건 차단" },
              { value: "no_match", label: "일치 없음" },
              { value: "conflict", label: "변경 충돌" },
              { value: "unchanged", label: "변경 없음" },
            ]}
            value={query.get("status")}
            onChange={(value) => update("status", value || "")}
          />
          <Group justify="flex-end">
            <AutomationRefresh onClick={data.reload} />
          </Group>
        </div>
        <LoadState
          loading={data.loading}
          error={data.error}
          reload={data.reload}
        />
        {!data.loading && !data.error && (
          <>
            {data.data?.items.length ? (
              <div
                className="automation-scroll"
                role="region"
                tabIndex={0}
                aria-label="자동화 실행 이력 표"
              >
                <Table verticalSpacing="md" horizontalSpacing="lg">
                  <Table.Thead>
                    <Table.Tr>
                      {[
                        "실행 시각",
                        "종류",
                        "실행 상태",
                        "서비스 ID",
                        "참조",
                        "결과",
                      ].map((label) => (
                        <Table.Th key={label}>{label}</Table.Th>
                      ))}
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {data.data.items.map((row) => (
                      <Table.Tr key={row.id}>
                        <Table.Td>{dateText(row.created_at)}</Table.Td>
                        <Table.Td>
                          {row.kind === "change"
                            ? "변경 기반 진단"
                            : "ITSM 동기화"}
                        </Table.Td>
                        <Table.Td>
                          <AutomationStatus status={row.status} />
                        </Table.Td>
                        <Table.Td>{row.service_id}</Table.Td>
                        <Table.Td>{row.reference || "—"}</Table.Td>
                        <Table.Td>
                          <Button
                            variant="default"
                            size="compact-sm"
                            onClick={() => setDetail(row)}
                          >
                            결과 보기
                          </Button>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </div>
            ) : (
              <Empty
                title="자동화 실행 이력이 없습니다"
                description="활성 규칙에 해당하는 변경이나 동기화가 처리되면 결정 근거를 확인할 수 있습니다."
              />
            )}
            <Group justify="space-between" className="automation-footer">
              <Text size="sm">전체 {total}건</Text>
              <Group>
                <Select
                  aria-label="자동화 이력 표시 수"
                  w={110}
                  data={["10", "25", "50", "100"].map((value) => ({
                    value,
                    label: value + "개씩",
                  }))}
                  value={query.get("size")}
                  onChange={(value) => update("size", value || "25")}
                />
                <Pagination
                  value={Math.min(data.data?.page || 1, pages)}
                  total={pages}
                  onChange={(value) => update("page", String(value))}
                />
              </Group>
            </Group>
          </>
        )}
      </Paper>
      <Modal
        opened={!!detail}
        onClose={() => setDetail(null)}
        title="자동화 실행 결과"
        size="lg"
      >
        {detail && <WorkflowRunResult run={detail} />}
      </Modal>
    </Stack>
  );
}
function WorkflowRunResult({ run }: { run: WorkflowRun }) {
  const result = run.result || {};
  return (
    <Stack gap="md">
      <Group justify="space-between">
        <AutomationStatus status={run.status} />
        <Text c="dimmed" size="sm">
          {dateText(run.created_at)}
        </Text>
      </Group>
      {result.reason && <Text>{String(result.reason)}</Text>}
      {result.changes && (
        <AutomationValues
          items={Object.entries(result.changes).map(([key, value]) => ({
            label:
              (
                {
                  assignee: "외부 담당자",
                  due_date: "외부 조치 기한",
                  external_status: "외부 티켓 상태",
                } as Record<string, string>
              )[key] || key,
            value: String(value ?? "—"),
          }))}
        />
      )}{" "}
      {Array.isArray(result.conflicts) && result.conflicts.length > 0 && (
        <Alert color="orange">
          충돌 항목:{" "}
          {result.conflicts
            .map((key: string) =>
              key === "assignee"
                ? "담당자"
                : key === "due_date"
                  ? "조치 기한"
                  : key,
            )
            .join(" · ")}
        </Alert>
      )}
      {Array.isArray(result.decisions) &&
        result.decisions.map((decision: Row, index: number) => (
          <Paper key={index} withBorder p="md">
            <Text fw={600}>
              {decision.rule_name || decision.rule_id || "규칙 결정"}
            </Text>
            <Text size="sm">
              {decision.reason || decision.status || "결정 기록"}
            </Text>
          </Paper>
        ))}
      {result.retest_reason && (
        <Text>재검증: {String(result.retest_reason)}</Text>
      )}
      {Array.isArray(result.scan_ids) && result.scan_ids.length > 0 && (
        <Group>
          {result.scan_ids.map((id: string) => (
            <Button
              key={id}
              component={Link}
              to={"/scans?item=" + encodeURIComponent(id)}
              variant="light"
              size="compact-sm"
            >
              연결 진단 {id.slice(0, 8)}
            </Button>
          ))}
        </Group>
      )}
      <Text c="dimmed" size="sm">
        외부 완료 상태만으로 발견 건을 해결하지 않습니다.
      </Text>
    </Stack>
  );
}
