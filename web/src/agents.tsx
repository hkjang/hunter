import { useEffect, useMemo, useRef, useState } from "react";
import {
  Link,
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import {
  Accordion,
  ActionIcon,
  Alert,
  Badge,
  Button,
  Code,
  Divider,
  Group,
  Modal,
  Paper,
  Progress,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Tabs,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import {
  IconActivity,
  IconArrowDown,
  IconArrowLeft,
  IconArrowRight,
  IconArrowUpRight,
  IconBrain,
  IconCheck,
  IconClock,
  IconGitBranch,
  IconInfoCircle,
  IconListCheck,
  IconPlayerPlay,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconSettings,
  IconShieldCheck,
  IconSquare,
  IconTerminal2,
  IconTool,
} from "@tabler/icons-react";
import {
  api,
  dateText,
  type Row,
  showError,
  success,
  useCan,
  useData,
  useSession,
} from "./api";
import {
  Empty,
  LoadState,
  PageHeader,
  SectionTitle,
  Status,
} from "./components";
import {
  displayMetadata,
  isTerminalRun,
  type AgentEvent,
  type AgentTool,
} from "./agent-events";
import { useAgentRun, type AgentRun } from "./use-agent-run";
import { canStartAgents } from "./agent-permissions";
import {
  ListPagination,
  ListReset,
  ListSearch,
  SortHeader,
  useListView,
} from "./use-list-view";

const runLabels: Record<string, string> = {
  queued: "대기 중",
  running: "진행 중",
  waiting_approval: "검토 대기",
  completed: "완료",
  failed: "실패",
  cancelled: "중지됨",
  inconclusive: "판단 불가",
  stopping: "중지 처리 중",
  created: "준비 중",
  waiting: "대기 중",
  finished: "완료",
};
const runColors: Record<string, string> = {
  queued: "gray",
  running: "blue",
  waiting_approval: "orange",
  completed: "teal",
  failed: "red",
  cancelled: "gray",
  inconclusive: "yellow",
  stopping: "orange",
  created: "gray",
  waiting: "orange",
  finished: "teal",
};
const toolNames: Record<string, string> = {
  service_context: "서비스 맥락 조회",
  list_findings: "발견 건 조회",
  request_scan: "진단 요청",
  scan_result: "진단 결과 조회",
  record_candidate: "발견 후보 기록",
  remember: "메모 저장",
  recall: "메모 조회",
};
const eventNames: Record<string, string> = {
  "run.updated": "실행 상태",
  "task.updated": "작업 변경",
  "subtask.updated": "하위 작업 변경",
  "message.delta": "에이전트 응답",
  "tool.started": "도구 실행 시작",
  "tool.completed": "도구 실행 결과",
  log: "실행 기록",
  usage: "사용량 집계",
};
const roleNames: Record<string, string> = {
  assistant: "에이전트",
  primary: "실행 관리자",
  primary_agent: "실행 관리자",
  generator: "계획 생성",
  refiner: "계획 구체화",
  adviser: "검토 조언",
  reflector: "결과 점검",
  searcher: "정보 검색",
  enricher: "맥락 보강",
  coder: "코드 분석",
  installer: "도구 준비",
  pentester: "보안 검증",
  system: "시스템",
  user: "사용자",
};
const safeText = (value: unknown) =>
  typeof value === "string"
    ? value
    : value == null
      ? ""
      : JSON.stringify(displayMetadata(value), null, 2);
export function AgentStatus({ status }: { status: string }) {
  return (
    <Badge
      variant="light"
      color={runColors[status] || "gray"}
      radius="sm"
      size="lg"
      className="agent-modal"
    >
      {runLabels[status] || status}
    </Badge>
  );
}
function EngineNotice() {
  const { config } = useSession();
  const can = useCan();
  if (config.agents_enabled && config.ai_enabled) return null;
  return (
    <Alert color="teal" title="에이전트 실행 설정을 확인하세요" mb="xl">
      {!config.agents_enabled
        ? "서비스 관리자가 에이전트 진단을 활성화하면 실행할 수 있습니다."
        : "기존 AI 설정에서 모델 연결을 활성화해야 실행할 수 있습니다."}
      {can("admin:manage") && (
        <Button
          variant="light"
          component={Link}
          to="/admin/settings?tab=agents"
          size="sm"
          mt="sm"
          leftSection={<IconSettings size={16} />}
        >
          에이전트 설정 열기
        </Button>
      )}
    </Alert>
  );
}
function CreateRunModal({
  opened,
  onClose,
  initial,
}: {
  opened: boolean;
  onClose: () => void;
  initial?: AgentRun | null;
}) {
  const can = useCan(),
    { config } = useSession(),
    navigate = useNavigate();
  const services = useData<Row[]>(
      opened && can("services:read") ? "/api/services" : null,
    ),
    scopes = useData<Row[]>(
      opened && can("services:read") ? "/api/scopes" : null,
    );
  const [serviceId, setServiceId] = useState<string | null>(null),
    [scopeId, setScopeId] = useState<string | null>(null),
    [prompt, setPrompt] = useState(""),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    if (opened) {
      setServiceId(initial?.service_id || null);
      setScopeId(null);
      setPrompt(initial?.prompt || "");
    }
  }, [opened, initial]);
  const approvedScopes = (scopes.data || []).filter(
    (s) =>
      s.service_id === serviceId &&
      s.approved &&
      new Date(s.expires_at).getTime() > Date.now(),
  );
  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!serviceId || !prompt.trim()) return;
    setBusy(true);
    try {
      const result = await api<AgentRun>("/api/agent-runs", {
        method: "POST",
        body: JSON.stringify({
          service_id: serviceId,
          scope_id: scopeId || undefined,
          prompt: prompt.trim(),
        }),
      });
      success("새 에이전트 실행을 등록했습니다");
      onClose();
      navigate(`/agents/${encodeURIComponent(result.id)}`);
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={initial ? "같은 목표로 새 실행" : "새 에이전트 진단"}
      size="lg"
    >
      <form onSubmit={create}>
        <Stack gap="lg">
          {initial && (
            <Alert color="teal">
              이전 실행의 서비스와 목표를 복사하여 새 실행을 생성합니다. 진단
              허용 범위와 현재 정책은 다시 확인합니다.
            </Alert>
          )}
          {can("services:read") ? (
            <Select
              label="대상 서비스"
              required
              searchable
              placeholder={
                services.loading ? "서비스를 불러오는 중" : "서비스 선택"
              }
              value={serviceId}
              data={(services.data || []).map((s) => ({
                value: s.id,
                label: `${s.name}${s.approved ? "" : " · 진단 미승인"}`,
              }))}
              onChange={(v) => {
                setServiceId(v);
                setScopeId(null);
              }}
              nothingFoundMessage="접근 가능한 서비스가 없습니다"
            />
          ) : (
            <TextInput
              label="대상 서비스 ID"
              required
              value={serviceId || ""}
              onChange={(e) => setServiceId(e.target.value)}
              description="접근 권한이 있는 서비스의 식별자를 입력하세요."
            />
          )}
          {services.error && <Alert color="red">{services.error}</Alert>}
          <Select
            label="진단 허용 범위"
            description="선택하지 않으면 서버가 유효한 승인 범위를 확인합니다. 실제 통신 진단은 허용된 범위에서만 실행됩니다."
            placeholder="유효한 범위 자동 선택"
            clearable
            searchable
            data={approvedScopes.map((s) => ({ value: s.id, label: s.name }))}
            value={scopeId}
            onChange={setScopeId}
            disabled={!serviceId}
          />
          <Textarea
            label="진단 목표"
            required
            placeholder="서비스의 기존 발견 건을 검토하고, 허용된 진단 결과를 근거로 추가 확인이 필요한 항목을 정리해 주세요."
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            autosize
            minRows={5}
            maxRows={12}
          />
          <div className="agent-form-note">
            <IconShieldCheck size={20} />
            <Text size="sm">
              에이전트는 관리자가 허용한 도구와 한도 안에서 작업합니다. 실행이
              완료되어도 취약점이 자동으로 해결 처리되지는 않습니다.
            </Text>
          </div>
          {config.approval_enabled && (
            <Alert color="orange">
              현재 팀장 검토 절차가 활성화되어 있습니다. 승인이 필요한 실제 진단
              요청은 기존 검토 절차를 따릅니다.
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              취소
            </Button>
            <Button
              type="submit"
              loading={busy}
              disabled={
                !serviceId ||
                !prompt.trim() ||
                !config.agents_enabled ||
                !config.ai_enabled ||
                !canStartAgents(can)
              }
              leftSection={<IconPlayerPlay size={17} />}
            >
              새 실행 시작
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
export function AgentsPage() {
  const { data, loading, error, reload } =
    useData<AgentRun[]>("/api/agent-runs");
  const { config } = useSession();
  const can = useCan(),
    navigate = useNavigate();
  const location = useLocation();
  const listLocation = location.pathname + location.search;
  const [opened, setOpened] = useState(false);
  const view = useListView<AgentRun>({
    rows: data || [],
    columns: [
      {
        key: "title",
        label: "실행 목표",
        value: (run) => run.title || "에이전트 진단",
      },
      {
        key: "service",
        label: "서비스",
        value: (run) => run.service_name || run.service_id,
      },
      {
        key: "status",
        label: "상태",
        value: (run) => runLabels[run.status] || run.status,
      },
      {
        key: "model_calls",
        label: "모델 호출",
        value: (run) => Number(run.model_calls || 0),
      },
      {
        key: "tool_calls",
        label: "Hunter 도구 호출",
        value: (run) => Number(run.tool_calls || 0),
      },
      {
        key: "created_at",
        label: "시작 일시",
        value: (run) => (run.created_at ? Date.parse(run.created_at) : null),
      },
    ],
    searchValues: (run) => [
      run.id,
      run.status,
      run.created_at,
      dateText(run.created_at),
    ],
    defaultSort: { key: "created_at", direction: "desc" },
    filters: {
      status: (run, value) => run.status === value,
      service: (run, value) => run.service_id === value,
    },
  });
  const serviceOptions = [
    ...new Map(
      (data || []).map((run) => [
        run.service_id,
        {
          value: run.service_id,
          label: String(run.service_name || run.service_id),
        },
      ]),
    ).values(),
  ].sort((a, b) => a.label.localeCompare(b.label, "ko"));
  const allowed = canStartAgents(can);
  return (
    <div className="agent-workspace">
      <PageHeader
        eyebrow="AGENT SECURITY VALIDATION"
        title="에이전트 진단"
        description="PentAGI 코어가 작업을 나누고, 허용된 도구의 실행 근거를 남기며 보안 검증을 진행합니다."
        action={
          <Group gap="sm">
            <Button
              variant="default"
              leftSection={<IconRefresh size={17} />}
              onClick={reload}
            >
              새로고침
            </Button>
            {allowed && (
              <Button
                leftSection={<IconPlus size={18} />}
                disabled={!config.agents_enabled || !config.ai_enabled}
                onClick={() => setOpened(true)}
              >
                새 에이전트 진단
              </Button>
            )}
          </Group>
        }
      />
      <EngineNotice />
      <div className="agent-intro">
        <span className="agent-intro-icon">
          <IconBrain size={29} stroke={1.5} />
        </span>
        <div>
          <h2>목표에서 작업으로, 실행에서 근거로</h2>
          <p>
            계획·작업·도구 호출·응답을 하나의 실행 이력에서 확인하세요. 화면을
            닫아도 서버의 실행은 계속됩니다.
          </p>
        </div>
        <Badge color="teal" variant="light">
          PentAGI 코어
        </Badge>
      </div>
      <Paper className="data-panel">
        <div className="table-toolbar">
          <Group gap="xs">
            <h2>에이전트 실행 목록</h2>
            <Badge variant="light" color="gray">
              {data?.length || 0}
            </Badge>
          </Group>
          <Group className="table-controls" gap="sm">
            <ListSearch
              view={view}
              label="에이전트 실행 검색"
              placeholder="목표 · 서비스 · 상태 검색"
            />
            <Select
              aria-label="에이전트 상태 필터"
              placeholder="모든 상태"
              data={[
                "queued",
                "running",
                "waiting_approval",
                "completed",
                "failed",
                "cancelled",
                "inconclusive",
                "stopping",
              ]
                .filter(
                  (s) =>
                    s !== "waiting_approval" ||
                    config.approval_enabled ||
                    (data || []).some((r) => r.status === s),
                )
                .map((value) => ({ value, label: runLabels[value] }))}
              value={view.filters.status || null}
              onChange={(value) => view.setFilter("status", value || "")}
              clearable
              w={150}
              size="sm"
            />
            <Select
              aria-label="에이전트 서비스 필터"
              placeholder="모든 서비스"
              data={serviceOptions}
              value={view.filters.service || null}
              onChange={(value) => view.setFilter("service", value || "")}
              clearable
              searchable
              w={180}
              size="sm"
            />
            <ListReset view={view} />
          </Group>
        </div>
        <LoadState loading={loading} error={error} reload={reload} />
        {!loading &&
          !error &&
          (view.rows.length ? (
            <Table.ScrollContainer minWidth={1060}>
              <Table
                verticalSpacing="lg"
                horizontalSpacing="lg"
                highlightOnHover
              >
                <Table.Thead>
                  <Table.Tr>
                    <SortHeader view={view} column="title">
                      실행 목표
                    </SortHeader>
                    <SortHeader view={view} column="service">
                      서비스
                    </SortHeader>
                    <SortHeader view={view} column="status">
                      상태
                    </SortHeader>
                    <SortHeader view={view} column="model_calls">
                      모델 호출
                    </SortHeader>
                    <SortHeader view={view} column="tool_calls">
                      Hunter 도구 호출
                    </SortHeader>
                    <SortHeader view={view} column="created_at">
                      시작 일시
                    </SortHeader>
                    <Table.Th>
                      <span className="sr-only">실행 상세</span>
                    </Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {view.rows.map((run) => (
                    <Table.Tr key={run.id}>
                      <Table.Td>
                        <Link
                          className="agent-run-link"
                          to={`/agents/${encodeURIComponent(run.id)}`}
                          state={{ from: listLocation }}
                        >
                          <span className="table-object-icon">
                            <IconBrain size={19} />
                          </span>
                          <div>
                            <strong>{run.title || "에이전트 진단"}</strong>
                          </div>
                        </Link>
                      </Table.Td>
                      <Table.Td>{run.service_name || run.service_id}</Table.Td>
                      <Table.Td>
                        <AgentStatus status={run.status} />
                      </Table.Td>
                      <Table.Td>
                        {Number(run.model_calls || 0).toLocaleString()}회
                      </Table.Td>
                      <Table.Td>
                        {Number(run.tool_calls || 0).toLocaleString()}회
                      </Table.Td>
                      <Table.Td className="table-date">
                        {dateText(run.created_at)}
                      </Table.Td>
                      <Table.Td>
                        <ActionIcon
                          aria-label={`${run.title || "실행"} 상세 보기`}
                          variant="subtle"
                          onClick={() =>
                            navigate(`/agents/${encodeURIComponent(run.id)}`, {
                              state: { from: listLocation },
                            })
                          }
                        >
                          <IconArrowUpRight size={20} />
                        </ActionIcon>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          ) : (
            <Empty
              title={
                view.query || view.filters.status || view.filters.service
                  ? "일치하는 실행이 없습니다"
                  : "아직 에이전트 실행이 없습니다"
              }
              description={
                view.query || view.filters.status || view.filters.service
                  ? "검색어나 서비스·상태 필터를 변경하세요."
                  : "서비스와 진단 목표를 선택하면 작업 계획, 실행 도구와 결과가 이곳에 기록됩니다."
              }
              icon={<IconBrain size={30} />}
              action={
                !data?.length &&
                allowed &&
                config.agents_enabled &&
                config.ai_enabled ? (
                  <Button variant="light" onClick={() => setOpened(true)}>
                    첫 에이전트 진단 시작
                  </Button>
                ) : undefined
              }
            />
          ))}
        {!loading && !error && (
          <ListPagination view={view} totalLabel="건" limit={1000} />
        )}
      </Paper>
      <div className="agent-footer-note">
        <IconInfoCircle size={17} />
        <span>
          조회에는 에이전트·서비스·발견 건·진단 조회 권한이 모두 필요합니다.
          실행에는 에이전트 실행과 AI 사용 권한이 추가로 필요하며, 개인 API 키와
          역할에서 관리합니다.
        </span>
      </div>
      <CreateRunModal opened={opened} onClose={() => setOpened(false)} />
    </div>
  );
}
function TaskList({
  tasks,
  onSelect,
  selected,
}: {
  tasks: Row[];
  onSelect: (id: string) => void;
  selected: string | null;
}) {
  if (!tasks.length)
    return (
      <Empty
        title="작업 계획을 기다리고 있습니다"
        description="에이전트가 작업을 생성하면 하위 작업과 진행 결과를 표시합니다."
        icon={<IconListCheck size={26} />}
      />
    );
  return (
    <Accordion
      variant="separated"
      multiple
      defaultValue={tasks.map((t) => String(t.id))}
      className="agent-task-list"
    >
      {tasks.map((task) => (
        <Accordion.Item key={task.id} value={String(task.id)}>
          <Accordion.Control>
            <Group justify="space-between" wrap="nowrap" gap="sm">
              <span className="agent-task-title">{task.title || "작업"}</span>
              <AgentStatus status={task.status} />
            </Group>
          </Accordion.Control>
          <Accordion.Panel>
            {task.result && (
              <div className="agent-text agent-task-result">
                {safeText(task.result)}
              </div>
            )}
            <button
              className={`agent-task-filter ${selected === String(task.id) ? "selected" : ""}`}
              onClick={() => onSelect(String(task.id))}
            >
              <IconSearch size={15} />
              {selected === String(task.id)
                ? "이 작업으로 기록 필터 적용 중"
                : "이 작업의 기록 보기"}
            </button>
            {(task.subtasks || []).map((sub: Row) => (
              <div className="agent-subtask" key={sub.id}>
                <span
                  className={`agent-subtask-dot ${["completed", "finished"].includes(sub.status) ? "complete" : ""}`}
                />
                <div>
                  <Group gap="sm" justify="space-between">
                    <Text fw={500}>{sub.title || "하위 작업"}</Text>
                    <AgentStatus status={sub.status} />
                  </Group>
                  {sub.result && (
                    <div className="agent-text">{safeText(sub.result)}</div>
                  )}
                </div>
              </div>
            ))}
          </Accordion.Panel>
        </Accordion.Item>
      ))}
    </Accordion>
  );
}
function ToolCard({ tool }: { tool: AgentTool }) {
  return (
    <Paper withBorder radius="md" p="lg" className="agent-tool-card">
      <Group justify="space-between" align="flex-start">
        <div>
          <Group gap="sm">
            <IconTool size={19} />
            <Text fw={600}>{toolNames[tool.name] || tool.name}</Text>
          </Group>
          <Text size="xs" c="dimmed" mt={5}>
            {tool.name} · {tool.id}
          </Text>
        </div>
        <AgentStatus status={tool.status} />
      </Group>
      <Group mt="md" gap="lg">
        <Text size="sm" c="dimmed">
          시작 {dateText(tool.started_at)}
        </Text>
        {tool.finished_at && (
          <Text size="sm" c="dimmed">
            종료 {dateText(tool.finished_at)}
          </Text>
        )}
      </Group>
      <Accordion variant="default" mt="sm">
        <Accordion.Item value="metadata">
          <Accordion.Control>실제 호출 정보와 결과</Accordion.Control>
          <Accordion.Panel>
            {tool.started && (
              <div className="agent-workspace">
                <Text size="sm" fw={500} mb="xs">
                  요청
                </Text>
                {tool.started.message && (
                  <div className="agent-text">{tool.started.message}</div>
                )}
                <Code block>
                  {JSON.stringify(
                    displayMetadata(tool.started.data || {}),
                    null,
                    2,
                  )}
                </Code>
              </div>
            )}
            {tool.completed && (
              <div className="agent-workspace">
                <Text size="sm" fw={500} mt="lg" mb="xs">
                  결과
                </Text>
                {tool.completed.message && (
                  <div className="agent-text">{tool.completed.message}</div>
                )}
                <Code block>
                  {JSON.stringify(
                    displayMetadata(tool.completed.data || {}),
                    null,
                    2,
                  )}
                </Code>
              </div>
            )}
          </Accordion.Panel>
        </Accordion.Item>
      </Accordion>
    </Paper>
  );
}
export function AgentRunPage() {
  const { id = "" } = useParams();
  const location = useLocation();
  const from =
    typeof location.state?.from === "string" &&
    /^\/agents(?:\?|$)/.test(location.state.from)
      ? location.state.from
      : "/agents";
  const { run, loading, error, reload, connection, streamError, activity } =
    useAgentRun(id);
  const can = useCan(),
    { config } = useSession();
  const [params, setParams] = useSearchParams();
  const [stopOpen, setStopOpen] = useState(false),
    [retryOpen, setRetryOpen] = useState(false),
    [busy, setBusy] = useState(false),
    [search, setSearch] = useState("");
  const [endFollow, setEndFollow] = useState(true);
  const logEnd = useRef<HTMLDivElement | null>(null);
  const tab = ["overview", "messages", "tools", "logs", "scans"].includes(
    params.get("tab") || "",
  )
    ? params.get("tab")!
    : "overview";
  const selectedTask = params.get("task");
  function setTab(value: string | null) {
    const next = new URLSearchParams(params);
    next.set("tab", value || "overview");
    setParams(next, { replace: true, state: location.state });
  }
  function chooseTask(value: string | null) {
    const next = new URLSearchParams(params);
    if (value) next.set("task", value);
    else next.delete("task");
    next.set("tab", "logs");
    setParams(next, { replace: true, state: location.state });
  }
  const visibleEvents = useMemo(
    () =>
      activity.events.filter(
        (e) =>
          (!selectedTask || String(e.data?.task_id || "") === selectedTask) &&
          (!search ||
            `${e.type} ${e.role || ""} ${e.message || ""} ${e.tool_name || ""} ${safeText(e.data)}`
              .toLowerCase()
              .includes(search.toLowerCase())),
      ),
    [activity.events, selectedTask, search],
  );
  const taskCount = run?.tasks?.length || 0,
    completedTasks =
      run?.tasks?.filter((t) => ["completed", "finished"].includes(t.status))
        .length || 0;
  useEffect(() => {
    if (endFollow && tab === "logs")
      logEnd.current?.scrollIntoView({ block: "nearest" });
  }, [activity.received, endFollow, tab]);
  async function stop() {
    setBusy(true);
    try {
      await api(`/api/agent-runs/${encodeURIComponent(id)}/stop`, {
        method: "POST",
      });
      success("중지 요청을 접수했습니다. 실제 중단 상태를 확인하고 있습니다.");
      setStopOpen(false);
      await reload();
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  if (loading) return <LoadState loading error="" />;
  if (!run)
    return (
      <div className="agent-workspace">
        <PageHeader
          title="에이전트 실행"
          description="실행 상세 정보를 확인합니다."
          action={
            <Button
              component={Link}
              to={from}
              variant="default"
              leftSection={<IconArrowLeft size={17} />}
            >
              목록으로
            </Button>
          }
        />
        <LoadState
          loading={false}
          error={error || "실행 정보를 찾을 수 없습니다."}
          reload={reload}
        />
      </div>
    );
  const mayStart =
    canStartAgents(can) && !!config.agents_enabled && !!config.ai_enabled;
  const connectionLabel = {
    connecting: "이벤트 연결 중",
    live: "실시간 연결",
    reconnecting: "재연결 중",
    closed: "기록 동기화 완료",
    error: "연결 확인 필요",
  }[connection];
  return (
    <div className="agent-workspace">
      <div className="agent-back-link">
        <Link to={from}>
          <IconArrowLeft size={16} />
          에이전트 진단 목록
        </Link>
      </div>
      <PageHeader
        eyebrow="AGENT RUN WORKSPACE"
        title={run.title || "에이전트 진단"}
        description={`${run.service_name || run.service_id} · ${dateText(run.created_at)} 생성`}
        action={
          <Group gap="sm">
            <Button
              variant="default"
              onClick={reload}
              leftSection={<IconRefresh size={17} />}
            >
              새로고침
            </Button>
            {can("agents:write") && run.allowed_actions?.includes("stop") && (
              <Button
                color="orange"
                variant="light"
                leftSection={<IconSquare size={16} />}
                disabled={
                  busy || !!run.cancel_requested || run.status === "stopping"
                }
                onClick={() => setStopOpen(true)}
              >
                실행 중지
              </Button>
            )}
            {mayStart && run.allowed_actions?.includes("retry") && (
              <Button
                leftSection={<IconPlus size={17} />}
                onClick={() => setRetryOpen(true)}
              >
                같은 목표로 새 실행
              </Button>
            )}
          </Group>
        }
      />
      <div className="agent-run-statusbar">
        <Group gap="md">
          <AgentStatus status={run.status} />
          <span
            className={`agent-connection ${connection === "live" ? "connected" : ""}`}
          >
            <i />
            {connectionLabel}
          </span>
        </Group>
        <Text size="sm" c="dimmed">
          실행 ID {run.id}
        </Text>
      </div>
      {error && (
        <Alert color="red" mb="lg" title="상태 조회 안내">
          {error}
        </Alert>
      )}
      {streamError && (
        <Alert
          color={connection === "error" ? "red" : "yellow"}
          mb="lg"
          title={
            connection === "error"
              ? "이벤트 연결을 확인해 주세요"
              : "실행 기록을 다시 동기화하고 있습니다"
          }
        >
          {streamError}
          {connection === "error" && (
            <Text size="sm" mt="xs">
              페이지를 새로고침하면 저장된 기록부터 다시 조회합니다.
            </Text>
          )}
        </Alert>
      )}
      {run.error && (
        <Alert color="orange" mb="lg" title="실행 결과 안내">
          {safeText(run.error)}
        </Alert>
      )}
      {run.status === "waiting_approval" && config.approval_enabled && (
        <Alert
          color="orange"
          mb="lg"
          title="진단 요청의 검토를 기다리고 있습니다"
        >
          에이전트가 요청한 실제 진단에 팀장 검토가 필요합니다.
          {can("scans:approve") && (
            <Button
              component={Link}
              to="/approvals"
              variant="light"
              color="orange"
              mt="sm"
            >
              검토 · 승인 열기
            </Button>
          )}
        </Alert>
      )}
      {run.cancel_requested && !isTerminalRun(run.status) && (
        <Alert color="orange" mb="lg" title="중지 요청 처리 중">
          실행 중인 작업이 중단되면 서버의 최종 상태가 표시됩니다.
        </Alert>
      )}
      <SimpleGrid
        cols={{ base: 1, xs: 2, lg: 4 }}
        spacing="md"
        mb="xl"
        className="agent-metrics"
      >
        {[
          {
            label: "작업 진행",
            value: `${completedTasks} / ${taskCount}`,
            icon: IconListCheck,
          },
          {
            label: "모델 호출",
            value: `${Number(run.model_calls || 0).toLocaleString()}회`,
            icon: IconBrain,
          },
          {
            label: "Hunter 도구 호출",
            value: `${Number(run.tool_calls || 0).toLocaleString()}회`,
            icon: IconTool,
          },
          {
            label: "사용 토큰 · 입력 / 출력",
            value: `${Number(run.input_tokens || 0).toLocaleString()} / ${Number(run.output_tokens || 0).toLocaleString()}`,
            icon: IconActivity,
          },
        ].map((m) => (
          <Paper className="agent-metric" key={m.label}>
            <Group justify="space-between" gap="sm">
              <Text size="sm" c="dimmed">
                {m.label}
              </Text>
              <m.icon size={19} />
            </Group>
            <strong>{m.value}</strong>
          </Paper>
        ))}
      </SimpleGrid>
      <div className="agent-detail-layout">
        <aside className="agent-task-pane">
          <Paper className="content-card">
            <SectionTitle
              title="작업과 하위 작업"
              description="실제로 생성된 계획과 진행 상태"
            />
            {taskCount > 0 && (
              <Progress
                value={(completedTasks / taskCount) * 100}
                color="teal"
                size="sm"
                mb="lg"
                aria-label={`작업 ${taskCount}개 중 ${completedTasks}개 완료`}
              />
            )}
            <TaskList
              tasks={run.tasks || []}
              selected={selectedTask}
              onSelect={chooseTask}
            />
          </Paper>
        </aside>
        <Paper className="agent-detail-main">
          <Tabs value={tab} onChange={setTab}>
            <Tabs.List className="agent-detail-tabs">
              <Tabs.Tab
                value="overview"
                leftSection={<IconListCheck size={16} />}
              >
                목표와 결과
              </Tabs.Tab>
              <Tabs.Tab value="messages" leftSection={<IconBrain size={16} />}>
                에이전트 응답
              </Tabs.Tab>
              <Tabs.Tab value="tools" leftSection={<IconTool size={16} />}>
                도구 호출
              </Tabs.Tab>
              <Tabs.Tab value="logs" leftSection={<IconTerminal2 size={16} />}>
                실행 기록
              </Tabs.Tab>
              <Tabs.Tab value="scans" leftSection={<IconGitBranch size={16} />}>
                연결된 진단
              </Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="overview" className="agent-tab-panel">
              <h2>진단 목표</h2>
              <div className="agent-text agent-goal">
                {safeText(run.prompt) || "등록된 목표를 불러오지 못했습니다."}
              </div>
              <Divider my="xl" />
              <h2>실행 결과</h2>
              {run.result ? (
                <div className="agent-text agent-result">
                  {safeText(run.result)}
                </div>
              ) : (
                <Empty
                  title={
                    isTerminalRun(run.status)
                      ? "기록된 최종 결과가 없습니다"
                      : "실행 결과를 기다리고 있습니다"
                  }
                  description={
                    isTerminalRun(run.status)
                      ? "실행 상태, 개별 작업과 도구 호출 기록에서 진행 내용을 확인하세요."
                      : "작업이 진행되면 에이전트 응답과 실제 도구 결과를 다른 탭에서 바로 확인할 수 있습니다."
                  }
                />
              )}
              <Alert mt="xl" color="teal" icon={<IconShieldCheck size={20} />}>
                에이전트 실행 완료와 발견 건 해결은 구분됩니다. 기록한 후보와
                실제 진단 결과를 검토하고 기존 재검증 절차로 조치를 확인하세요.
              </Alert>
              {run.limits && (
                <Accordion mt="xl">
                  <Accordion.Item value="limits">
                    <Accordion.Control>적용된 실행 한도</Accordion.Control>
                    <Accordion.Panel>
                      <Code block>
                        {JSON.stringify(displayMetadata(run.limits), null, 2)}
                      </Code>
                    </Accordion.Panel>
                  </Accordion.Item>
                </Accordion>
              )}
            </Tabs.Panel>
            <Tabs.Panel value="messages" className="agent-tab-panel">
              {activity.messages.length ? (
                <Stack gap="xl">
                  {activity.messages.map((m) => (
                    <article className="agent-message" key={m.id}>
                      <div className="agent-message-avatar">
                        <IconBrain size={19} />
                      </div>
                      <div>
                        <Group gap="sm">
                          <Text fw={600}>{roleNames[m.role] || m.role}</Text>
                          <Text size="xs" c="dimmed">
                            {dateText(m.created_at)}
                          </Text>
                        </Group>
                        <div className="agent-text">{m.content}</div>
                      </div>
                    </article>
                  ))}
                </Stack>
              ) : (
                <Empty
                  title="아직 에이전트 응답이 없습니다"
                  description="모델이 생성하는 응답을 스트리밍으로 표시합니다."
                  icon={<IconBrain size={28} />}
                />
              )}
            </Tabs.Panel>
            <Tabs.Panel value="tools" className="agent-tab-panel">
              {activity.tools.length ? (
                <Stack>
                  {activity.tools.map((tool) => (
                    <ToolCard key={tool.id} tool={tool} />
                  ))}
                </Stack>
              ) : (
                <Empty
                  title="호출된 도구가 없습니다"
                  description="에이전트가 실제로 요청한 도구의 이름, 인자와 결과를 표시합니다."
                  icon={<IconTool size={28} />}
                />
              )}
            </Tabs.Panel>
            <Tabs.Panel value="logs" className="agent-tab-panel">
              <div className="agent-log-toolbar">
                <TextInput
                  aria-label="실행 기록 검색"
                  placeholder="역할 · 도구 · 메시지 검색"
                  leftSection={<IconSearch size={16} />}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  size="sm"
                />
                <Select
                  aria-label="작업별 실행 기록"
                  placeholder="모든 작업"
                  data={(run.tasks || []).map((t) => ({
                    value: String(t.id),
                    label: t.title || String(t.id),
                  }))}
                  value={selectedTask}
                  onChange={chooseTask}
                  clearable
                  searchable
                  size="sm"
                />
                <Button
                  variant={endFollow ? "light" : "default"}
                  size="sm"
                  onClick={() => setEndFollow(!endFollow)}
                  leftSection={<IconArrowDown size={16} />}
                  aria-pressed={endFollow}
                >
                  {endFollow ? "최신 기록 따라가기" : "자동 이동 꺼짐"}
                </Button>
              </div>
              <Text size="xs" c="dimmed" mb="md">
                수신한 이벤트 {activity.received.toLocaleString()}개
                {activity.trimmed
                  ? " · 화면에는 최근 1,500개 기록과 150개 응답을 표시합니다."
                  : ""}
              </Text>
              <div
                className="agent-log-stream"
                onWheel={() => setEndFollow(false)}
              >
                {visibleEvents.length ? (
                  visibleEvents.map((event) => (
                    <div
                      className={`agent-log-item ${event.type === "message.delta" ? "delta" : ""}`}
                      key={String(event.id)}
                    >
                      <Group gap="xs" justify="space-between">
                        <Group gap="xs">
                          <Badge
                            color={
                              event.type.startsWith("tool.") ? "teal" : "gray"
                            }
                            variant="light"
                          >
                            {eventNames[event.type] || event.type}
                          </Badge>
                          {event.role && (
                            <Text size="xs" c="dimmed">
                              {roleNames[event.role] || event.role}
                            </Text>
                          )}
                          {event.tool_name && (
                            <Text size="xs" fw={500}>
                              {toolNames[event.tool_name] || event.tool_name}
                            </Text>
                          )}
                        </Group>
                        <Text size="xs" c="dimmed">
                          {dateText(event.created_at)}
                        </Text>
                      </Group>
                      {event.message && (
                        <div className="agent-text">{event.message}</div>
                      )}
                      {event.status && (
                        <Text size="sm" mt="xs">
                          상태: {runLabels[event.status] || event.status}
                        </Text>
                      )}
                      {event.data && Object.keys(event.data).length > 0 && (
                        <details className="agent-event-data">
                          <summary>이벤트 상세</summary>
                          <Code block>
                            {JSON.stringify(
                              displayMetadata(event.data),
                              null,
                              2,
                            )}
                          </Code>
                        </details>
                      )}
                    </div>
                  ))
                ) : (
                  <Empty
                    title={
                      search || selectedTask
                        ? "조건에 맞는 기록이 없습니다"
                        : "실행 이벤트를 기다리고 있습니다"
                    }
                    description="조회 조건을 변경하거나 에이전트가 기록을 생성할 때까지 기다려 주세요."
                  />
                )}
                <div ref={logEnd} />
              </div>
            </Tabs.Panel>
            <Tabs.Panel value="scans" className="agent-tab-panel">
              <Text size="sm" c="dimmed" mb="lg">
                에이전트가 요청한 실제 진단입니다. 각 진단에 기존 허용 범위와
                실행 정책을 적용합니다.
              </Text>
              {run.scans?.length ? (
                <Stack>
                  {run.scans.map((scan) => (
                    <Paper key={scan.id} withBorder radius="md" p="lg">
                      <Group justify="space-between">
                        <div>
                          <Text fw={600}>
                            {scan.profile === "http-baseline"
                              ? "HTTP 보안 헤더 진단"
                              : scan.profile || "진단 실행"}
                          </Text>
                          <Text size="xs" c="dimmed" mt="xs">
                            {dateText(scan.created_at)}
                          </Text>
                        </div>
                        <Status value={scan.status} />
                      </Group>
                      {can("scans:read") && (
                        <Button
                          mt="md"
                          component={Link}
                          to={`/scans?scan=${encodeURIComponent(scan.id)}`}
                          variant="light"
                          size="sm"
                          rightSection={<IconArrowUpRight size={16} />}
                        >
                          실제 진단 상세
                        </Button>
                      )}
                    </Paper>
                  ))}
                </Stack>
              ) : (
                <Empty
                  title="연결된 진단이 없습니다"
                  description="진단 요청 도구가 허용되고 실제 진단을 생성하면 이곳에 표시됩니다."
                  icon={<IconGitBranch size={28} />}
                />
              )}
            </Tabs.Panel>
          </Tabs>
        </Paper>
      </div>
      <div className="agent-footer-note">
        <IconInfoCircle size={16} />
        <span>
          PentAGI 코어 · 출처 커밋{" "}
          {(
            run.upstream_commit ||
            config.agent_upstream_commit ||
            "정보 없음"
          ).slice(0, 12)}{" "}
          · 화면을 닫아도 서버의 실행은 계속됩니다.
        </span>
      </div>
      <Modal
        opened={stopOpen}
        onClose={() => setStopOpen(false)}
        title="에이전트 실행 중지"
      >
        <Text>
          현재 실행 중인 에이전트 작업의 중지를 요청합니다. 처리 결과는 실행
          상태에 반영됩니다.
        </Text>
        <Group justify="flex-end" mt="xl">
          <Button variant="default" onClick={() => setStopOpen(false)}>
            닫기
          </Button>
          <Button color="orange" loading={busy} onClick={stop}>
            중지 요청
          </Button>
        </Group>
      </Modal>
      <CreateRunModal
        opened={retryOpen}
        onClose={() => setRetryOpen(false)}
        initial={run}
      />
    </div>
  );
}
