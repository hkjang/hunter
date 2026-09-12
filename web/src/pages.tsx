import { ListTools, TableViewport } from "./list-tools";
import { canReadAgents } from "./agent-permissions";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
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
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import {
  IconActivity,
  IconArrowDown,
  IconArrowRight,
  IconArrowUpRight,
  IconChartDonut,
  IconCheck,
  IconChevronRight,
  IconCircleCheck,
  IconDownload,
  IconExclamationCircle,
  IconFileAnalytics,
  IconGitBranch,
  IconLayersIntersect,
  IconLink,
  IconMinus,
  IconPlayerPlay,
  IconPlus,
  IconRadar,
  IconRefresh,
  IconSearch,
  IconSend,
  IconShieldCheck,
  IconShieldExclamation,
  IconSparkles,
  IconSquare,
  IconTargetArrow,
  IconTrophy,
  IconUser,
} from "@tabler/icons-react";
import {
  api,
  colors,
  dateText,
  label,
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
  SmallLink,
  Stat,
  Status,
} from "./components";
import {
  useListView,
  ListSearch,
  SortHeader,
  ListPagination,
  ListReset,
} from "./use-list-view";
const severityColors: Record<string, string> = {
  critical: "#e45560",
  high: "#ed955a",
  medium: "#e9bd55",
  low: "#65a1ce",
  info: "#a1adb5",
};
export function Dashboard() {
  const { data, loading, error, reload } = useData<Row>("/api/dashboard");
  const { user } = useSession();
  const can = useCan();
  const navigate = useNavigate();
  const [stopOpen, setStopOpen] = useState(false),
    [reason, setReason] = useState(""),
    [busy, setBusy] = useState(false);
  const total = Object.values(data?.by_severity || {}).reduce(
    (a: number, b) => a + Number(b),
    0,
  );
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  let acc = 0;
  const segments = severityOrder.map((k) => {
    const start = acc;
    acc += Number(data?.by_severity?.[k] || 0);
    return `${severityColors[k]} ${total ? (start / total) * 100 : 0}% ${total ? (acc / total) * 100 : 0}%`;
  });
  const stopped = !!data?.emergency_stop;
  async function stop() {
    setBusy(true);
    try {
      await api("/api/emergency-stop", {
        method: "POST",
        body: JSON.stringify({ enabled: !stopped, reason }),
      });
      success(
        stopped
          ? "진단 실행을 다시 허용했습니다"
          : "대기 중인 진단과 실행 중인 진단을 중지했습니다",
      );
      setStopOpen(false);
      setReason("");
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
        eyebrow="SECURITY OVERVIEW"
        title="보안 현황"
        description="사내 서비스의 위험과 개선 흐름을 한눈에 확인하세요."
        action={
          <Group gap="sm">
            <Button
              variant="default"
              leftSection={<IconRefresh size={17} />}
              onClick={reload}
            >
              새로고침
            </Button>
            {can("scans:write") && (
              <Button
                leftSection={<IconPlayerPlay size={18} />}
                component={Link}
                to="/scans"
              >
                진단 실행
              </Button>
            )}
          </Group>
        }
      />
      <LoadState loading={loading} error={error} reload={reload} />
      {!loading && !error && data && (
        <>
          <div className="overview-banner">
            <div>
              <div className="banner-kicker">
                <span className="status-led" />
                {stopped
                  ? "진단 실행 중지됨"
                  : "지속적인 보안 검증 워크스페이스"}
              </div>
              <h2>
                {Number(data.critical) > 0 ? (
                  <>
                    우선 확인이 필요한{" "}
                    <span>심각한 위험 {data.critical}건</span>이 있습니다.
                  </>
                ) : Number(data.services) > 0 ? (
                  <>
                    발견한 위험을 <span>다음 개선으로</span> 연결하세요.
                  </>
                ) : (
                  <>
                    우리 서비스의 보안을, <span>한곳에서 시작하세요.</span>
                  </>
                )}
              </h2>
              <p>
                {Number(data.services) > 0
                  ? `${data.services}개 서비스의 발견 건과 진단 상태를 기준으로 집계한 현황입니다.`
                  : "서비스를 등록하고 진단 범위를 설정하면 실제 검증 결과가 이곳에 모입니다."}
              </p>
              <button
                className="banner-link"
                onClick={() =>
                  navigate(
                    Number(data.services) > 0 ? "/findings" : "/services",
                  )
                }
              >
                {Number(data.services) > 0
                  ? "발견 건 확인하기"
                  : "첫 서비스 등록하기"}
                <IconArrowRight size={17} />
              </button>
            </div>
            <div className="banner-graphic" aria-hidden="true">
              <div className="banner-orbit o1" />
              <div className="banner-orbit o2" />
              <div className="banner-shield">
                <IconShieldCheck size={57} stroke={1.25} />
              </div>
              <span className="orbit-dot od1" />
              <span className="orbit-dot od2" />
            </div>
          </div>
          <SimpleGrid
            cols={{ base: 1, xs: 2, xl: 4 }}
            spacing="lg"
            className="stats-grid"
          >
            <Stat
              label="등록 서비스"
              value={data.services ?? 0}
              unit="개"
              icon={<IconLayersIntersect size={22} />}
              detail="승인 여부와 관계없는 전체 등록 자산"
            />
            <Stat
              label="미해결 발견 건"
              value={data.open_findings ?? 0}
              unit="건"
              icon={<IconShieldExclamation size={22} />}
              detail="해결 · 오탐 · 위험 수용 제외"
            />
            <Stat
              label="심각한 위험"
              value={data.critical ?? 0}
              unit="건"
              icon={<IconExclamationCircle size={22} />}
              detail="우선 검토가 필요한 심각도"
              accent
            />
            <Stat
              label="서비스 진단 커버리지"
              value={Math.round(Number(data.coverage || 0))}
              unit="%"
              icon={<IconTargetArrow size={22} />}
              detail="완료된 진단 이력이 있는 서비스 비율"
            />
          </SimpleGrid>
          <div className="dashboard-middle">
            <Paper className="content-card risk-distribution">
              <SectionTitle
                title="위험 분포"
                description="기술적 심각도에 따른 발견 건 현황"
                action={
                  <SmallLink onClick={() => navigate("/findings")}>
                    발견 건 보기
                  </SmallLink>
                }
              />
              <div className="risk-chart-layout">
                <div className="donut-wrap">
                  <div
                    className="donut-chart"
                    style={{
                      background: total
                        ? `conic-gradient(${segments.join(",")})`
                        : "#e9edef",
                    }}
                  >
                    <div className="donut-hole">
                      <span>전체 발견 건</span>
                      <strong>{total}</strong>
                      <small>
                        {total
                          ? "근거를 확인하고 개선하세요"
                          : "진단 결과를 기다리고 있어요"}
                      </small>
                    </div>
                  </div>
                </div>
                <div className="severity-legend">
                  {severityOrder.map((s) => (
                    <div className="severity-row" key={s}>
                      <span
                        className="severity-dot"
                        style={{ background: severityColors[s] }}
                      />
                      <span>{label(s)}</span>
                      <div className="severity-track">
                        <div
                          style={{
                            width: `${total ? (Number(data.by_severity?.[s] || 0) / total) * 100 : 0}%`,
                            background: severityColors[s],
                          }}
                        />
                      </div>
                      <strong>
                        {data.by_severity?.[s] || 0}
                        <small>건</small>
                      </strong>
                    </div>
                  ))}
                </div>
              </div>
              <div className="risk-footnote">
                <IconChartDonut size={16} />
                <span>기술적 심각도와 실제 업무 영향도를 함께 검토하세요.</span>
              </div>
            </Paper>
            <Paper className="content-card execution-card">
              <SectionTitle
                title="진단 운영 현황"
                description="현재 워크스페이스 실행 상태"
              />
              <div className="execution-total">
                <div>
                  <span>누적 진단 실행</span>
                  <strong>
                    {data.scans ?? 0}
                    <small>회</small>
                  </strong>
                </div>
                <span className="execution-icon">
                  <IconRadar size={34} stroke={1.4} />
                </span>
              </div>
              <Divider my="lg" />
              <div className="execution-row">
                <span>
                  <i style={{ background: "#4e94cc" }} />
                  진행 중
                </span>
                <strong>
                  {data.running_scans ??
                    (data.recent_scans || []).filter(
                      (s: Row) => s.status === "running",
                    ).length}
                </strong>
              </div>
              <div className="execution-row">
                <span>
                  <i style={{ background: "#bec8cd" }} />
                  대기 중
                </span>
                <strong>
                  {data.queued_scans ??
                    (data.recent_scans || []).filter(
                      (s: Row) => s.status === "queued",
                    ).length}
                </strong>
              </div>
              <div className="security-debt">
                <div>
                  <span>보안 부채 지수</span>
                  <strong>
                    {Number(data.security_debt || 0).toLocaleString("ko-KR")}
                  </strong>
                </div>
                <Text size="xs" c="dimmed">
                  미해결 심각도 가중치 × 경과 기간 기반
                </Text>
              </div>
              <Button
                variant="light"
                fullWidth
                rightSection={<IconArrowRight size={16} />}
                onClick={() => navigate("/scans")}
              >
                진단 이력 확인
              </Button>
            </Paper>
          </div>
          <div className="dashboard-bottom">
            <Paper className="data-panel">
              <div className="table-toolbar">
                <h2>최근 발견 건</h2>
                <SmallLink onClick={() => navigate("/findings")}>
                  전체 보기
                </SmallLink>
              </div>
              {data.recent_findings?.length ? (
                <Table.ScrollContainer minWidth={560}>
                  <Table
                    verticalSpacing="md"
                    horizontalSpacing="lg"
                    highlightOnHover
                  >
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>발견 내용</Table.Th>
                        <Table.Th>심각도</Table.Th>
                        <Table.Th>상태</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {data.recent_findings.slice(0, 5).map((f: Row) => (
                        <Table.Tr
                          key={f.id}
                          onClick={() => navigate("/findings")}
                          style={{ cursor: "pointer" }}
                        >
                          <Table.Td>
                            <Text fw={500} size="sm" lineClamp={1}>
                              {f.title}
                            </Text>
                            <Text size="xs" c="dimmed" mt={4}>
                              {f.source} · {dateText(f.created_at)}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Status value={f.severity} />
                          </Table.Td>
                          <Table.Td>
                            <Status value={f.status} />
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              ) : (
                <Empty
                  title="아직 발견 건이 없습니다"
                  description="진단을 실행하거나 기존 엔진의 결과를 가져오면 발견 건을 확인할 수 있습니다."
                />
              )}
            </Paper>
            <Paper className="content-card">
              <SectionTitle
                title="최근 진단 활동"
                action={
                  <SmallLink onClick={() => navigate("/scans")}>
                    전체 보기
                  </SmallLink>
                }
              />
              {data.recent_scans?.length ? (
                <div className="activity-list">
                  {data.recent_scans.slice(0, 5).map((s: Row) => (
                    <div className="activity-item" key={s.id}>
                      <span
                        className={`activity-icon ${s.status === "failed" ? "activity-error" : ""}`}
                      >
                        {s.status === "completed" ? (
                          <IconCheck size={17} />
                        ) : (
                          <IconRadar size={17} />
                        )}
                      </span>
                      <div>
                        <strong>{label(s.profile)}</strong>
                        <small>{dateText(s.created_at)}</small>
                      </div>
                      <Status value={s.status} />
                    </div>
                  ))}
                </div>
              ) : (
                <Empty
                  title="진단을 시작할 준비가 됐습니다"
                  description="등록된 서비스의 허용 범위를 설정하고 첫 진단을 요청하세요."
                  icon={<IconRadar size={28} />}
                />
              )}
            </Paper>
          </div>
          {can("admin:manage") && (
            <div className={`safety-bar ${stopped ? "safety-stopped" : ""}`}>
              <div>
                <IconShieldCheck size={22} />
                <div>
                  <strong>
                    {stopped
                      ? "긴급 중지가 활성화되었습니다"
                      : "안전 정책이 모든 진단에 적용됩니다"}
                  </strong>
                  <span>
                    {stopped
                      ? "관리자가 재개할 때까지 새 진단 실행이 차단됩니다."
                      : "허용 범위 · 요청량 제한 · 실행 시간 제한 · 민감정보 보호"}
                  </span>
                </div>
              </div>
              <Button
                variant="subtle"
                color={stopped ? "teal" : "red"}
                size="sm"
                leftSection={
                  stopped ? (
                    <IconPlayerPlay size={16} />
                  ) : (
                    <IconSquare size={15} />
                  )
                }
                onClick={() => setStopOpen(true)}
              >
                {stopped ? "진단 실행 재개" : "긴급 중지"}
              </Button>
            </div>
          )}
        </>
      )}
      <Modal
        opened={stopOpen}
        onClose={() => setStopOpen(false)}
        title={stopped ? "진단 실행 재개" : "전체 진단 긴급 중지"}
      >
        <Text mb="lg">
          {stopped
            ? "진단 요청을 다시 허용합니다. 취소된 작업은 자동으로 재실행하지 않습니다."
            : "대기 중이거나 실행 중인 진단을 중지하고, 새로운 진단 실행을 차단합니다."}
        </Text>
        <Textarea
          label="작업 사유"
          placeholder="운영 장애 감지, 점검 완료 등"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required
        />
        <Group justify="flex-end" mt="xl">
          <Button variant="default" onClick={() => setStopOpen(false)}>
            취소
          </Button>
          <Button
            color={stopped ? "teal" : "red"}
            loading={busy}
            disabled={!reason.trim()}
            onClick={stop}
          >
            {stopped ? "재개" : "전체 진단 중지"}
          </Button>
        </Group>
      </Modal>
    </>
  );
}
export function GraphPage() {
  const { data, loading, error, reload } = useData<Row>("/api/graph");
  const [query, setQuery] = useState(""),
    [selected, setSelected] = useState<Row | null>(null),
    [zoom, setZoom] = useState(1);
  const types: Record<string, string> = {
    service: "서비스",
    finding: "발견 건",
    component: "구성요소",
    cve: "CVE",
    owner: "담당자",
    repository: "저장소",
    image: "이미지",
    database: "데이터베이스",
    api: "API",
    domain: "도메인",
    container: "컨테이너",
    llm: "LLM",
  };
  const graph = useMemo(() => {
    const nodes = (data?.nodes || [])
      .filter(
        (n: Row) =>
          !query || String(n.label).toLowerCase().includes(query.toLowerCase()),
      )
      .slice(0, 70);
    const services = nodes.filter((n: Row) => n.type === "service"),
      others = nodes.filter((n: Row) => n.type !== "service");
    const positions: Record<string, { x: number; y: number }> = {};
    services.forEach((n: Row, i: number) => {
      positions[n.id] = { x: 200, y: 80 + i * 125 };
    });
    others.forEach((n: Row, i: number) => {
      positions[n.id] = {
        x: 520 + (i % 2) * 280,
        y: 65 + Math.floor(i / 2) * 100,
      };
    });
    return {
      nodes,
      positions,
      height: Math.max(
        520,
        services.length * 125 + 100,
        Math.ceil(others.length / 2) * 100 + 100,
      ),
      edges: (data?.edges || []).filter(
        (e: Row) => positions[e.source] && positions[e.target],
      ),
    };
  }, [data, query]);
  return (
    <>
      <PageHeader
        eyebrow="ASSET RELATIONSHIPS"
        title="영향 관계도"
        description="서비스, 구성요소, 발견 건의 관계를 따라 실제 영향 범위를 탐색합니다."
        action={
          <Button
            variant="default"
            leftSection={<IconRefresh size={17} />}
            onClick={reload}
          >
            새로고침
          </Button>
        }
      />
      <LoadState loading={loading} error={error} reload={reload} />
      {!loading && !error && (
        <div className="graph-layout">
          <Paper className="data-panel graph-panel">
            <div className="table-toolbar">
              <TextInput
                aria-label="관계도 검색"
                placeholder="노드 이름 검색"
                value={query}
                size="sm"
                onChange={(e) => setQuery(e.target.value)}
                leftSection={<IconSearch size={17} />}
              />
              <Group gap="xs">
                <Badge color="teal" variant="light">
                  {data?.nodes?.length || 0}개 노드
                </Badge>
                <ActionIcon
                  aria-label="축소"
                  variant="default"
                  onClick={() => setZoom(Math.max(0.5, zoom - 0.1))}
                >
                  <IconMinus size={15} />
                </ActionIcon>
                <Text size="sm">{Math.round(zoom * 100)}%</Text>
                <ActionIcon
                  aria-label="확대"
                  variant="default"
                  onClick={() => setZoom(Math.min(1.6, zoom + 0.1))}
                >
                  <IconPlus size={15} />
                </ActionIcon>
              </Group>
            </div>
            {graph.nodes.length ? (
              <div className="graph-canvas">
                <svg
                  width={1000 * zoom}
                  height={graph.height * zoom}
                  viewBox={`0 0 1000 ${graph.height}`}
                  role="img"
                  aria-label="서비스와 발견 건의 영향 관계도"
                >
                  <defs>
                    <marker
                      id="arrow"
                      viewBox="0 0 10 10"
                      refX="9"
                      refY="5"
                      markerWidth="5"
                      markerHeight="5"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#b3c5cc" />
                    </marker>
                  </defs>
                  {graph.edges.map((e: Row, i: number) => {
                    const a = graph.positions[e.source],
                      b = graph.positions[e.target];
                    const active =
                      selected &&
                      (e.source === selected.id || e.target === selected.id);
                    return (
                      <path
                        key={i}
                        d={`M ${a.x} ${a.y} C ${(a.x + b.x) / 2} ${a.y}, ${(a.x + b.x) / 2} ${b.y}, ${b.x} ${b.y}`}
                        fill="none"
                        stroke={active ? "#087f6b" : "#c3d2d7"}
                        strokeWidth={active ? 2.4 : 1.5}
                        markerEnd="url(#arrow)"
                      />
                    );
                  })}
                  {graph.nodes.map((n: Row) => {
                    const p = graph.positions[n.id];
                    const chosen = selected?.id === n.id;
                    return (
                      <g
                        key={n.id}
                        transform={`translate(${p.x - 96},${p.y - 32})`}
                        onClick={() => setSelected(n)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") setSelected(n);
                        }}
                        tabIndex={0}
                        role="button"
                        aria-label={n.label}
                        style={{ cursor: "pointer" }}
                      >
                        <rect
                          width={192}
                          height={64}
                          rx={12}
                          fill={
                            chosen
                              ? "#123039"
                              : n.type === "service"
                                ? "#edf7f3"
                                : "white"
                          }
                          stroke={
                            chosen
                              ? "#123039"
                              : n.type === "service"
                                ? "#7fbfae"
                                : "#d8e1e5"
                          }
                          strokeWidth={1.5}
                        />
                        <circle
                          cx={21}
                          cy={31}
                          r={6}
                          fill={
                            n.type === "service"
                              ? "#39a48b"
                              : n.type === "finding"
                                ? "#e99559"
                                : "#84a3c1"
                          }
                        />
                        <text
                          x={36}
                          y={26}
                          fontSize={10}
                          fill={chosen ? "#a6c6c1" : "#7a8d94"}
                        >
                          {types[n.type] || n.type}
                        </text>
                        <text
                          x={36}
                          y={46}
                          fontSize={12}
                          fontWeight={600}
                          fill={chosen ? "white" : "#253f48"}
                        >
                          {String(n.label).length > 15
                            ? String(n.label).slice(0, 15) + "…"
                            : n.label}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            ) : (
              <Empty
                title={
                  query
                    ? "일치하는 노드가 없습니다"
                    : "아직 연결된 자산이 없습니다"
                }
                description="서비스의 저장소, 이미지, 추가 공격 표면과 발견 건을 등록하면 관계도가 만들어집니다."
                icon={<IconGitBranch size={30} />}
              />
            )}
            <div className="graph-legend">
              <span>
                <i style={{ background: "#39a48b" }} />
                서비스
              </span>
              <span>
                <i style={{ background: "#e99559" }} />
                발견 건
              </span>
              <span>
                <i style={{ background: "#84a3c1" }} />
                연결된 구성요소
              </span>
              {(data?.nodes?.length || 0) > 70 && (
                <Text size="xs">
                  최대 70개 표시 · 검색으로 범위를 좁히세요.
                </Text>
              )}
            </div>
          </Paper>
          <Paper className="content-card graph-details">
            <h2>연결 정보</h2>
            {selected ? (
              <>
                <Badge variant="light" color="teal" mt="md">
                  {types[selected.type] || selected.type}
                </Badge>
                <h3>{selected.label}</h3>
                <Text size="sm" c="dimmed" style={{ wordBreak: "break-all" }}>
                  {selected.id}
                </Text>
                <Divider my="xl" />
                <Text fw={600} mb="md">
                  연결된 노드
                </Text>
                <Stack gap="sm">
                  {(data?.edges || [])
                    .filter(
                      (e: Row) =>
                        e.source === selected.id || e.target === selected.id,
                    )
                    .map((e: Row, i: number) => {
                      const other = data?.nodes.find(
                        (n: Row) =>
                          n.id ===
                          (e.source === selected.id ? e.target : e.source),
                      );
                      return (
                        <button
                          className="connected-node"
                          key={i}
                          onClick={() => setSelected(other)}
                        >
                          <IconLink size={16} />
                          <span>
                            {other?.label || e.target}
                            <small>{e.label}</small>
                          </span>
                          <IconChevronRight size={15} />
                        </button>
                      );
                    })}
                </Stack>
              </>
            ) : (
              <Empty
                title="노드를 선택하세요"
                description="관계도에서 노드를 클릭하면 연결된 서비스와 영향을 확인할 수 있습니다."
                icon={<IconTargetArrow size={25} />}
              />
            )}
          </Paper>
        </div>
      )}
    </>
  );
}
export function ReportsPage() {
  const can = useCan();
  const { data, loading, error, reload } = useData<Row>("/api/dashboard");
  const findings = useData<Row[]>("/api/findings");
  const services = useData<Row[]>(
    can("services:read") ? "/api/services" : null,
  );
  const grouping = useMemo(() => {
    const map: Record<
      string,
      {
        name: string;
        services: number;
        open: number;
        critical: number;
        resolved: number;
      }
    > = {};
    (services.data || []).forEach((s) => {
      const team = s.team || "미지정";
      if (!map[team])
        map[team] = {
          name: team,
          services: 0,
          open: 0,
          critical: 0,
          resolved: 0,
        };
      map[team].services++;
    });
    (findings.data || []).forEach((f) => {
      const s = services.data?.find((s) => s.id === f.service_id);
      if (!s) return;
      const team = s.team || "미지정";
      if (["resolved", "false_positive", "accepted"].includes(f.status)) {
        if (f.status === "resolved") map[team].resolved++;
      } else {
        map[team].open++;
        if (f.severity === "critical") map[team].critical++;
      }
    });
    return Object.values(map);
  }, [findings.data, services.data]);
  const teams = useListView({
    rows: grouping,
    columns: [
      { key: "name", label: "담당 조직", value: (row) => row.name },
      { key: "services", label: "등록 서비스", value: (row) => row.services },
      { key: "open", label: "미해결 발견 건", value: (row) => row.open },
      { key: "critical", label: "심각한 위험", value: (row) => row.critical },
      { key: "resolved", label: "해결 완료", value: (row) => row.resolved },
    ],
  });
  return (
    <>
      <PageHeader
        eyebrow="RISK INTELLIGENCE"
        title="보고서"
        description="조직별 보안 노출과 개선 현황을 살펴보고 운영 보고 자료를 내보냅니다."
        action={
          <Group>
            <Button
              component="a"
              href="/api/reports/export?format=csv"
              variant="default"
              leftSection={<IconDownload size={18} />}
            >
              CSV 다운로드
            </Button>
            <Button
              component="a"
              href="/api/reports/export?format=json"
              leftSection={<IconDownload size={18} />}
            >
              JSON 다운로드
            </Button>
          </Group>
        }
      />
      <LoadState
        loading={loading || findings.loading || services.loading}
        error={error || findings.error || services.error}
        reload={() => {
          void reload();
          void findings.reload();
          void services.reload();
        }}
      />
      {!loading &&
        !findings.loading &&
        !services.loading &&
        !error &&
        !findings.error &&
        !services.error &&
        data && (
          <>
            <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="lg">
              <Stat
                label="보안 부채 지수"
                value={Number(data.security_debt || 0).toLocaleString()}
                icon={<IconFileAnalytics size={22} />}
                detail="위험의 크기와 미해결 기간을 반영"
                accent
              />
              <Stat
                label="서비스 진단 커버리지"
                value={Math.round(data.coverage || 0)}
                unit="%"
                icon={<IconTargetArrow size={22} />}
                detail="등록 서비스 중 완료 진단 이력이 있는 비율"
              />
              <Stat
                label="해결된 발견 건"
                value={
                  findings.data?.filter((f) => f.status === "resolved")
                    .length || 0
                }
                unit="건"
                icon={<IconCircleCheck size={22} />}
                detail="실제 재검증 기준을 충족한 발견 건"
              />
            </SimpleGrid>
            <Paper className="data-panel" mt="xl">
              <div className="table-toolbar">
                <div>
                  <h2>조직별 보안 현황</h2>
                  <Text size="sm" c="dimmed" mt={4}>
                    서비스 담당 조직을 기준으로 집계합니다.
                  </Text>
                </div>
                <Group className="table-controls" gap="sm">
                  <ListSearch
                    view={teams}
                    label="조직별 보안 현황 검색"
                    placeholder="담당 조직 검색"
                  />
                  <ListReset view={teams} />
                </Group>
              </div>
              <ListTools view={teams} />
              {teams.rows.length ? (
                <TableViewport
                  view={teams}
                  label="조직별 보안 현황"
                  minWidth={670}
                >
                  <Table verticalSpacing="lg" horizontalSpacing="lg">
                    <Table.Thead>
                      <Table.Tr>
                        <SortHeader view={teams} column="name">
                          담당 조직
                        </SortHeader>
                        <SortHeader view={teams} column="services">
                          등록 서비스
                        </SortHeader>
                        <SortHeader view={teams} column="open">
                          미해결 발견 건
                        </SortHeader>
                        <SortHeader view={teams} column="critical">
                          심각한 위험
                        </SortHeader>
                        <SortHeader view={teams} column="resolved">
                          해결 완료
                        </SortHeader>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {teams.rows.map((t) => (
                        <Table.Tr key={t.name}>
                          <Table.Td>
                            <Text fw={600}>{t.name}</Text>
                          </Table.Td>
                          <Table.Td>{t.services}개</Table.Td>
                          <Table.Td>{t.open}건</Table.Td>
                          <Table.Td>
                            <Badge
                              color={t.critical ? "red" : "gray"}
                              variant="light"
                            >
                              {t.critical}건
                            </Badge>
                          </Table.Td>
                          <Table.Td>{t.resolved}건</Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </TableViewport>
              ) : (
                <Empty
                  title={
                    teams.query
                      ? "검색 결과가 없습니다"
                      : "집계할 서비스가 없습니다"
                  }
                  description={
                    teams.query
                      ? "검색어를 변경하거나 조건을 초기화해 주세요."
                      : "서비스와 발견 건을 등록하면 조직별 현황이 표시됩니다."
                  }
                />
              )}
              <ListPagination view={teams} totalLabel="개 조직" />
            </Paper>
            <SimpleGrid cols={{ base: 1, lg: 2 }} mt="xl" spacing="xl">
              <Paper className="content-card">
                <h2>다운로드에 포함되는 정보</h2>
                <Text size="sm" c="dimmed" mt="sm">
                  내보내기 범위: 접근 가능한 발견 건의 최신 5,000건. 조직 표의
                  검색은 화면 목록에 적용됩니다.
                </Text>
                <Stack gap="md" mt="lg">
                  {[
                    "발견 건 제목과 대상 서비스 식별자",
                    "발견 건의 심각도 · 상태 · 개선 정보",
                    "발견 출처와 CVE 식별자",
                    "기여 점수 및 JSON의 내보내기 시점",
                  ].map((t) => (
                    <Group key={t}>
                      <IconCheck size={18} color="#087f6b" />
                      <Text size="sm">{t}</Text>
                    </Group>
                  ))}
                </Stack>
              </Paper>
              <Paper className="content-card">
                <h2>지표를 읽는 방법</h2>
                <Text size="sm" c="dimmed" mt="lg" lh={1.9}>
                  커버리지는 완료된 진단 이력이 있는 서비스의 비율이며, 개별
                  업무 기능과 역할 조합의 전체 검증을 의미하지 않습니다. 보안
                  부채는 조치 우선순위 참고 지표로 사용하고 실제 업무 영향을
                  함께 검토하세요. 실행 실패나 인증 실패는 해결로 집계하지
                  않습니다.
                </Text>
              </Paper>
            </SimpleGrid>
          </>
        )}
    </>
  );
}
export function ContributionsPage() {
  const { data, loading, error, reload } = useData<Row[]>("/api/findings");
  const rows = (data || []).filter((r) => Number(r.contribution_points) > 0);
  const total = rows.reduce((a, r) => a + Number(r.contribution_points), 0);
  const view = useListView<Row>({
    rows,
    columns: [
      { key: "title", label: "발견 건", value: (row) => row.title },
      {
        key: "assignee",
        label: "담당자",
        value: (row) => row.assignee || "미지정",
      },
      {
        key: "severity",
        label: "심각도",
        value: (row) => label(row.severity),
        compare: (a, b) =>
          ["info", "low", "medium", "high", "critical"].indexOf(a.severity) -
          ["info", "low", "medium", "high", "critical"].indexOf(b.severity),
      },
      { key: "status", label: "상태", value: (row) => label(row.status) },
      {
        key: "contribution_points",
        label: "인정 점수",
        value: (row) => Number(row.contribution_points),
      },
    ],
    defaultSort: { key: "contribution_points", direction: "desc" },
    searchValues: (row) => [row.cve, row.severity, row.status],
  });
  return (
    <>
      <PageHeader
        eyebrow="SECURITY CONTRIBUTIONS"
        title="보안 기여"
        description="유효한 발견과 재현, 개선에 기여한 활동을 투명하게 기록합니다."
      />
      <div className="contribution-banner">
        <div className="contribution-icon">
          <IconTrophy size={38} stroke={1.4} />
        </div>
        <div>
          <h2>함께 만드는 더 안전한 서비스</h2>
          <p>
            발견 건수보다 재현 가능한 근거와 실제 개선을 가치 있게 기록합니다.
          </p>
        </div>
      </div>
      <LoadState loading={loading} error={error} reload={reload} />
      {!loading && !error && (
        <>
          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="lg">
            <Stat
              label="인정된 기여"
              value={rows.length}
              unit="건"
              icon={<IconShieldCheck size={22} />}
              detail="관리자가 검토하고 점수를 부여한 발견 건"
            />
            <Stat
              label="누적 기여 점수"
              value={total.toLocaleString()}
              unit="점"
              icon={<IconTrophy size={22} />}
              detail="검토된 기여 점수의 합계"
              accent
            />
            <Stat
              label="개선으로 이어진 기여"
              value={rows.filter((r) => r.status === "resolved").length}
              unit="건"
              icon={<IconCircleCheck size={22} />}
              detail="기여가 인정되고 재검증으로 해결된 건"
            />
          </SimpleGrid>
          <Paper className="data-panel" mt="xl">
            <div className="table-toolbar">
              <h2>기여 기록</h2>
              <Group className="table-controls" gap="sm">
                <ListSearch
                  view={view}
                  label="보안 기여 검색"
                  placeholder="발견 건 · 담당자 · 상태 검색"
                />
                <ListReset view={view} />
              </Group>
            </div>
            <ListTools view={view} />
            {view.rows.length ? (
              <TableViewport view={view} label="보안 기여" minWidth={680}>
                <Table verticalSpacing="md" horizontalSpacing="lg">
                  <Table.Thead>
                    <Table.Tr>
                      <SortHeader view={view} column="title">
                        발견 건
                      </SortHeader>
                      <SortHeader view={view} column="assignee">
                        담당자
                      </SortHeader>
                      <SortHeader view={view} column="severity">
                        심각도
                      </SortHeader>
                      <SortHeader view={view} column="status">
                        상태
                      </SortHeader>
                      <SortHeader view={view} column="contribution_points">
                        인정 점수
                      </SortHeader>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {view.rows.map((r) => (
                      <Table.Tr key={r.id}>
                        <Table.Td>
                          <Link
                            className="table-detail-link"
                            to={`/findings?item=${encodeURIComponent(r.id)}`}
                          >
                            {r.title}
                          </Link>
                        </Table.Td>
                        <Table.Td>{r.assignee || "미지정"}</Table.Td>
                        <Table.Td>
                          <Status value={r.severity} />
                        </Table.Td>
                        <Table.Td>
                          <Status value={r.status} />
                        </Table.Td>
                        <Table.Td>
                          <Badge color="teal" variant="light" size="lg">
                            +{r.contribution_points}점
                          </Badge>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </TableViewport>
            ) : (
              <Empty
                title={
                  view.query
                    ? "검색 결과가 없습니다"
                    : "인정된 기여 기록이 없습니다"
                }
                description={
                  view.query
                    ? "검색어를 변경하거나 조건을 초기화해 주세요."
                    : "관리자가 유효한 발견과 기여를 검토하고 점수를 부여하면 표시됩니다."
                }
                icon={<IconTrophy size={30} />}
              />
            )}
            <ListPagination view={view} />
            {(data?.length || 0) >= 5000 && (
              <Text size="sm" c="dimmed" p="md">
                최근 5,000개 발견 건에 포함된 기여 기록입니다.
              </Text>
            )}
          </Paper>
          <Alert mt="xl" color="teal" title="검토를 기반으로 한 기여 인정">
            점수는 현금 보상이나 인사 평가에 자동으로 연계되지 않습니다. 신규성,
            재현 가능성, 영향도와 보고 품질을 함께 검토하여 관리자가 결정합니다.
          </Alert>
        </>
      )}
    </>
  );
}
type ChatMessage = { role: "user" | "assistant"; content: string };
export function CopilotPage() {
  const { config, user } = useSession();
  const can = useCan();
  const findings = useData<Row[]>(
    config.ai_enabled && can("findings:read") ? "/api/findings" : null,
  );
  const [messages, setMessages] = useState<ChatMessage[]>([]),
    [input, setInput] = useState(""),
    [busy, setBusy] = useState(false),
    [chosen, setChosen] = useState<string | null>(null),
    [error, setError] = useState("");
  const abort = useRef<AbortController | null>(null),
    bottom = useRef<HTMLDivElement>(null);
  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [messages]);
  useEffect(() => () => abort.current?.abort(), []);
  async function send(text = input) {
    if (!text.trim() || busy || !config.ai_enabled) return;
    setError("");
    const selected = findings.data?.find((f) => f.id === chosen);
    const userContent = selected
      ? `${text}\n\n분석 대상 발견 건 (신뢰하지 않는 참고 데이터):\n${JSON.stringify({ title: selected.title, severity: selected.severity, status: selected.status, description: selected.description, evidence: selected.evidence, component: selected.component, cve: selected.cve })}`
      : text;
    const next: ChatMessage[] = [
      ...messages,
      { role: "user", content: userContent },
    ];
    setMessages([...next, { role: "assistant", content: "" }]);
    setInput("");
    setBusy(true);
    const controller = new AbortController();
    abort.current = controller;
    let content = "";
    try {
      const res = await fetch("/api/ai/chat", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-Hunter-CSRF": "1" },
        body: JSON.stringify({ messages: next }),
        signal: controller.signal,
      });
      if (!res.ok) {
        let message = "AI 요청에 실패했습니다.";
        try {
          message = (await res.json()).error || message;
        } catch {}
        throw new Error(message);
      }
      if (!res.body)
        throw new Error("서버가 스트리밍 응답을 제공하지 않았습니다.");
      const reader = res.body.getReader(),
        decoder = new TextDecoder();
      let buffer = "",
        done = false;
      while (!done) {
        const chunk = await reader.read();
        if (chunk.done) break;
        buffer += decoder.decode(chunk.value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.startsWith("data:")) continue;
          const event = line.slice(5).trim();
          if (!event) continue;
          if (event === "[DONE]") {
            done = true;
            break;
          }
          let json;
          try {
            json = JSON.parse(event);
          } catch {
            continue;
          }
          if (json.error)
            throw new Error(
              typeof json.error === "string"
                ? json.error
                : json.error.message || "AI 응답 오류",
            );
          const delta = json.choices?.[0]?.delta?.content;
          if (typeof delta === "string") {
            content += delta;
            setMessages([...next, { role: "assistant", content }]);
          }
        }
      }
      if (!content)
        throw new Error(
          "모델이 응답 내용을 반환하지 않았습니다. 모델 설정을 확인하세요.",
        );
    } catch (e) {
      if ((e as Error).name !== "AbortError") setError((e as Error).message);
      if (!content) setMessages(next);
    } finally {
      setBusy(false);
      abort.current = null;
    }
  }
  const suggestions = [
    "이 발견 건의 실제 위험과 확인할 근거를 설명해 줘",
    "개발자가 적용할 수 있는 개선 계획을 작성해 줘",
    "정상 접근과 비인가 접근을 비교하는 검증 시나리오를 제안해 줘",
  ];
  return (
    <>
      <PageHeader
        eyebrow="DEVELOPER SECURITY COPILOT"
        title="AI 분석 도우미"
        description="사내 AI와 함께 발견 건을 이해하고, 근거를 확인하며, 다음 개선을 준비하세요."
        action={
          <Group>
            {canReadAgents(can) && (
              <Button
                component={Link}
                to="/agents"
                variant="light"
                leftSection={<IconSparkles size={17} />}
              >
                에이전트 진단
              </Button>
            )}
            <Badge
              variant="light"
              color={config.ai_enabled ? "teal" : "gray"}
              size="lg"
            >
              {config.ai_enabled ? "스트리밍 응답" : "설정 대기"}
            </Badge>
            <Button
              variant="default"
              size="sm"
              disabled={busy || !messages.length}
              onClick={() => {
                setMessages([]);
                setError("");
              }}
            >
              새 대화
            </Button>
          </Group>
        }
      />
      {!config.ai_enabled && (
        <Alert color="teal" title="AI 연결 설정이 필요합니다" mb="xl">
          서비스 관리자가 AI API 주소, 모델과 토큰 한도를 설정하면 분석 도우미를
          사용할 수 있습니다.
          {user?.role === "admin" && (
            <Button
              component={Link}
              to="/admin/settings"
              variant="light"
              size="sm"
              ml="md"
            >
              AI 설정으로 이동
            </Button>
          )}
        </Alert>
      )}
      <div className="copilot-layout">
        <Paper className="chat-panel">
          <div className="chat-topline">
            <Group gap="sm">
              <div className="copilot-avatar">
                <IconSparkles size={19} />
              </div>
              <div>
                <strong>Hunter AI</strong>
                <span>분석과 개선을 함께하는 보안 도우미</span>
              </div>
            </Group>
            <Badge color="gray" variant="light">
              사내 모델 연결
            </Badge>
          </div>
          <div className="chat-messages">
            {!messages.length ? (
              <div className="chat-welcome">
                <div className="chat-welcome-icon">
                  <IconSparkles size={32} stroke={1.5} />
                </div>
                <h2>어떤 위험을 함께 살펴볼까요?</h2>
                <p>
                  발견 건의 맥락을 이해하고, 개선 방향을 구체적으로 정리하세요.
                  <br />
                  AI의 판단은 실제 검증 근거와 함께 확인합니다.
                </p>
                <div className="prompt-suggestions">
                  {suggestions.map((s, i) => (
                    <button
                      key={i}
                      disabled={!config.ai_enabled}
                      onClick={() => {
                        setInput(s);
                      }}
                    >
                      <IconSparkles size={17} />
                      <span>{s}</span>
                      <IconArrowUpRight size={17} />
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((m, i) => (
                <div key={i} className={`chat-message ${m.role}`}>
                  <div className="message-avatar">
                    {m.role === "assistant" ? (
                      <IconSparkles size={18} />
                    ) : (
                      <IconUser size={18} />
                    )}
                  </div>
                  <div>
                    <strong>
                      {m.role === "assistant" ? "Hunter AI" : "나"}
                    </strong>
                    <div className="message-content">
                      {m.content || (
                        <span className="typing-indicator">
                          분석하고 있습니다<span>···</span>
                        </span>
                      )}
                      {busy && i === messages.length - 1 && m.content && (
                        <span className="stream-cursor" />
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
            {error && (
              <Alert color="red" mt="lg" title="AI 응답 안내">
                {error}
              </Alert>
            )}
            <div ref={bottom} />
          </div>
          <div className="chat-composer">
            <Textarea
              aria-label="AI에게 질문하기"
              placeholder={
                config.ai_enabled
                  ? "발견 건이나 개선 방법에 대해 질문하세요..."
                  : "AI 설정 후 질문할 수 있습니다."
              }
              disabled={!config.ai_enabled}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              minRows={2}
              maxRows={8}
              autosize
              onKeyDown={(e) => {
                if (
                  e.key === "Enter" &&
                  !e.shiftKey &&
                  !e.nativeEvent.isComposing
                ) {
                  e.preventDefault();
                  void send();
                }
              }}
            />
            <div className="composer-footer">
              <Text size="xs" c="dimmed">
                Enter로 전송 · Shift + Enter로 줄바꿈
              </Text>
              {busy ? (
                <Button
                  size="sm"
                  variant="light"
                  color="gray"
                  leftSection={<IconSquare size={15} />}
                  onClick={() => abort.current?.abort()}
                >
                  응답 중지
                </Button>
              ) : (
                <Button
                  size="sm"
                  disabled={!config.ai_enabled || !input.trim()}
                  rightSection={<IconSend size={16} />}
                  onClick={() => send()}
                >
                  전송
                </Button>
              )}
            </div>
          </div>
        </Paper>
        <div className="copilot-context">
          <Paper className="content-card">
            <div className="context-icon">
              <IconShieldCheck size={23} />
            </div>
            <h2>분석 맥락</h2>
            <Text size="sm" c="dimmed" mt="sm" mb="xl">
              발견 건을 선택하면 제목, 근거와 영향 정보가 질문에 함께
              전달됩니다.
            </Text>
            <Select
              label="참고할 발견 건"
              placeholder="선택하지 않음"
              searchable
              clearable
              data={(findings.data || []).map((f) => ({
                value: f.id,
                label: f.title,
              }))}
              value={chosen}
              onChange={setChosen}
              disabled={busy || !config.ai_enabled}
              nothingFoundMessage="조회 가능한 발견 건이 없습니다"
            />
            {chosen && (
              <Badge mt="md" color="teal" variant="light">
                발견 건 맥락 포함
              </Badge>
            )}
          </Paper>
          <div className="copilot-notes">
            <IconShieldCheck size={19} />
            <h3>검증은 근거를 기준으로</h3>
            <p>
              AI는 진단을 직접 실행하거나 취약점을 확정하지 않습니다. 제안한
              개선안은 담당자가 검토하고 실제 테스트로 확인하세요.
            </p>
            <Divider my="lg" />
            <Text size="xs" c="dimmed">
              대화는 현재 브라우저 화면에서 유지됩니다. 새로고침하거나 새 대화를
              시작하면 초기화됩니다.
            </Text>
          </div>
        </div>
      </div>
    </>
  );
}
