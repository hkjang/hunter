import { useEffect, useState } from "react";
import {
  Link,
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Tabs,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import {
  IconArrowLeft,
  IconGitCompare,
  IconPlayerPlay,
  IconPlus,
  IconRefresh,
  IconTrash,
} from "@tabler/icons-react";
import {
  dateText,
  label,
  type Row,
  useCan,
  useData,
  useSession,
  success,
} from "./api";
import { LoadState, PageHeader, Status } from "./components";
import { FormFeedback } from "./form-feedback";
import {
  Metric,
  WorkflowTable,
  type WorkflowColumn,
} from "./workflow-components";
import {
  workflowAPI,
  type Campaign,
  type CampaignTarget,
  type CampaignComparison,
  type CampaignScan,
  type Observation,
} from "./workflow-api";
import {
  campaignTargetError,
  safeListReturn,
  unchangedObservations,
} from "./workflow-state";
const profiles = ["http-baseline", "authorization", "import-only"].map(
  (value) => ({ value, label: label(value) }),
);
function CampaignForm({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (campaign: Campaign) => void;
}) {
  const services = useData<Row[]>("/api/services"),
    scopes = useData<Row[]>("/api/scopes"),
    scenarios = useData<Row[]>("/api/scenarios");
  const { config } = useSession();
  const [name, setName] = useState(""),
    [description, setDescription] = useState(""),
    [targets, setTargets] = useState<CampaignTarget[]>([
      { service_id: "", profile: "http-baseline" },
    ]),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  function update(index: number, change: Partial<CampaignTarget>) {
    setTargets((current) =>
      current.map((target, i) =>
        i === index ? { ...target, ...change } : target,
      ),
    );
  }
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    const problem = !name.trim()
      ? "캠페인 이름을 입력하세요."
      : campaignTargetError(targets);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    try {
      const campaign = await workflowAPI.createCampaign({
        name: name.trim(),
        description,
        targets: targets.map((target) => ({
          service_id: target.service_id,
          profile: target.profile,
          ...(target.scope_id ? { scope_id: target.scope_id } : {}),
          ...(target.profile === "authorization" && target.scenario_id
            ? { scenario_id: target.scenario_id }
            : {}),
        })),
      });
      success("캠페인을 등록했습니다. 상세에서 진단을 시작할 수 있습니다.");
      onCreated(campaign);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit}>
      <Stack>
        <FormFeedback error={error} />
        <LoadState
          loading={services.loading}
          error={services.error || scopes.error || scenarios.error}
          reload={() => {
            void services.reload();
            void scopes.reload();
            void scenarios.reload();
          }}
        />
        <TextInput
          required
          label="캠페인 이름"
          placeholder="예: 결제 서비스 2.4 배포 검증"
          value={name}
          onChange={(event) => setName(event.currentTarget.value)}
          maxLength={200}
          disabled={busy}
        />
        <Textarea
          label="목적 · 배포 정보"
          placeholder="검증할 변경 사항과 기준 배포를 기록하세요."
          value={description}
          onChange={(event) => setDescription(event.currentTarget.value)}
          minRows={2}
          autosize
          disabled={busy}
        />
        {targets.map((target, index) => (
          <Paper key={index} withBorder p="md">
            <Stack>
              <Group justify="space-between">
                <Text fw={600}>대상 {index + 1}</Text>
                {targets.length > 1 && (
                  <Button
                    variant="subtle"
                    color="red"
                    size="compact-md"
                    disabled={busy}
                    aria-label={`대상 ${index + 1} 삭제`}
                    leftSection={<IconTrash size={15} />}
                    onClick={() =>
                      setTargets((current) =>
                        current.filter((_, i) => i !== index),
                      )
                    }
                  >
                    삭제
                  </Button>
                )}
              </Group>
              <Select
                required
                label={`대상 ${index + 1} 서비스`}
                searchable
                placeholder="서비스 선택"
                value={target.service_id || null}
                onChange={(value) =>
                  update(index, {
                    service_id: value || "",
                    scope_id: "",
                    scenario_id: "",
                  })
                }
                data={(services.data || []).map((item) => ({
                  value: item.id,
                  label: item.name,
                }))}
                disabled={busy}
              />
              <Select
                required
                label={`대상 ${index + 1} 프로파일`}
                value={target.profile}
                data={profiles}
                allowDeselect={false}
                onChange={(value) =>
                  update(index, {
                    profile: value || "http-baseline",
                    scenario_id: "",
                  })
                }
                disabled={busy}
              />
              <Select
                label={`대상 ${index + 1} 허용 범위`}
                placeholder="유효한 범위 자동 선택"
                clearable
                searchable
                data={(scopes.data || [])
                  .filter((item) => item.service_id === target.service_id)
                  .map((item) => ({ value: item.id, label: item.name }))}
                value={target.scope_id || null}
                onChange={(value) => update(index, { scope_id: value || "" })}
                disabled={busy || !target.service_id}
                description="실행할 때 현재 승인·기한·정책을 다시 검사합니다."
              />
              {target.profile === "authorization" && (
                <Select
                  required
                  label={`대상 ${index + 1} 권한 시나리오`}
                  placeholder="시나리오 선택"
                  searchable
                  value={target.scenario_id || null}
                  onChange={(value) =>
                    update(index, { scenario_id: value || "" })
                  }
                  data={(scenarios.data || [])
                    .filter((item) => item.service_id === target.service_id)
                    .map((item) => ({ value: item.id, label: item.name }))}
                  disabled={busy}
                />
              )}
              {target.profile === "import-only" && (
                <Text size="sm" c="dimmed">
                  실제 스캐너를 실행하지 않습니다. 생성된 진단 실행에 외부 도구
                  결과를 반입해야 완료됩니다.
                </Text>
              )}
            </Stack>
          </Paper>
        ))}
        <Button
          variant="light"
          leftSection={<IconPlus size={17} />}
          onClick={() =>
            setTargets((current) => [
              ...current,
              { service_id: "", profile: "http-baseline" },
            ])
          }
          disabled={busy || targets.length >= 20}
        >
          진단 대상 추가 ({targets.length}/20)
        </Button>
        <Alert color="teal">
          등록하면 초안으로 저장됩니다. 상세의 ‘캠페인 시작’으로 각 대상의 실제
          진단을 요청합니다.
          {config.approval_enabled
            ? " 현재 팀장 검토·승인 절차가 적용됩니다."
            : " 현재 팀장 검토·승인 절차는 사용하지 않습니다."}
        </Alert>
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose} disabled={busy}>
            취소
          </Button>
          <Button type="submit" loading={busy}>
            캠페인 등록
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
export function CampaignsPage() {
  const result = useData<{ items: Campaign[]; total: number }>(
    "/api/campaigns",
  );
  const [opened, setOpened] = useState(false);
  const can = useCan(),
    navigate = useNavigate(),
    location = useLocation();
  const columns: WorkflowColumn<Campaign>[] = [
    {
      key: "name",
      label: "캠페인",
      value: (item) => item.name,
      render: (item) => (
        <>
          <Link
            className="workflow-link"
            to={`/campaigns/${item.id}`}
            state={{ from: location.pathname + location.search }}
          >
            {item.name}
          </Link>
          <Text size="sm" c="dimmed" lineClamp={2}>
            {item.description}
          </Text>
        </>
      ),
    },
    {
      key: "status",
      label: "상태",
      value: (item) => label(item.status),
      render: (item) => <Status value={item.status} />,
    },
    {
      key: "targets",
      label: "진단 대상",
      value: (item) => item.targets?.length || 0,
    },
    {
      key: "completed",
      label: "완료 실행",
      value: (item) => item.summary?.completed || 0,
      render: (item) =>
        `${item.summary?.completed || 0} / ${item.summary?.total || 0}`,
    },
    {
      key: "created_at",
      label: "등록 시각",
      value: (item) => Date.parse(item.created_at),
      render: (item) => dateText(item.created_at),
    },
  ];
  return (
    <>
      <PageHeader
        title="진단 캠페인"
        description="배포나 검증 목적에 맞춰 여러 진단을 묶고, 이전 캠페인과 관측 결과를 비교합니다."
        action={
          can("scans:write") && (
            <Button
              leftSection={<IconPlus size={18} />}
              onClick={() => setOpened(true)}
            >
              캠페인 등록
            </Button>
          )
        }
      />
      <WorkflowTable
        name="캠페인"
        rowKey={(item) => item.id}
        rows={result.data?.items || []}
        columns={columns}
        loading={result.loading}
        error={result.error}
        reload={result.reload}
        defaultSort={{ key: "created_at", direction: "desc" }}
        empty="승인된 서비스와 진단 프로파일을 묶어 첫 캠페인을 등록하세요."
      />
      <Modal
        opened={opened}
        onClose={() => setOpened(false)}
        title="진단 캠페인 등록"
        size="lg"
      >
        {opened && (
          <CampaignForm
            onClose={() => setOpened(false)}
            onCreated={(campaign) => {
              setOpened(false);
              navigate(`/campaigns/${campaign.id}`, {
                state: { from: location.pathname + location.search },
              });
            }}
          />
        )}
      </Modal>
    </>
  );
}
function CampaignCompare({ campaign }: { campaign: Campaign }) {
  const [params, setParams] = useSearchParams(),
    location = useLocation();
  const baseline = params.get("baseline") || "";
  const campaigns = useData<{ items: Campaign[]; total: number }>(
    "/api/campaigns",
  );
  const result = useData<CampaignComparison>(
    baseline
      ? `/api/campaigns/${campaign.id}/compare?baseline=${encodeURIComponent(baseline)}`
      : null,
  );
  type Change = {
    key: string;
    kind: string;
    current: Observation;
    before?: Observation;
  };
  const changes: Change[] = result.data?.comparable
    ? [
        ...result.data.added.map((current, i) => ({
          key: `added-${i}`,
          kind: "신규 관측",
          current,
        })),
        ...unchangedObservations(
          result.data.persisting,
          result.data.changed,
        ).map((current, i) => ({
          key: `persisting-${i}`,
          kind: "반복 관측",
          current,
        })),
        ...result.data.not_seen.map((current, i) => ({
          key: `not-seen-${i}`,
          kind: "이번 실행에서 미관측",
          current,
        })),
        ...result.data.changed.map((item, i) => ({
          key: `changed-${i}`,
          kind: "관측 정보 변경",
          current: item.after,
          before: item.before,
        })),
      ]
    : [];
  return (
    <Stack>
      <Select
        label="기준 캠페인"
        placeholder="비교할 이전 캠페인 선택"
        searchable
        clearable
        value={baseline || null}
        data={(campaigns.data?.items || [])
          .filter((item) => item.id !== campaign.id)
          .map((item) => ({
            value: item.id,
            label: `${item.name} · ${label(item.status)} · ${dateText(item.created_at)}`,
          }))}
        onChange={(value) => {
          const next = new URLSearchParams(params);
          if (value) next.set("baseline", value);
          else next.delete("baseline");
          next.delete("page");
          setParams(next, { state: location.state });
        }}
      />
      <Alert color="teal" title="같은 조건의 완료된 실행만 비교합니다">
        두 캠페인의 서비스·프로파일·실행 조건과 관측 기록을 확인합니다. ‘이번
        실행에서 미관측’은 해결 상태가 아닙니다. 발견 건의 해결은 별도 재검증
        결과로 확인하세요.
      </Alert>
      {campaigns.error && (
        <LoadState
          loading={false}
          error={campaigns.error}
          reload={campaigns.reload}
        />
      )}
      {baseline && (
        <>
          <LoadState
            loading={result.loading}
            error={result.error}
            reload={result.reload}
          />
          {result.data &&
            !result.loading &&
            !result.error &&
            (!result.data.comparable ? (
              <Alert color="orange" title="현재 두 캠페인을 비교할 수 없습니다">
                <Stack gap="xs">
                  {result.data.reasons.map((reason, i) => (
                    <Text key={i}>{reason}</Text>
                  ))}
                </Stack>
              </Alert>
            ) : (
              <>
                <SimpleGrid cols={{ base: 2, md: 4 }}>
                  <Metric label="신규 관측" value={result.data.added.length} />
                  <Metric
                    label="반복 관측"
                    value={result.data.persisting.length}
                    detail="관측 정보 변경 항목 포함"
                  />
                  <Metric
                    label="미관측"
                    value={result.data.not_seen.length}
                    detail="해결을 의미하지 않습니다."
                  />
                  <Metric
                    label="정보 변경"
                    value={result.data.changed.length}
                  />
                </SimpleGrid>
                <WorkflowTable
                  name="관측 결과 비교"
                  rowKey={(item) => item.key}
                  rows={changes}
                  columns={[
                    {
                      key: "title",
                      label: "발견 건",
                      value: (item) => item.current.title,
                      render: (item) => (
                        <>
                          <Link
                            className="workflow-link"
                            to={`/findings?item=${encodeURIComponent(item.current.finding_id)}`}
                          >
                            {item.current.title}
                          </Link>
                          <Text size="sm" c="dimmed">
                            {[item.current.cve, item.current.component]
                              .filter(Boolean)
                              .join(" · ")}
                          </Text>
                        </>
                      ),
                    },
                    {
                      key: "kind",
                      label: "비교 결과",
                      value: (item) => item.kind,
                    },
                    {
                      key: "severity",
                      label: "심각도",
                      value: (item) => label(item.current.severity),
                      render: (item) => (
                        <Stack gap="xs">
                          {item.before && (
                            <Text size="sm" c="dimmed">
                              기준: {label(item.before.severity)}
                            </Text>
                          )}
                          <Status value={item.current.severity} />
                        </Stack>
                      ),
                    },
                    {
                      key: "source",
                      label: "관측 위치",
                      value: (item) =>
                        [
                          item.current.source,
                          item.current.location,
                          item.current.rule_id,
                        ]
                          .filter(Boolean)
                          .join(" · "),
                      render: (item) => (
                        <>
                          <Text size="sm">
                            {item.current.location ||
                              item.current.rule_id ||
                              item.current.source ||
                              "미지정"}
                          </Text>
                          <Link
                            className="workflow-link"
                            to={`/scans?item=${encodeURIComponent(item.current.scan_id)}`}
                          >
                            관련 실행
                          </Link>
                        </>
                      ),
                    },
                  ]}
                  empty="두 캠페인에 비교 가능한 발견 관측이 없습니다."
                />
              </>
            ))}
        </>
      )}
    </Stack>
  );
}
export function CampaignDetailPage() {
  const { id = "" } = useParams();
  return <CampaignDetail key={id} id={id} />;
}
function CampaignDetail({ id }: { id: string }) {
  const result = useData<Campaign>(`/api/campaigns/${encodeURIComponent(id)}`);
  const services = useData<Row[]>("/api/services");
  const can = useCan(),
    location = useLocation();
  const { config } = useSession();
  const [params, setParams] = useSearchParams();
  const tab =
    params.get("tab") === "compare" && can("findings:read")
      ? "compare"
      : "runs";
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const campaign = result.data;
  useEffect(() => {
    if (
      !campaign ||
      ["draft", "completed", "inconclusive"].includes(campaign.status)
    )
      return;
    const timer = window.setInterval(() => {
      if (!document.hidden) void result.reload();
    }, 10000);
    return () => window.clearInterval(timer);
  }, [campaign?.status, result.reload]);
  async function start() {
    setError("");
    setBusy(true);
    try {
      const value = await workflowAPI.startCampaign(id);
      result.setData(value);
      success("캠페인의 진단 요청을 처리했습니다.");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const columns: WorkflowColumn<CampaignScan>[] = [
    {
      key: "service",
      label: "서비스",
      value: (item) => item.service_name,
      render: (item) => (
        <Link
          className="workflow-link"
          to={`/scans?item=${encodeURIComponent(item.id)}`}
        >
          {item.service_name || "진단 실행 보기"}
        </Link>
      ),
    },
    {
      key: "profile",
      label: "진단 프로파일",
      value: (item) => label(item.profile),
    },
    {
      key: "status",
      label: "상태",
      value: (item) => label(item.status),
      render: (item) => <Status value={item.status} />,
    },
    {
      key: "created_at",
      label: "요청 시각",
      value: (item) => Date.parse(item.created_at),
      render: (item) => dateText(item.created_at),
    },
  ];
  return (
    <>
      <Button
        component={Link}
        to={safeListReturn(location.state?.from, "/campaigns")}
        variant="subtle"
        mb="md"
        leftSection={<IconArrowLeft size={17} />}
      >
        캠페인 목록으로
      </Button>
      <PageHeader
        title={campaign?.name || "캠페인 상세"}
        description={
          campaign?.description ||
          "대상별 실행 상태와 기준 캠페인 대비 관측 결과를 확인합니다."
        }
        action={
          <Group>
            <Button
              variant="default"
              leftSection={<IconRefresh size={17} />}
              onClick={result.reload}
            >
              새로고침
            </Button>
            {can("scans:write") && campaign?.status === "draft" && (
              <Button
                loading={busy}
                onClick={start}
                leftSection={<IconPlayerPlay size={17} />}
              >
                캠페인 시작
              </Button>
            )}
          </Group>
        }
      />
      <FormFeedback error={error} />
      <LoadState
        loading={result.loading}
        error={result.error}
        reload={result.reload}
      />
      {campaign && !result.loading && !result.error && (
        <>
          <Group mb="lg">
            <Status value={campaign.status} />
            <Text size="sm" c="dimmed">
              등록 {dateText(campaign.created_at)}
              {campaign.started_at
                ? ` · 시작 ${dateText(campaign.started_at)}`
                : ""}
            </Text>
          </Group>
          <SimpleGrid cols={{ base: 2, md: 4 }}>
            <Metric label="진단 대상" value={campaign.targets.length} />
            <Metric label="완료 실행" value={campaign.summary.completed} />
            <Metric label="실행 중" value={campaign.summary.running} />
            <Metric label="실패 · 불확실" value={campaign.summary.failed} />
          </SimpleGrid>
          {campaign.status === "draft" && (
            <Alert mt="lg" color="teal" title="시작 전 초안">
              최대 20개의 등록된 진단 대상을 각각 검사합니다. 서비스와 범위
              승인을 확인한 후 시작하세요.
              {config.approval_enabled
                ? " 팀장 검토·승인 절차가 적용됩니다."
                : ""}{" "}
              같은 캠페인을 다시 시작해도 실행을 중복 생성하지 않습니다.
            </Alert>
          )}
          {campaign.status === "draft" && (
            <Paper className="workflow-panel" mt="lg">
              <Text fw={600} mb="sm">
                등록된 진단 대상
              </Text>
              <Stack gap="sm">
                {campaign.targets.map((target, index) => (
                  <Text key={index}>
                    {index + 1}. {label(target.profile)} ·{" "}
                    {services.data?.find(
                      (service) => service.id === target.service_id,
                    )?.name || "등록된 서비스"}
                    {target.scenario_id ? " · 권한 시나리오 지정" : ""}
                    {target.scope_id
                      ? " · 범위 지정"
                      : " · 유효 범위 자동 선택"}
                  </Text>
                ))}
              </Stack>
            </Paper>
          )}
          <Tabs
            value={tab}
            onChange={(value) => {
              const next = new URLSearchParams(params);
              next.set("tab", value || "runs");
              next.delete("page");
              setParams(next, { state: location.state });
            }}
            className="workflow-tabs"
          >
            <Tabs.List>
              <Tabs.Tab value="runs">진단 실행</Tabs.Tab>
              {can("findings:read") && (
                <Tabs.Tab
                  value="compare"
                  leftSection={<IconGitCompare size={16} />}
                >
                  결과 비교
                </Tabs.Tab>
              )}
            </Tabs.List>
          </Tabs>
          {tab === "runs" ? (
            <WorkflowTable
              name="캠페인 실행"
              rowKey={(item) => item.id}
              rows={campaign.scans || []}
              columns={columns}
              empty={
                campaign.status === "draft"
                  ? "캠페인을 시작하면 대상별 진단 실행이 생성됩니다."
                  : "생성된 실행이 없습니다. 캠페인 상태를 새로 확인해 주세요."
              }
            />
          ) : (
            <CampaignCompare campaign={campaign} />
          )}
        </>
      )}
    </>
  );
}
