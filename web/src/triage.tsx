import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  Alert,
  Badge,
  Button,
  Group,
  Pagination,
  Paper,
  Popover,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { IconMessage, IconRefresh, IconSearch } from "@tabler/icons-react";
import { dateText, fullDate, useCan, useData, success } from "./api";
import { Empty, LoadState, PageHeader, Status } from "./components";
import { FormFeedback } from "./form-feedback";
import { Metric } from "./workflow-components";
import {
  workflowAPI,
  type ActivityPage,
  type FindingQueue,
  type QueueItem,
} from "./workflow-api";
import {
  percentText,
  queueRequest,
  queueViews,
  readQueueParams,
} from "./workflow-state";

const slaLabels: Record<string, string> = {
  overdue: "기한 초과",
  due_soon: "기한 임박",
  on_track: "기한 내",
  not_set: "기한 미설정",
  invalid: "기한 형식 확인 필요",
};
function Priority({ item }: { item: QueueItem }) {
  return (
    <Popover
      width={310}
      position="bottom-start"
      shadow="md"
      trapFocus
      returnFocus
    >
      <Popover.Target>
        <Button
          variant="light"
          color={
            item.priority.score >= 80
              ? "red"
              : item.priority.score >= 55
                ? "orange"
                : "teal"
          }
          aria-label={`${item.title} 우선순위 근거`}
        >
          {item.priority.score}점 · 근거
        </Button>
      </Popover.Target>
      <Popover.Dropdown>
        <Text fw={700}>업무 조치 우선순위</Text>
        <Text size="sm" c="dimmed" mt="xs">
          기술적 심각도와 별도로, 현재 서비스 정보와 관리 정책에 따라
          산출합니다.
        </Text>
        <Stack gap="xs" mt="sm">
          {item.priority.reasons.map((reason, index) => (
            <Text size="sm" key={index}>
              • {reason}
            </Text>
          ))}
        </Stack>
      </Popover.Dropdown>
    </Popover>
  );
}
export function TriagePage() {
  const [params, setParams] = useSearchParams();
  const state = readQueueParams(params);
  const { data, loading, error, reload } = useData<FindingQueue>(
    queueRequest(params),
  );
  function update(changes: Record<string, string | null>, replace = false) {
    const next = new URLSearchParams(params);
    next.delete("page");
    for (const [key, value] of Object.entries(changes))
      value ? next.set(key, value) : next.delete(key);
    setParams(next, { replace, preventScrollReset: true });
  }
  useEffect(() => {
    const validPage = data
      ? Math.max(1, Math.min(data.page, Math.ceil(data.total / state.size)))
      : state.page;
    if (data && !loading && !error && validPage !== state.page) {
      const next = new URLSearchParams(params);
      if (validPage <= 1) next.delete("page");
      else next.set("page", String(validPage));
      setParams(next, { replace: true });
    }
  }, [data, loading, error]);
  return (
    <>
      <PageHeader
        title="조치함"
        description="기한과 위험 근거를 함께 확인하고, 먼저 조치할 발견 건부터 이어서 처리하세요."
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
      {data && !error && (
        <SimpleGrid cols={{ base: 2, md: 4 }} mb="xl">
          <Metric
            label="조치 대상"
            value={data.summary.total ?? 0}
            detail="현재 검색 조건 기준"
          />
          <Metric label="기한 초과" value={data.summary.overdue ?? 0} />
          <Metric label="담당자 미지정" value={data.summary.unassigned ?? 0} />
          <Metric
            label="KEV 목록 일치"
            value={data.summary.kev ?? 0}
            detail="반입한 위협 정보 기준"
          />
        </SimpleGrid>
      )}
      <Paper className="workflow-panel" mb="lg">
        <Stack>
          <div className="workflow-queue-views" aria-label="조치함 보기">
            {queueViews.map((item) => (
              <Button
                key={item.value}
                variant={state.view === item.value ? "filled" : "default"}
                aria-pressed={state.view === item.value}
                onClick={() =>
                  update({ view: item.value === "all" ? null : item.value })
                }
              >
                {item.label}
                {data
                  ? ` ${data.summary[item.value === "all" ? "total" : item.value] ?? 0}`
                  : ""}
              </Button>
            ))}
          </div>
          <Group align="flex-end">
            <TextInput
              flex={1}
              miw={200}
              label="발견 건 검색"
              placeholder="제목, 서비스, CVE, 구성요소"
              leftSection={<IconSearch size={18} />}
              value={state.query}
              onChange={(event) =>
                update({ q: event.currentTarget.value }, true)
              }
            />
            <Select
              miw={220}
              label="공통 원인 후보"
              placeholder="모든 후보"
              clearable
              value={state.group || null}
              onChange={(value) => update({ group: value })}
              data={(data?.groups || []).map((group) => ({
                value: group.id,
                label: `${group.cve || "CVE 미지정"} · ${group.component || "구성요소 미지정"} (${group.finding_count}건 / ${group.service_count}개 서비스)`,
              }))}
            />
            {(state.query || state.group || state.view !== "all") && (
              <Button
                variant="default"
                onClick={() => update({ q: null, group: null, view: null })}
              >
                조건 초기화
              </Button>
            )}
          </Group>
          <Text size="sm" c="dimmed">
            유효한 위험 수용, 오탐, 해결 항목은 제외합니다. 공통 원인 후보는
            같은 CVE와 구성요소를 가진 발견 건을 묶으며 개별 상태는 유지됩니다.
          </Text>
        </Stack>
      </Paper>
      <Paper className="data-panel">
        <LoadState loading={loading} error={error} reload={reload} />
        {data && !loading && !error && (
          <>
            {data.items.length ? (
              <div
                className="workflow-queue-scroll"
                role="region"
                aria-label="조치 대상 목록, 가로로 스크롤할 수 있습니다"
                tabIndex={0}
              >
                <Table
                  verticalSpacing="md"
                  horizontalSpacing="lg"
                  highlightOnHover
                >
                  <Table.Thead>
                    <Table.Tr>
                      {[
                        "발견 건 · 서비스",
                        "우선순위",
                        "심각도 · 상태",
                        "조치 기한",
                        "담당자",
                        "위협 정보",
                      ].map((name) => (
                        <Table.Th key={name} scope="col">
                          {name}
                        </Table.Th>
                      ))}
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {data.items.map((item) => (
                      <Table.Tr key={item.id}>
                        <Table.Td miw={260}>
                          <Link
                            className="workflow-link"
                            to={`/findings?item=${encodeURIComponent(item.id)}`}
                          >
                            {item.title}
                          </Link>
                          <Text size="sm" c="dimmed" mt={6}>
                            {item.service_name || "서비스"}
                            {item.cve ? ` · ${item.cve}` : ""}
                          </Text>
                          {item.component && (
                            <Text size="sm" c="dimmed">
                              {item.component}
                            </Text>
                          )}
                        </Table.Td>
                        <Table.Td>
                          <Priority item={item} />
                        </Table.Td>
                        <Table.Td>
                          <Stack gap="xs" align="flex-start">
                            <Status value={item.severity} />
                            <Status value={item.status} />
                          </Stack>
                        </Table.Td>
                        <Table.Td>
                          <Badge
                            variant="light"
                            color={
                              item.sla.state === "overdue"
                                ? "red"
                                : item.sla.state === "due_soon" ||
                                    item.sla.state === "invalid"
                                  ? "orange"
                                  : "gray"
                            }
                          >
                            {slaLabels[item.sla.state]}
                          </Badge>
                          <Text size="sm" mt={6}>
                            {fullDate(item.sla.due_date)}
                          </Text>
                          <Text size="xs" c="dimmed">
                            {item.sla.source === "policy"
                              ? "SLA 정책"
                              : item.sla.source === "manual"
                                ? "개별 기한"
                                : "기한 없음"}
                          </Text>
                        </Table.Td>
                        <Table.Td>{item.assignee || "미지정"}</Table.Td>
                        <Table.Td>
                          <Text size="sm">
                            KEV{" "}
                            {item.intelligence.kev == null
                              ? "미확인"
                              : item.intelligence.kev
                                ? "목록 일치"
                                : "목록 미일치"}
                          </Text>
                          <Text size="sm">
                            EPSS {percentText(item.intelligence.epss)}
                          </Text>
                          {item.intelligence.stale && (
                            <Badge color="orange" variant="light" mt={5}>
                              갱신 필요
                            </Badge>
                          )}
                          <Text size="xs" c="dimmed" mt={5}>
                            KEV {fullDate(item.intelligence.kev_source_date)}
                            <br />
                            EPSS {fullDate(item.intelligence.epss_source_date)}
                          </Text>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </div>
            ) : (
              <Empty
                title="현재 보기의 조치 대상이 없습니다"
                description="조건을 바꾸거나 발견 건에서 새 항목을 등록해 주세요. 모든 발견 건이 해결되었다는 의미는 아닙니다."
                action={
                  <Button component={Link} to="/findings" variant="light">
                    발견 건 열기
                  </Button>
                }
              />
            )}
            <div className="list-footer">
              <Text size="sm" role="status">
                {data.total.toLocaleString()}건 · 우선순위 높은 순 · 기준{" "}
                {dateText(data.as_of)}
              </Text>
              <Group>
                <Select
                  aria-label="페이지당 표시 수"
                  w={115}
                  value={String(state.size)}
                  allowDeselect={false}
                  data={[10, 25, 50, 100].map((size) => ({
                    value: String(size),
                    label: `${size}개씩`,
                  }))}
                  onChange={(value) => update({ size: value })}
                />
                {data.total > state.size && (
                  <Pagination
                    value={data.page}
                    total={Math.max(1, Math.ceil(data.total / state.size))}
                    siblings={0}
                    onChange={(page) => update({ page: String(page) })}
                    getItemProps={(page) => ({ "aria-label": `${page}페이지` })}
                  />
                )}
              </Group>
            </div>
          </>
        )}
      </Paper>
    </>
  );
}
export function FindingActivity({ findingId }: { findingId: string }) {
  const can = useCan();
  const [page, setPage] = useState(1),
    [body, setBody] = useState(""),
    [busy, setBusy] = useState(false),
    [formError, setFormError] = useState("");
  const result = useData<ActivityPage>(
    `/api/findings/${encodeURIComponent(findingId)}/activity?page=${page}&size=25`,
  );
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setFormError("");
    if (!body.trim()) {
      setFormError("댓글 내용을 입력하세요.");
      return;
    }
    if (new TextEncoder().encode(body).length > 16000) {
      setFormError("댓글은 UTF-8 기준 16,000바이트까지 입력할 수 있습니다.");
      return;
    }
    setBusy(true);
    try {
      await workflowAPI.comment(findingId, body);
      setBody("");
      setPage(1);
      await result.reload();
      success("댓글을 등록했습니다.");
    } catch (e) {
      setFormError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Stack>
      <Group justify="space-between">
        <Text fw={600}>활동 · 댓글</Text>
        <Button
          variant="subtle"
          onClick={result.reload}
          leftSection={<IconRefresh size={16} />}
        >
          새로고침
        </Button>
      </Group>
      {can("findings:write") && (
        <form onSubmit={submit}>
          <FormFeedback error={formError} />
          <Textarea
            label="댓글"
            placeholder="조치 상황과 검토 근거를 남겨 주세요."
            autosize
            minRows={3}
            maxRows={10}
            value={body}
            onChange={(event) => setBody(event.currentTarget.value)}
            disabled={busy}
          />
          <Text size="xs" c="dimmed" mt="xs">
            자격 증명이나 개인정보 원문을 입력하지 마세요. UTF-8 기준 최대
            16,000바이트입니다.
          </Text>
          <Group justify="flex-end" mt="sm">
            <Button
              type="submit"
              loading={busy}
              leftSection={<IconMessage size={16} />}
            >
              댓글 등록
            </Button>
          </Group>
        </form>
      )}
      <LoadState
        loading={result.loading}
        error={result.error}
        reload={result.reload}
      />
      {!result.loading && !result.error && (
        <>
          {!result.data?.items.length ? (
            <Text c="dimmed" p="md">
              아직 기록된 활동이 없습니다.
            </Text>
          ) : (
            result.data.items.map((item) => (
              <article key={item.id} className="workflow-activity">
                <Group justify="space-between">
                  <Badge variant="light">
                    {
                      {
                        comment: "댓글",
                        audit: "변경 이력",
                        observation: "진단 관측",
                        verification: "검증",
                      }[item.kind]
                    }
                  </Badge>
                  <Text size="xs" c="dimmed">
                    {dateText(item.created_at)}
                  </Text>
                </Group>
                <Text fw={600} size="sm" mt="sm">
                  {item.author_name || "시스템"}
                </Text>
                <Text className="workflow-pre" mt="xs">
                  {item.body || item.summary}
                </Text>
              </article>
            ))
          )}
          {result.data && result.data.total > result.data.page_size && (
            <Pagination
              total={Math.ceil(result.data.total / result.data.page_size)}
              value={page}
              onChange={setPage}
              siblings={0}
            />
          )}
        </>
      )}
    </Stack>
  );
}
