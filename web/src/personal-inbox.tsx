import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  Pagination,
  Paper,
  Select,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import {
  IconBell,
  IconCheck,
  IconExternalLink,
  IconRefresh,
  IconSearch,
} from "@tabler/icons-react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { dateText, success, useData } from "./api";
import { Empty, LoadState, PageHeader } from "./components";
import {
  automationAPI,
  type PersonalNotification,
  type PersonalNotificationPage,
} from "./automation-api";
import { AutomationStatus } from "./automation-ui";
import {
  boundedPageQuery,
  inboxAcknowledgementState,
} from "./automation-state";
import { notificationEvents } from "./notification-state";
import "./automation.css";
const eventName = (value: string) =>
  notificationEvents.find((row) => row.value === value)?.label || value;
export function PersonalInboxPage() {
  const [params, setParams] = useSearchParams(),
    location = useLocation();
  const query = boundedPageQuery(
      params,
      { status: ["all", "pending", "acknowledged"] },
      { status: "pending" },
    ),
    status = query.get("status") || "pending";
  const data = useData<PersonalNotificationPage>(
      "/api/my-notifications?" + query.toString(),
    ),
    [selected, setSelected] = useState<PersonalNotification | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const search = params.get("q") || "",
    sort = params.get("sort") || "created_desc";
  const rows = useMemo(() => {
    const words = search
      .trim()
      .toLocaleLowerCase("ko-KR")
      .split(/\s+/)
      .filter(Boolean);
    return [...(data.data?.items || [])]
      .filter((row) =>
        words.every((word) =>
          [row.subject, row.body, eventName(row.event_type)]
            .join(" ")
            .toLocaleLowerCase("ko-KR")
            .includes(word),
        ),
      )
      .sort((a, b) =>
        sort === "created_asc"
          ? Date.parse(a.created_at) - Date.parse(b.created_at)
          : sort === "due_asc"
            ? (Date.parse(a.ack_due_at || "") || Infinity) -
              (Date.parse(b.ack_due_at || "") || Infinity)
            : Date.parse(b.created_at) - Date.parse(a.created_at),
      );
  }, [data.data, search, sort]);
  function update(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key === "status" || key === "size") next.delete("page");
    setParams(next, { preventScrollReset: true, state: location.state });
  }
  async function acknowledge() {
    if (!selected || busy) return;
    setBusy(true);
    setError("");
    try {
      await automationAPI.acknowledge(selected.id);
      success("업무 알림의 확인을 기록했습니다.");
      setSelected(null);
      await data.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
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
    <>
      <PageHeader
        eyebrow="MY WORKSPACE"
        title="내 업무 알림"
        description="나에게 지정된 업무 내용을 확인하고 확인 완료를 명시적으로 기록합니다."
        action={
          <Button
            variant="default"
            leftSection={<IconRefresh size={16} />}
            onClick={data.reload}
          >
            새로고침
          </Button>
        }
      />
      <Alert color="teal" mb="lg">
        이 화면에는 현재 접근할 수 있는 서비스의 내 알림만 표시합니다. 업무
        확인은 발송 배달 확인·취약점 해결·팀장 승인과 별도로 기록됩니다.
      </Alert>
      <Paper withBorder radius="lg" className="automation-section" mb="lg">
        <Group mb="md" wrap="wrap">
          <Select
            aria-label="업무 알림 상태"
            label="확인 상태"
            data={[
              { value: "pending", label: "확인 대기" },
              { value: "acknowledged", label: "확인 완료" },
              { value: "all", label: "전체" },
            ]}
            value={status}
            onChange={(value) => update("status", value || "pending")}
          />
          <TextInput
            label="현재 페이지 검색"
            leftSection={<IconSearch size={17} />}
            value={search}
            onChange={(e) => update("q", e.currentTarget.value)}
            placeholder="제목·본문·이벤트"
            style={{ flex: "1 1 240px" }}
          />
          <Select
            label="현재 페이지 정렬"
            data={[
              { value: "created_desc", label: "최근 알림 먼저" },
              { value: "created_asc", label: "오래된 알림 먼저" },
              { value: "due_asc", label: "확인 기한 빠른 순" },
            ]}
            value={sort}
            onChange={(value) => update("sort", value || "created_desc")}
          />
        </Group>
        <Text size="sm" c="dimmed">
          선택한 상태 전체 {total.toLocaleString()}건 · 현재 페이지{" "}
          {rows.length}건 표시. 검색과 정렬은 이 페이지에서 조회한 알림에
          적용합니다.
        </Text>
      </Paper>
      <LoadState
        loading={data.loading}
        error={data.error}
        reload={data.reload}
      />
      {!data.loading && !data.error && (
        <>
          <Stack gap="md">
            {rows.map((row) => (
              <Paper
                key={row.id}
                withBorder
                radius="lg"
                className="automation-section"
              >
                <Group justify="space-between" align="flex-start">
                  <div>
                    <Group gap="sm" mb="sm">
                      <AutomationStatus
                        status={inboxAcknowledgementState(row)}
                      />
                      <Badge variant="light" color="gray">
                        {eventName(row.event_type)}
                      </Badge>
                    </Group>
                    <Text fw={700} size="lg">
                      {row.subject}
                    </Text>
                  </div>
                  <Text c="dimmed" size="sm">
                    {dateText(row.created_at)}
                  </Text>
                </Group>
                <div className="automation-inbox-message">
                  {row.body ||
                    "보존 정책에 따라 본문이 정리되었거나 본문이 없습니다."}
                </div>
                <Group justify="space-between" align="flex-end">
                  <Stack gap={3}>
                    <Text size="sm" c="dimmed">
                      확인 기한: {dateText(row.ack_due_at)}
                    </Text>
                    {row.acknowledged_at && (
                      <Text size="sm" c="teal">
                        확인 완료: {dateText(row.acknowledged_at)}
                      </Text>
                    )}
                  </Stack>
                  <Group>
                    {resourcePath(row) && (
                      <Button
                        component={Link}
                        to={resourcePath(row)!}
                        variant="default"
                        leftSection={<IconExternalLink size={16} />}
                      >
                        업무 내용 열기
                      </Button>
                    )}
                    {row.can_ack && (
                      <Button
                        leftSection={<IconCheck size={16} />}
                        onClick={() => {
                          setSelected(row);
                          setError("");
                        }}
                      >
                        업무 확인
                      </Button>
                    )}
                  </Group>
                </Group>
              </Paper>
            ))}
          </Stack>
          {!rows.length && (
            <Empty
              title={
                search
                  ? "검색 조건에 맞는 알림이 없습니다"
                  : "표시할 업무 알림이 없습니다"
              }
              description={
                search
                  ? "현재 페이지 검색어를 지우거나 다른 페이지를 확인하세요."
                  : "관리자가 동적 수신자와 업무 확인 알림을 설정하면 내게 지정된 알림을 이곳에서 확인할 수 있습니다."
              }
              icon={<IconBell size={28} />}
            />
          )}
          <Group justify="space-between" className="automation-footer" mt="lg">
            <Text size="sm">
              {data.data?.page || 1} / {pages}페이지
            </Text>
            <Group>
              <Select
                aria-label="업무 알림 표시 수"
                w={110}
                data={["10", "25", "50", "100"].map((value) => ({
                  value,
                  label: value + "개씩",
                }))}
                value={query.get("size")}
                onChange={(value) => update("size", value || "25")}
              />
              <Pagination
                total={pages}
                value={Math.min(data.data?.page || 1, pages)}
                onChange={(value) => update("page", String(value))}
              />
            </Group>
          </Group>
        </>
      )}
      <Modal
        opened={!!selected}
        onClose={() => {
          if (!busy) setSelected(null);
        }}
        title="업무 내용을 확인했나요?"
        zIndex={350}
        withCloseButton={!busy}
        closeOnEscape={!busy}
        closeOnClickOutside={!busy}
      >
        <Stack>
          <Text fw={700}>{selected?.subject}</Text>
          <Text>
            현재 사용자와 확인 시각을 기록합니다. 발견 건이나 승인 상태는 바뀌지
            않습니다.
          </Text>
          {error && <Alert color="red">{error}</Alert>}
          <Group justify="flex-end">
            <Button
              variant="default"
              disabled={busy}
              onClick={() => setSelected(null)}
            >
              닫기
            </Button>
            <Button loading={busy} onClick={acknowledge}>
              확인 완료 기록
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
function resourcePath(row: PersonalNotification) {
  if (!row.entity_id) return null;
  if (row.event_type.startsWith("finding."))
    return "/findings?item=" + encodeURIComponent(row.entity_id);
  if (row.event_type.startsWith("scan."))
    return "/scans?item=" + encodeURIComponent(row.entity_id);
  if (row.event_type.startsWith("approval."))
    return "/approvals?item=" + encodeURIComponent(row.entity_id);
  return null;
}
