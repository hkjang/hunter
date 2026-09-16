import { useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { useLocation } from "react-router-dom";
import {
  Alert,
  Badge,
  Button,
  Code,
  Divider,
  Group,
  Modal,
  Paper,
  Select,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import {
  IconCheck,
  IconEye,
  IconPlayerStop,
  IconPlus,
  IconRefresh,
  IconShieldCheck,
  IconTrash,
} from "@tabler/icons-react";
import { api, APIError, fullDate, useData } from "./api";
import { LoadState } from "./components";
import { changed } from "./form-state";
import { FormFeedback, SaveStatus } from "./form-feedback";
import {
  emptyTracking,
  trackingFrameURL,
  trackingPage,
  trackingSnippetOrigins,
  trackingStatus,
  trackingViolation,
  trackingViolationOrigin,
  validateTrackingDraft,
  type TrackingConfiguration,
  type TrackingPage,
  type TrackingValidation,
  type TrackingViolation,
  type TrackingViolationReport,
} from "./tracking-state";
import "./tracking.css";

type FrameStatus = "loading" | "ready" | "error" | "blocked" | "timeout";
const frameLabels: Record<FrameStatus, string> = {
  loading: "격리 프레임 연결 중",
  ready: "격리 프레임 준비됨",
  error: "스크립트 오류",
  blocked: "보안 정책에서 요청 차단",
  timeout: "프레임 응답 확인 필요",
};

function TrackingFrame({
  url,
  page,
  onStatus,
  onViolation,
}: {
  url: string;
  page: TrackingPage;
  onStatus?: (status: FrameStatus) => void;
  onViolation?: (report: TrackingViolationReport) => void;
}) {
  const frame = useRef<HTMLIFrameElement>(null);
  const currentPage = useRef(page);
  currentPage.current = page;
  const notified = useRef<TrackingPage | null>(null);
  const callback = useRef(onStatus);
  callback.current = onStatus;
  const violationCallback = useRef(onViolation);
  violationCallback.current = onViolation;
  const ready = useRef(false);
  useEffect(() => {
    ready.current = false;
    notified.current = null;
    let failed = false;
    callback.current?.("loading");
    function receive(event: MessageEvent) {
      // sandbox has an opaque origin; validate the exact iframe window instead.
      if (!frame.current || event.source !== frame.current.contentWindow)
        return;
      const violation = trackingViolation(event.data);
      if (violation) {
        violationCallback.current?.(violation);
        return;
      }
      const status = trackingStatus(event.data);
      if (!status) return;
      if (status === "error" || status === "blocked") failed = true;
      if (status !== "ready" || !failed) callback.current?.(status);
      if (status === "ready") {
        ready.current = true;
        const value = currentPage.current;
        if (notified.current !== value) {
          frame.current.contentWindow?.postMessage(
            { type: "hunter:pageview", page: value },
            "*",
          );
          notified.current = value;
        }
      }
    }
    window.addEventListener("message", receive);
    const timer = window.setTimeout(() => {
      if (!ready.current && !failed) callback.current?.("timeout");
    }, 15000);
    return () => {
      window.removeEventListener("message", receive);
      window.clearTimeout(timer);
    };
  }, [url]);
  useEffect(() => {
    if (ready.current && notified.current !== page) {
      frame.current?.contentWindow?.postMessage(
        { type: "hunter:pageview", page },
        "*",
      );
      notified.current = page;
    }
  }, [page]);
  return (
    <iframe
      ref={frame}
      src={url}
      sandbox="allow-scripts"
      referrerPolicy="no-referrer"
      title="방문 추적 격리 프레임"
      className="tracking-frame"
      aria-hidden="true"
      tabIndex={-1}
    />
  );
}

export function TrackingRuntime() {
  const { pathname } = useLocation();
  const page = useMemo(() => trackingPage(pathname), [pathname]);
  const { data, error, reload } = useData<{
    enabled: boolean;
    revision: number;
    frame_url: string;
  }>(page ? "/api/tracking/config" : null);
  useEffect(() => {
    if (!page) return;
    const refresh = () => {
      if (!document.hidden) void reload();
    };
    const timer = window.setInterval(refresh, 30000);
    window.addEventListener("hunter:tracking-changed", refresh);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("hunter:tracking-changed", refresh);
    };
  }, [!!page, reload]);
  const url = trackingFrameURL(data?.frame_url);
  const pending = useRef<(TrackingViolationReport & { page: string })[]>([]);
  const flush = useRef<number | undefined>(undefined);
  const report = (violation: TrackingViolationReport) => {
    const key = violation.directive + " " + violation.blocked_uri;
    if (!page || relayed.has(key) || relayed.size >= 100) return;
    relayed.add(key);
    pending.current.push({ ...violation, page: page.path });
    // Each blocked origin repeats on every page; one short batch per burst is enough.
    if (flush.current === undefined)
      flush.current = window.setTimeout(() => {
        flush.current = undefined;
        const violations = pending.current.splice(0, 100);
        void api("/api/tracking/violations", {
          method: "POST",
          body: JSON.stringify({ violations }),
        }).catch(() => undefined);
      }, 2000);
  };
  if (!page || !data?.enabled || error || !url) return null;
  return (
    <TrackingFrame
      key={data.revision}
      url={url}
      page={page}
      onViolation={report}
    />
  );
}
// Blocked origin·directive pairs already relayed to the server by this document.
const relayed = new Set<string>();

type SettingsProps = {
  active: boolean;
  saveRef: RefObject<(() => Promise<boolean>) | null>;
  onDirtyChange: (value: boolean) => void;
  onBusyChange: (value: boolean) => void;
};
export function TrackingSettings({
  active,
  saveRef,
  onDirtyChange,
  onBusyChange,
}: SettingsProps) {
  const {
    data,
    loading,
    error: loadError,
    reload,
    setData,
  } = useData<TrackingConfiguration>("/api/admin/tracking");
  const [draft, setDraft] = useState<TrackingConfiguration>(emptyTracking);
  const [originText, setOriginText] = useState("");
  const baseline = useRef<TrackingConfiguration>(emptyTracking);
  const initialized = useRef(false);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [savedAt, setSavedAt] = useState<string>(),
    [conflict, setConflict] = useState(false);
  const [replaceOpen, setReplaceOpen] = useState(false);
  const [preview, setPreview] = useState<TrackingValidation | null>(null);
  const [status, setStatus] = useState<FrameStatus>("loading");
  const [previewPath, setPreviewPath] = useState("/services");
  const previewPage = useMemo(() => trackingPage(previewPath)!, [previewPath]);
  const [previewViolations, setPreviewViolations] = useState<
    TrackingViolationReport[]
  >([]);
  const violations = useData<{
    violations: TrackingViolation[];
    limit: number;
  }>("/api/admin/tracking/violations");
  const [clearing, setClearing] = useState(false);
  const effective = useMemo(
    () => ({
      ...draft,
      allowed_origins: [
        ...new Set(
          originText
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter(Boolean),
        ),
      ],
    }),
    [draft, originText],
  );
  const dirty = changed(baseline.current, effective);
  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);
  useEffect(() => {
    onBusyChange(busy);
  }, [busy, onBusyChange]);
  useEffect(() => {
    if (data && !initialized.current) {
      initialized.current = true;
      baseline.current = data;
      setDraft(data);
      setOriginText(data.allowed_origins.join("\n"));
    }
  }, [data]);
  useEffect(() => {
    if (!active) setPreview(null);
  }, [active]);
  const originLines = originText
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  function addOrigin(...origins: string[]) {
    const missing = origins.filter((o) => !originLines.includes(o));
    if (!missing.length) return;
    setOriginText([...originLines, ...missing].join("\n"));
    setPreview(null);
    setError("");
  }
  // Addresses written in the snippet that the frame policy would still block.
  const suggestedOrigins = trackingSnippetOrigins(
    draft.script,
    window.location.origin,
  ).filter((origin) => !originLines.includes(origin));
  async function clearViolations() {
    setClearing(true);
    try {
      await api("/api/admin/tracking/violations", { method: "DELETE" });
      await violations.reload();
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "차단 기록을 지우지 못했습니다.",
      );
    } finally {
      setClearing(false);
    }
  }
  function check() {
    const issues = validateTrackingDraft(effective, window.location.origin);
    if (issues.length) {
      setError(issues.join(" "));
      return false;
    }
    setError("");
    return true;
  }
  async function save(): Promise<boolean> {
    if (busy || !check()) return false;
    setBusy(true);
    try {
      const value = await api<TrackingConfiguration>("/api/admin/tracking", {
        method: "PUT",
        body: JSON.stringify(effective),
      });
      baseline.current = value;
      setData(value);
      setDraft(value);
      setOriginText(value.allowed_origins.join("\n"));
      setConflict(false);
      setPreview(null);
      setSavedAt(value.updated_at || new Date().toISOString());
      window.dispatchEvent(new Event("hunter:tracking-changed"));
      return true;
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "방문 추적 설정을 저장하지 못했습니다.",
      );
      setConflict(e instanceof APIError && e.status === 409);
      return false;
    } finally {
      setBusy(false);
    }
  }
  saveRef.current = save;
  async function test() {
    if (busy || !check()) return;
    setBusy(true);
    setPreview(null);
    setPreviewViolations([]);
    setStatus("loading");
    try {
      const value = await api<TrackingValidation>("/api/admin/tracking/test", {
        method: "POST",
        body: JSON.stringify(effective),
      });
      if (!trackingFrameURL(value.preview_url, true))
        throw new Error("미리보기 주소를 확인할 수 없습니다.");
      setPreview(value);
    } catch (e) {
      setError(e instanceof Error ? e.message : "설정을 검증하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }
  async function replaceWithLatest() {
    setReplaceOpen(false);
    setBusy(true);
    try {
      const value = await api<TrackingConfiguration>("/api/admin/tracking");
      baseline.current = value;
      setData(value);
      setDraft(value);
      setOriginText(value.allowed_origins.join("\n"));
      setConflict(false);
      setError("");
      setPreview(null);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "최신 설정을 불러오지 못했습니다.",
      );
    } finally {
      setBusy(false);
    }
  }
  const previewURL = trackingFrameURL(preview?.preview_url, true);
  return (
    <Paper className="settings-panel tracking-settings" hidden={!active}>
      <div className="settings-panel-head">
        <span className="settings-section-icon">
          <IconShieldCheck />
        </span>
        <div>
          <h2>방문 추적</h2>
          <p>필요한 방문 통계 코드를 격리된 환경에서 실행합니다.</p>
        </div>
      </div>
      <LoadState loading={loading} error={loadError} reload={reload} />
      {!loading && !loadError && data && (
        <>
          <FormFeedback error={error} />
          {conflict && (
            <Alert
              color="orange"
              title="다른 관리자가 설정을 변경했습니다"
              mb="lg"
            >
              현재 입력은 그대로 유지했습니다. 최신 설정을 불러오려면 현재
              초안을 버릴지 먼저 확인합니다.
              <Button
                variant="light"
                color="orange"
                mt="sm"
                onClick={() => setReplaceOpen(true)}
                disabled={busy}
              >
                최신 설정 불러오기
              </Button>
            </Alert>
          )}
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void save();
            }}
          >
            <fieldset className="form-fields" disabled={busy}>
              <Stack gap="lg">
                <Switch
                  label="방문 추적 사용"
                  description="기본값은 사용 안 함입니다. 저장하면 허용된 일반 화면에만 적용합니다."
                  checked={draft.enabled}
                  onChange={(event) =>
                    setDraft({ ...draft, enabled: event.currentTarget.checked })
                  }
                />
                <TextInput
                  label="추적 설정 이름"
                  required
                  value={draft.name}
                  onChange={(event) =>
                    setDraft({ ...draft, name: event.currentTarget.value })
                  }
                  description="최대 100자. 통계 서비스 이름을 적어 주세요."
                />
                <Textarea
                  label="추적 스크립트"
                  value={draft.script}
                  onChange={(event) => {
                    setDraft({ ...draft, script: event.currentTarget.value });
                    setPreview(null);
                  }}
                  minRows={10}
                  maxRows={22}
                  autosize
                  spellCheck={false}
                  description="최대 32KiB. JavaScript 또는 script 태그를 붙여 넣으세요. noscript·iframe·HTML 배너는 지원하지 않습니다. 비밀 API 키와 사용자 인증정보를 넣지 마세요."
                  className="tracking-code"
                />
                <Text
                  size="sm"
                  c={
                    new TextEncoder().encode(draft.script).length > 32768
                      ? "red"
                      : "dimmed"
                  }
                >
                  {new TextEncoder()
                    .encode(draft.script)
                    .length.toLocaleString()}{" "}
                  / 32,768바이트
                </Text>
                <Textarea
                  label="허용된 외부 원점"
                  value={originText}
                  onChange={(event) => {
                    setOriginText(event.currentTarget.value);
                    setPreview(null);
                  }}
                  minRows={3}
                  autosize
                  placeholder="https://analytics.internal\nhttps://collector.internal:8443"
                  description="한 줄에 하나씩 최대 10개·총 1,536바이트. 프로토콜과 호스트·포트만 입력하세요. Hunter 자체 주소, 경로, 와일드카드는 허용되지 않습니다. 스크립트와 수집 주소를 모두 등록하세요."
                />
                {suggestedOrigins.length > 0 && (
                  <Alert
                    color="blue"
                    title="스크립트에 적힌 주소가 허용 목록에 없습니다"
                    className="tracking-suggested-origins"
                  >
                    <Text size="sm">
                      아래 원점은 추적 스크립트에서 찾은 http(s) 주소입니다.
                      수집기·스크립트 주소가 맞는지 확인한 뒤 추가하세요.
                      허용하지 않으면 격리 프레임의 보안 정책이 해당 요청을
                      차단합니다.
                    </Text>
                    <Group gap="xs" mt="sm">
                      {suggestedOrigins.map((origin) => (
                        <Button
                          key={origin}
                          size="compact-xs"
                          variant="light"
                          leftSection={<IconPlus size={14} />}
                          onClick={() => addOrigin(origin)}
                          disabled={busy}
                        >
                          {origin}
                        </Button>
                      ))}
                      {suggestedOrigins.length > 1 && (
                        <Button
                          size="compact-xs"
                          variant="filled"
                          onClick={() => addOrigin(...suggestedOrigins)}
                          disabled={busy}
                        >
                          모두 추가
                        </Button>
                      )}
                    </Group>
                  </Alert>
                )}
                <Alert
                  color="teal"
                  title="화면과 계정 정보의 경계를 유지합니다"
                >
                  <Text size="sm">
                    스크립트는 부모 화면의 DOM·쿠키·저장소에 접근할 수 없는
                    프레임에서 실행합니다. 관리자·개인화·로그인 화면은 추적하지
                    않으며, 일반 화면에서도 고정 경로 템플릿과 메뉴명만
                    전달합니다.
                  </Text>
                  <Text size="sm" mt="sm">
                    사용자·대상 ID, 검색 조건, URL 해시, 증거와 AI 답변은
                    전달하지 않습니다. 기존 통계 코드는 문서 주소 자동 수집 대신
                    아래 pageview 이벤트에 맞게 연결해야 합니다.
                  </Text>
                  <Code
                    block
                    mt="sm"
                  >{`window.addEventListener('hunter:pageview', (event) => {\n  const { path, title } = event.detail;\n  // 허용한 수집 주소로 고정 경로와 메뉴명만 전달하세요.\n});`}</Code>
                </Alert>
              </Stack>
            </fieldset>
            <Divider my="xl" />
            <Group className="form-save-actions" justify="space-between">
              <SaveStatus dirty={dirty} saving={busy} savedAt={savedAt} />
              <Group>
                <Button
                  type="button"
                  variant="default"
                  leftSection={<IconEye size={18} />}
                  onClick={() => void test()}
                  disabled={busy}
                >
                  검증 · 격리 미리보기
                </Button>
                <Button
                  type="submit"
                  loading={busy}
                  leftSection={<IconCheck size={18} />}
                >
                  설정 저장
                </Button>
              </Group>
            </Group>
          </form>
          <Text c="dimmed" size="sm" mt="md">
            저장 버전 {data.revision} ·{" "}
            {data.updated_at ? fullDate(data.updated_at) : "아직 저장하지 않음"}
            . 사용 중인 화면은 변경 사항을 최대 30초 내에 확인합니다.
          </Text>
          <Paper withBorder p="lg" mt="xl" className="tracking-violations">
            <Group justify="space-between">
              <Text fw={700}>보안 정책에서 차단된 출처</Text>
              <Group gap="xs">
                <Button
                  variant="subtle"
                  size="compact-sm"
                  leftSection={<IconRefresh size={16} />}
                  onClick={() => void violations.reload()}
                  disabled={violations.loading || clearing}
                >
                  새로 고침
                </Button>
                <Button
                  variant="subtle"
                  color="red"
                  size="compact-sm"
                  leftSection={<IconTrash size={16} />}
                  onClick={() => void clearViolations()}
                  disabled={clearing || !violations.data?.violations.length}
                >
                  기록 지우기
                </Button>
              </Group>
            </Group>
            <Text size="sm" c="dimmed" mt="sm">
              격리 프레임이 허용 원점 밖으로 보내려다 차단된 요청의 출처와
              지시어입니다. 이 서버 인스턴스의 메모리에 최대{" "}
              {violations.data?.limit ?? 100}개만 보관하며 재시작하면
              사라집니다. 로그인한 사용자 화면이 전달한 내용이므로 수집기 주소가
              맞는지 확인한 뒤 허용 목록에 추가하고 저장하세요.
            </Text>
            <LoadState
              loading={violations.loading}
              error={violations.error}
              reload={violations.reload}
            />
            {violations.data && violations.data.violations.length === 0 && (
              <Text size="sm" mt="md">
                기록된 차단이 없습니다.
              </Text>
            )}
            {violations.data && violations.data.violations.length > 0 && (
              <Stack gap="xs" mt="md">
                {violations.data.violations.map((item) => (
                  <Group
                    key={item.directive + " " + item.origin}
                    justify="space-between"
                    align="flex-start"
                    wrap="nowrap"
                  >
                    <div>
                      <Group gap="xs">
                        <Code>{item.directive}</Code>
                        <Text size="sm" fw={500}>
                          {item.origin}
                        </Text>
                      </Group>
                      <Text size="xs" c="dimmed">
                        {item.count}회 · 최근 {fullDate(item.last_seen)}
                        {item.page ? ` · ${item.page}` : ""}
                      </Text>
                    </div>
                    {item.allowed || originLines.includes(item.origin) ? (
                      <Badge color="teal" variant="light">
                        {item.allowed ? "허용됨" : "저장 대기"}
                      </Badge>
                    ) : (
                      <Button
                        size="compact-xs"
                        variant="light"
                        leftSection={<IconPlus size={14} />}
                        onClick={() => addOrigin(item.origin)}
                        disabled={busy}
                      >
                        허용 목록에 추가
                      </Button>
                    )}
                  </Group>
                ))}
              </Stack>
            )}
          </Paper>
          {preview && (
            <Paper withBorder p="lg" mt="xl" className="tracking-preview">
              <Group justify="space-between">
                <Text fw={700}>격리 미리보기</Text>
                <Button
                  variant="subtle"
                  leftSection={<IconPlayerStop size={16} />}
                  onClick={() => setPreview(null)}
                >
                  미리보기 중지
                </Button>
              </Group>
              <Text size="sm" c="dimmed" mt="sm">
                저장 여부와 관계없이 현재 브라우저에서 코드가 실행됩니다. 허용한
                수집 서버로 합성 방문 이벤트가 전송될 수 있습니다. 실제 통계
                접수는 해당 서버에서도 확인하세요.
              </Text>
              <Stack gap="xs" mt="md">
                {preview.checks.map((check) => (
                  <Text
                    size="sm"
                    key={check.name}
                    c={check.ok ? "teal.8" : "red.8"}
                  >
                    {check.ok ? "✓" : "!"} {check.message}
                  </Text>
                ))}
              </Stack>
              <Group mt="lg" align="end">
                <Select
                  label="전달할 합성 페이지"
                  data={[
                    { value: "/services", label: "서비스 자산" },
                    {
                      value: "/agents/example",
                      label: "에이전트 진단 상세 · ID 제외",
                    },
                  ]}
                  value={previewPath}
                  onChange={(value) => {
                    if (value) setPreviewPath(value);
                  }}
                />
                <Badge
                  color={
                    status === "ready"
                      ? "teal"
                      : status === "loading"
                        ? "gray"
                        : "orange"
                  }
                  variant="light"
                >
                  {frameLabels[status]}
                </Badge>
              </Group>
              <Code block mt="md">
                {JSON.stringify(
                  { type: "hunter:pageview", page: previewPage },
                  null,
                  2,
                )}
              </Code>
              {["error", "blocked", "timeout"].includes(status) && (
                <Alert color="orange" mt="md" title="연동 결과를 확인하세요">
                  스크립트 문법과 허용 원점, 브라우저 네트워크 정책을
                  확인하세요. 이 오류는 Hunter 업무 기능을 중지하지 않습니다.
                  수정한 뒤 미리보기를 다시 시작할 수 있습니다.
                  {previewViolations.length > 0 && (
                    <Stack gap="xs" mt="sm">
                      {previewViolations.map((item) => {
                        const origin = trackingViolationOrigin(
                          item.blocked_uri,
                        );
                        return (
                          <Group
                            key={item.directive + " " + item.blocked_uri}
                            gap="xs"
                          >
                            <Code>{item.directive}</Code>
                            <Text size="sm">{origin ?? item.blocked_uri}</Text>
                            {origin && !originLines.includes(origin) && (
                              <Button
                                size="compact-xs"
                                variant="light"
                                leftSection={<IconPlus size={14} />}
                                onClick={() => addOrigin(origin)}
                              >
                                허용 목록에 추가
                              </Button>
                            )}
                          </Group>
                        );
                      })}
                    </Stack>
                  )}
                </Alert>
              )}
              {active && previewURL && (
                <TrackingFrame
                  key={previewURL}
                  url={previewURL}
                  page={previewPage}
                  onStatus={setStatus}
                  onViolation={(item) =>
                    setPreviewViolations((current) =>
                      current.some(
                        (v) =>
                          v.directive === item.directive &&
                          v.blocked_uri === item.blocked_uri,
                      ) || current.length >= 100
                        ? current
                        : [...current, item],
                    )
                  }
                />
              )}
            </Paper>
          )}
        </>
      )}
      <Modal
        opened={replaceOpen}
        onClose={() => setReplaceOpen(false)}
        title="현재 초안을 최신 설정으로 바꿀까요?"
      >
        <Text>
          작성 중인 스크립트와 허용 주소가 최신 저장 값으로 바뀝니다. 필요한
          입력을 보관한 뒤 불러오세요.
        </Text>
        <Group justify="flex-end" mt="xl">
          <Button variant="default" onClick={() => setReplaceOpen(false)}>
            계속 수정
          </Button>
          <Button
            leftSection={<IconRefresh size={17} />}
            onClick={() => void replaceWithLatest()}
          >
            최신 설정 불러오기
          </Button>
        </Group>
      </Modal>
    </Paper>
  );
}
