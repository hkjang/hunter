import { useState } from "react";
import {
  Alert,
  Button,
  Group,
  Menu,
  Modal,
  Stack,
  Text,
  Textarea,
} from "@mantine/core";
import {
  IconDownload,
  IconMessagePlus,
  IconPlayerPause,
  IconPlayerPlay,
  IconSend,
} from "@tabler/icons-react";
import {
  api,
  APIError,
  dateText,
  showError,
  success,
  useCan,
  useData,
} from "./api";
import {
  handoffClaimRequest,
  handoffOpenURL,
  type HandoffClaim,
  type HandoffTargets,
} from "./handoff-state";
import { useUnsavedChanges } from "./form-feedback";
import type { AgentRun } from "./use-agent-run";
import {
  agentControlPayload,
  agentControlRevision,
  agentInputBytes,
  agentReportPath,
  type AgentControlAction,
} from "./agent-control-state";
const titles: Record<AgentControlAction, string> = {
  pause: "일시중지 요청",
  resume: "같은 실행 재개",
  input: "추가 지시 저장",
};
export function AgentRunControls({
  run,
  onUpdated,
}: {
  run: AgentRun;
  onUpdated: (action: AgentControlAction) => Promise<void>;
}) {
  const can = useCan(),
    [action, setAction] = useState<AgentControlAction | null>(null);
  const allowed = run.allowed_actions || [];
  return (
    <>
      <Group gap="sm" className="agent-control-actions">
        {can("agents:write") && can("ai:use") && allowed.includes("pause") && (
          <Button
            variant="light"
            color="orange"
            leftSection={<IconPlayerPause size={16} />}
            disabled={!!run.pause_requested}
            onClick={() => setAction("pause")}
          >
            일시중지
          </Button>
        )}
        {can("agents:write") && can("ai:use") && allowed.includes("input") && (
          <Button
            variant="default"
            leftSection={<IconMessagePlus size={17} />}
            onClick={() => setAction("input")}
          >
            추가 지시
          </Button>
        )}
        {can("agents:write") && can("ai:use") && allowed.includes("resume") && (
          <Button
            leftSection={<IconPlayerPlay size={17} />}
            onClick={() => setAction("resume")}
          >
            같은 실행 재개
          </Button>
        )}
      </Group>
      {action && (
        <ControlEditor
          key={run.id + action}
          run={run}
          action={action}
          onClose={() => setAction(null)}
          onUpdated={onUpdated}
        />
      )}
    </>
  );
}
function ControlEditor({
  run,
  action,
  onClose,
  onUpdated,
}: {
  run: AgentRun;
  action: AgentControlAction;
  onClose: () => void;
  onUpdated: (action: AgentControlAction) => Promise<void>;
}) {
  const [message, setMessage] = useState(""),
    [revision, setRevision] = useState(agentControlRevision(run)),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [conflict, setConflict] = useState(false),
    [latest, setLatest] = useState<AgentRun | null>(null),
    [checking, setChecking] = useState(false),
    [discard, setDiscard] = useState(false);
  const dirty = action === "input" && !!message,
    bytes = agentInputBytes(message);
  useUnsavedChanges(dirty || busy);
  function close() {
    if (busy) return;
    if (dirty) setDiscard(true);
    else onClose();
  }
  async function submit() {
    if (busy) return;
    setError("");
    setConflict(false);
    try {
      const body = agentControlPayload(action, revision, message);
      setBusy(true);
      await api(`/api/agent-runs/${encodeURIComponent(run.id)}/${action}`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      success(
        action === "input"
          ? "추가 지시를 저장했습니다. 대기 중인 실행은 재개 버튼으로 이어가세요."
          : action === "pause"
            ? "일시중지를 요청했습니다. 다음 안전 경계의 상태를 확인하세요."
            : "같은 실행의 재개를 요청했습니다.",
      );
      await onUpdated(action);
      onClose();
    } catch (e) {
      setError((e as Error).message);
      setConflict(e instanceof APIError && e.status === 409);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Modal
        opened
        title={titles[action]}
        size="lg"
        zIndex={320}
        onClose={close}
        closeOnEscape={!busy}
        closeOnClickOutside={!busy}
        withCloseButton={!busy}
      >
        <form
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Stack gap="lg">
            <Text fw={600}>{run.title || "에이전트 진단"}</Text>
            <Text>
              {action === "input"
                ? "추가 지시는 현재 실행에 저장되며 다음 안전 경계에서 반영됩니다. 대기 상태에서 저장해도 자동으로 재개하지 않습니다."
                : action === "pause"
                  ? "진행 중인 요청의 안전 경계에서 일시중지를 적용합니다. 실제 상태가 일시중지로 바뀌었는지 확인하세요."
                  : "저장된 근거와 추가 지시를 사용하여 같은 실행 ID로 작업을 이어갑니다. 현재 권한·허용 범위·모델 연결을 다시 확인합니다."}
            </Text>
            {error && (
              <Alert color="red" title="요청을 처리하지 못했습니다">
                {error}
              </Alert>
            )}
            {conflict && (
              <Alert color="orange" title="실행 상태가 변경되었습니다">
                <Text size="sm">
                  입력은 유지됩니다. 최신 상태를 확인한 뒤 요청 기준을
                  갱신하세요.
                </Text>
                <Button
                  mt="sm"
                  variant="light"
                  loading={checking}
                  onClick={async () => {
                    setChecking(true);
                    try {
                      setLatest(
                        await api<AgentRun>(
                          `/api/agent-runs/${encodeURIComponent(run.id)}`,
                        ),
                      );
                    } catch (e) {
                      setError((e as Error).message);
                    } finally {
                      setChecking(false);
                    }
                  }}
                >
                  최신 실행 상태 확인
                </Button>
              </Alert>
            )}
            {action === "input" && (
              <Textarea
                label="추가 지시"
                description="자격값·개인정보를 입력하지 마세요. Ctrl 또는 ⌘ + Enter로 저장할 수 있습니다."
                minRows={6}
                autosize
                maxRows={12}
                value={message}
                disabled={busy}
                onChange={(e) => setMessage(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
                    e.preventDefault();
                    void submit();
                  }
                }}
                error={
                  bytes > 16000 ? "16,000바이트 한도를 넘었습니다." : undefined
                }
              />
            )}{" "}
            {action === "input" && (
              <Text size="sm" c={bytes > 16000 ? "red" : "dimmed"}>
                {bytes.toLocaleString()} / 16,000바이트
              </Text>
            )}
            <Text size="sm" c="dimmed">
              확인한 상태 시각: {dateText(revision)}
            </Text>
            <Group justify="flex-end">
              <Button variant="default" disabled={busy} onClick={close}>
                취소
              </Button>
              <Button
                type="submit"
                loading={busy}
                disabled={
                  action === "input" && (!message.trim() || bytes > 16000)
                }
              >
                {titles[action]}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
      <Modal
        opened={discard}
        onClose={() => setDiscard(false)}
        title="추가 지시를 닫을까요?"
        size="sm"
        zIndex={360}
      >
        <Text>저장하지 않은 추가 지시는 창을 닫으면 사라집니다.</Text>
        <Group mt="lg" justify="flex-end">
          <Button variant="default" onClick={() => setDiscard(false)}>
            계속 작성
          </Button>
          <Button color="red" onClick={onClose}>
            입력 버리고 닫기
          </Button>
        </Group>
      </Modal>
      <Modal
        opened={!!latest}
        onClose={() => setLatest(null)}
        title="최신 실행 상태"
        size="sm"
        zIndex={360}
      >
        <Text>
          최신 제어 변경 시각:{" "}
          {dateText(latest ? agentControlRevision(latest) : "")}
        </Text>
        <Text mt="sm">
          입력 내용은 유지하고 요청 기준만 최신 상태로 바꿉니다. 적용 후
          저장·재개 버튼을 다시 누르세요.
        </Text>
        {latest && !latest.allowed_actions?.includes(action) && (
          <Alert mt="md" color="orange">
            현재 상태에서는 이 요청을 할 수 없습니다. 창을 닫고 실행 상세를
            새로고침하세요.
          </Alert>
        )}
        <Group mt="lg" justify="flex-end">
          <Button variant="default" onClick={() => setLatest(null)}>
            돌아가기
          </Button>
          <Button
            disabled={!latest?.allowed_actions?.includes(action)}
            onClick={() => {
              setRevision(agentControlRevision(latest!));
              setLatest(null);
              setConflict(false);
              setError("");
            }}
          >
            확인한 상태 적용
          </Button>
        </Group>
      </Modal>
    </>
  );
}
export function AgentReportMenu({ run }: { run: AgentRun }) {
  const [busy, setBusy] = useState(false);
  // Receiving services an administrator listed; empty on a fresh install, so no menu.
  const handoff = useData<HandoffTargets>("/api/handoff/targets");
  const targets = handoff.data?.targets || [];
  async function send(target: { name: string; origin: string }) {
    if (busy) return;
    setBusy(true);
    // Open the window while still inside the click so popup blockers allow it; it
    // carries the claim only after Hunter has issued one. The opener is cut so the
    // receiving service cannot reach this page.
    const popup = window.open("about:blank", "_blank");
    if (popup) popup.opener = null;
    try {
      if (!popup)
        throw new Error(
          "새 창이 차단되었습니다. 이 사이트의 팝업을 허용한 뒤 다시 시도하세요.",
        );
      const issued = await api<HandoffClaim>("/api/v1/handoff/claims", {
        method: "POST",
        body: JSON.stringify(handoffClaimRequest(run.id)),
      });
      popup.location.replace(
        handoffOpenURL(target.origin, issued.source, issued.claim),
      );
      success(
        `${target.name}에서 보고서를 받아 가도록 새 창을 열었습니다. 표는 5분 동안 한 번만 쓸 수 있습니다.`,
      );
    } catch (e) {
      popup?.close();
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  async function download(format: "md" | "html" | "pdf") {
    if (busy) return;
    setBusy(true);
    try {
      const response = await fetch(agentReportPath(run.id, format), {
        credentials: "same-origin",
        headers: {
          Accept:
            format === "pdf"
              ? "application/pdf"
              : format === "html"
                ? "text/html"
                : "text/markdown",
        },
      });
      if (!response.ok) {
        if (response.status === 401)
          window.dispatchEvent(new Event("hunter:unauthorized"));
        let message = `보고서 다운로드에 실패했습니다 (${response.status})`;
        try {
          message = (await response.json()).error || message;
        } catch {}
        throw new Error(message);
      }
      const expected = {
        md: "text/markdown",
        html: "text/html",
        pdf: "application/pdf",
      }[format];
      if (
        !response.headers.get("content-type")?.includes(expected) ||
        !response.headers.get("content-disposition")?.includes("attachment")
      )
        throw new Error("서버가 요청한 보고서 파일을 반환하지 않았습니다.");
      const url = URL.createObjectURL(await response.blob()),
        link = document.createElement("a");
      link.href = url;
      link.download = `hunter-agent-${run.id.replace(/[^a-zA-Z0-9_-]/g, "")}.${format}`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      success("현재 실행 상태의 보고서를 다운로드했습니다.");
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Menu position="bottom-end" withinPortal>
      <Menu.Target>
        <Button
          variant="default"
          leftSection={<IconDownload size={17} />}
          loading={busy}
        >
          실행 보고서
        </Button>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>현재 상태의 보고서 다운로드</Menu.Label>
        <Menu.Item disabled={busy} onClick={() => download("md")}>
          Markdown (.md)
        </Menu.Item>
        <Menu.Item disabled={busy} onClick={() => download("html")}>
          HTML (.html)
        </Menu.Item>
        <Menu.Item disabled={busy} onClick={() => download("pdf")}>
          PDF (.pdf)
        </Menu.Item>
        {targets.length > 0 && (
          <>
            <Menu.Divider />
            <Menu.Label>다른 서비스로 보내기 (Markdown)</Menu.Label>
            {targets.map((target) => (
              <Menu.Item
                key={target.origin}
                disabled={busy}
                leftSection={<IconSend size={15} />}
                onClick={() => void send(target)}
              >
                {target.name}
              </Menu.Item>
            ))}
          </>
        )}
      </Menu.Dropdown>
    </Menu>
  );
}
