import { useRef, useState, type ReactNode } from "react";
import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  Paper,
  Stack,
  Text,
} from "@mantine/core";
import { IconPencil, IconRefresh } from "@tabler/icons-react";
import { APIError, dateText } from "./api";
import { FormFeedback, SaveStatus, useUnsavedChanges } from "./form-feedback";
import { changed } from "./form-state";
import "./automation.css";

export function AutomationEditor<T>({
  title,
  value,
  revision,
  onClose,
  onSave,
  loadLatest,
  children,
  submitLabel = "변경 저장",
}: {
  title: string;
  value: T;
  revision: string;
  onClose: () => void;
  onSave: (value: T, revision: string) => Promise<unknown>;
  loadLatest?: () => Promise<{ value: T; revision: string }>;
  children: (
    value: T,
    onChange: (value: T) => void,
    busy: boolean,
  ) => ReactNode;
  submitLabel?: string;
}) {
  const [draft, setDraft] = useState(() => structuredClone(value)),
    [baseline, setBaseline] = useState(() => structuredClone(value)),
    [version, setVersion] = useState(revision);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [conflict, setConflict] = useState(false),
    [discard, setDiscard] = useState(false),
    [latest, setLatest] = useState<{ value: T; revision: string } | null>(null),
    [checking, setChecking] = useState(false);
  const submitting = useRef(false),
    dirty = changed(baseline, draft);
  useUnsavedChanges(dirty || busy);
  const close = () => {
    if (busy) return;
    if (dirty) setDiscard(true);
    else onClose();
  };
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    setError("");
    setConflict(false);
    try {
      submitting.current = true;
      setBusy(true);
      await onSave(draft, version);
      onClose();
    } catch (e) {
      setError((e as Error).message);
      setConflict(e instanceof APIError && e.status === 409);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  async function fetchLatest() {
    if (!loadLatest || checking) return;
    setChecking(true);
    try {
      setLatest(await loadLatest());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setChecking(false);
    }
  }
  return (
    <>
      <Modal
        opened
        onClose={close}
        title={<strong>{title}</strong>}
        zIndex={300}
        size="xl"
        closeOnEscape={!busy}
        closeOnClickOutside={!busy}
        withCloseButton={!busy}
      >
        <form noValidate onSubmit={submit} className="automation-editor">
          <Stack gap="lg">
            <FormFeedback error={error} />
            {conflict && loadLatest && (
              <Alert color="orange" title="다른 관리자가 먼저 변경했습니다">
                <Text size="sm">
                  현재 입력은 유지됩니다. 최신 내용을 확인한 뒤 명시적으로 다시
                  불러올 수 있습니다.
                </Text>
                <Button
                  mt="sm"
                  variant="light"
                  color="orange"
                  loading={checking}
                  onClick={fetchLatest}
                >
                  최신 자료 확인
                </Button>
              </Alert>
            )}
            <SaveStatus dirty={dirty} saving={busy} />
            <fieldset className="form-fields" disabled={busy}>
              {children(draft, setDraft, busy)}
            </fieldset>
            <Group justify="flex-end" className="automation-editor-actions">
              <Button variant="default" onClick={close} disabled={busy}>
                취소
              </Button>
              <Button type="submit" loading={busy}>
                {submitLabel}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
      <Modal
        opened={discard}
        onClose={() => setDiscard(false)}
        title="작성 중인 내용을 닫을까요?"
        size="sm"
        zIndex={350}
      >
        <Text>
          저장하지 않은 입력이 있습니다. 입력을 버리고 닫으면 복구할 수
          없습니다.
        </Text>
        <Group justify="flex-end" mt="lg">
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
        title="최신 설정 확인"
        size="sm"
        zIndex={350}
      >
        <Text>최신 수정 시각: {dateText(latest?.revision)}</Text>
        <Text mt="sm">
          현재 작성한 내용을 최신 설정으로 바꿉니다. 입력을 유지하려면 닫으세요.
        </Text>
        <Group justify="flex-end" mt="lg">
          <Button variant="default" onClick={() => setLatest(null)}>
            입력 유지
          </Button>
          <Button
            onClick={() => {
              if (!latest) return;
              setDraft(structuredClone(latest.value));
              setBaseline(structuredClone(latest.value));
              setVersion(latest.revision);
              setLatest(null);
              setConflict(false);
              setError("");
            }}
          >
            최신 자료로 다시 작성
          </Button>
        </Group>
      </Modal>
    </>
  );
}
export function AutomationSection({
  title,
  description,
  enabled,
  children,
  onEdit,
}: {
  title: string;
  description?: string;
  enabled?: boolean;
  children?: ReactNode;
  onEdit?: () => void;
}) {
  return (
    <Paper className="automation-section" withBorder radius="lg">
      <Group justify="space-between" align="flex-start" gap="sm">
        <div>
          <h2>{title}</h2>
          {description && (
            <Text c="dimmed" mt={6}>
              {description}
            </Text>
          )}
        </div>
        <Group gap="sm">
          {enabled !== undefined && (
            <Badge variant="light" color={enabled ? "teal" : "gray"}>
              {enabled ? "사용 중" : "사용 안 함"}
            </Badge>
          )}
          {onEdit && (
            <Button
              variant="default"
              leftSection={<IconPencil size={16} />}
              onClick={onEdit}
              aria-label={title + " 설정 변경"}
            >
              설정 변경
            </Button>
          )}
        </Group>
      </Group>
      {children && <div className="automation-section-body">{children}</div>}
    </Paper>
  );
}
export function AutomationValues({
  items,
}: {
  items: { label: string; value: ReactNode }[];
}) {
  return (
    <dl className="automation-values">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
export function AutomationStatus({ status }: { status: string }) {
  const values: Record<string, [string, string]> = {
    closed: ["정상", "teal"],
    notice: ["일반 알림", "gray"],
    unavailable: ["결과 확인 불가", "yellow"],
    delivery_failed: ["배달 실패", "red"],
    receipt_pending: ["공급자 처리 대기", "blue"],
    receipt_conflict: ["결과 충돌", "orange"],
    completed: ["완료", "teal"],
    partial: ["일부 완료", "yellow"],
    blocked: ["조건 차단", "orange"],
    no_match: ["일치 없음", "gray"],
    conflict: ["변경 충돌", "orange"],
    unchanged: ["변경 없음", "gray"],
    pending: ["확인 대기", "orange"],
    acknowledged: ["확인 완료", "teal"],
    healthy: ["정상", "teal"],
    open: ["일시 중단", "red"],
    half_open: ["회복 확인", "yellow"],
    unknown: ["확인 전", "gray"],
    delivered: ["배달 완료", "teal"],
    failed: ["실패", "red"],
    accepted: ["공급자 접수", "teal"],
    queued: ["대기", "blue"],
    running: ["실행 중", "blue"],
  };
  const value = values[status];
  return (
    <Badge variant="light" color={value?.[1] || "gray"}>
      {value?.[0] || status}
    </Badge>
  );
}
export function AutomationRefresh({
  onClick,
  busy = false,
}: {
  onClick: () => void;
  busy?: boolean;
}) {
  return (
    <Button
      variant="default"
      leftSection={<IconRefresh size={16} />}
      loading={busy}
      onClick={onClick}
    >
      새로고침
    </Button>
  );
}
