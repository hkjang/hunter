import { useEffect, useRef, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Group,
  Modal,
  Select,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { IconEdit, IconRefresh, IconX } from "@tabler/icons-react";
import { APIError, api, label, success, useSession, type Row } from "./api";
import { FormFeedback, useUnsavedChanges } from "./form-feedback";
import { bulkStatuses, findingBulkPatch } from "./finding-bulk-state";

export function useFindingSelection(scope: string) {
  const [selection, setSelection] = useState<{ scope: string; rows: Row[] }>({
    scope,
    rows: [],
  });
  useEffect(() => {
    setSelection((previous) =>
      previous.scope === scope ? previous : { scope, rows: [] },
    );
  }, [scope]);
  const rows = selection.scope === scope ? selection.rows : [];
  return {
    rows,
    selected: (id: string) => rows.some((row) => row.id === id),
    toggle(row: Row, checked: boolean) {
      setSelection((previous) => {
        const current = previous.scope === scope ? previous.rows : [];
        return {
          scope,
          rows: checked
            ? [...current.filter((item) => item.id !== row.id), row].slice(
                0,
                100,
              )
            : current.filter((item) => item.id !== row.id),
        };
      });
    },
    page(items: Row[], checked: boolean) {
      setSelection({ scope, rows: checked ? items.slice(0, 100) : [] });
    },
    clear() {
      setSelection({ scope, rows: [] });
    },
  };
}

export function BulkFindingActions({
  items,
  onDone,
  onClear,
}: {
  items: Row[];
  onDone: () => Promise<unknown> | void;
  onClear: () => void;
}) {
  const { user } = useSession();
  const [opened, setOpened] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [conflict, setConflict] = useState(false);
  const [changeAssignee, setChangeAssignee] = useState(false),
    [assignee, setAssignee] = useState(""),
    [changeDue, setChangeDue] = useState(false),
    [clearDue, setClearDue] = useState(false),
    [due, setDue] = useState(""),
    [changeStatus, setChangeStatus] = useState(false),
    [status, setStatus] = useState("in_progress");
  const submitting = useRef(false);
  useEffect(() => {
    if (items.length) return;
    setOpened(false);
    setError("");
    setConflict(false);
    setChangeAssignee(false);
    setChangeDue(false);
    setChangeStatus(false);
    setAssignee("");
    setDue("");
  }, [items.length]);
  useUnsavedChanges(opened && (changeAssignee || changeDue || changeStatus));
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (submitting.current) return;
    setError("");
    setConflict(false);
    try {
      const patch = findingBulkPatch({
        changeAssignee,
        assignee,
        changeDue,
        clearDue,
        due,
        changeStatus,
        status,
      });
      if (
        !items.length ||
        items.length > 100 ||
        items.some((item) => !item.id || !item.updated_at)
      )
        throw new Error("선택한 항목의 최신 정보를 불러온 뒤 다시 시도하세요.");
      submitting.current = true;
      setBusy(true);
      const result = await api<{ updated: number }>("/api/findings/bulk", {
        method: "POST",
        body: JSON.stringify({
          items: items.map(({ id, updated_at }) => ({ id, updated_at })),
          patch,
        }),
      });
      success(
        result.updated
          ? `${result.updated}개 발견 건의 선택한 항목을 변경했습니다.`
          : "선택한 항목이 이미 같은 값이어서 변경할 내용이 없습니다.",
      );
      setOpened(false);
      onClear();
      await onDone();
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "일괄 변경하지 못했습니다.",
      );
      setConflict(
        error instanceof APIError && [404, 409].includes(error.status),
      );
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  if (!items.length) return null;
  return (
    <>
      <Group className="finding-bulk-bar" justify="space-between" p="md">
        <Group gap="sm">
          <Badge size="lg" color="teal">
            {items.length}개 선택
          </Badge>
          <Text size="sm">현재 페이지에서 선택한 항목</Text>
        </Group>
        <Group gap="xs">
          <Button
            variant="default"
            leftSection={<IconX size={16} />}
            disabled={busy}
            onClick={onClear}
          >
            선택 해제
          </Button>
          <Button
            leftSection={<IconEdit size={16} />}
            disabled={busy}
            onClick={() => {
              setError("");
              setConflict(false);
              setChangeAssignee(false);
              setChangeDue(false);
              setChangeStatus(false);
              setAssignee("");
              setClearDue(false);
              setDue("");
              setStatus("in_progress");
              setOpened(true);
            }}
          >
            선택 항목 일괄 변경
          </Button>
        </Group>
      </Group>
      <Modal
        opened={opened}
        onClose={() => {
          if (!busy) setOpened(false);
        }}
        title={`${items.length}개 발견 건 일괄 변경`}
        size="lg"
        closeOnClickOutside={false}
        closeOnEscape={!busy}
        withCloseButton={!busy}
      >
        <form onSubmit={submit} className="finding-bulk-form">
          <Stack>
            <Alert color="teal">
              체크한 항목만 변경합니다. 권한이나 수정 버전이 맞지 않는 항목이
              있으면 전체 변경을 적용하지 않습니다.
            </Alert>
            <details>
              <summary>선택한 발견 건 {items.length}개 확인</summary>
              <ul>
                {items.map((item) => (
                  <li key={item.id}>
                    {item.title || item.id} · {label(item.status)}
                  </li>
                ))}
              </ul>
            </details>
            <FormFeedback error={error} />
            {conflict && (
              <Button
                variant="light"
                leftSection={<IconRefresh size={16} />}
                disabled={busy}
                onClick={async () => {
                  setOpened(false);
                  onClear();
                  await onDone();
                }}
              >
                선택 해제하고 최신 목록 새로고침
              </Button>
            )}
            <Checkbox
              label="담당자 변경"
              checked={changeAssignee}
              disabled={busy}
              onChange={(event) =>
                setChangeAssignee(event.currentTarget.checked)
              }
            />
            {changeAssignee && (
              <Stack gap="xs">
                <TextInput
                  label="새 담당자"
                  description="비워 두면 담당자 지정을 해제합니다."
                  value={assignee}
                  disabled={busy}
                  onChange={(event) => setAssignee(event.currentTarget.value)}
                />
                <Button
                  variant="subtle"
                  size="compact-md"
                  disabled={busy}
                  onClick={() =>
                    setAssignee(user?.name || user?.username || "")
                  }
                >
                  내 이름 입력
                </Button>
              </Stack>
            )}
            <Checkbox
              label="조치 기한 변경"
              checked={changeDue}
              disabled={busy}
              onChange={(event) => setChangeDue(event.currentTarget.checked)}
            />
            {changeDue && (
              <Stack gap="xs">
                <Checkbox
                  label="직접 지정 기한 해제"
                  description="관리자가 SLA를 설정했다면 정책 기한이 적용됩니다."
                  checked={clearDue}
                  disabled={busy}
                  onChange={(event) => setClearDue(event.currentTarget.checked)}
                />
                {!clearDue && (
                  <TextInput
                    type="datetime-local"
                    label="새 조치 기한"
                    description="현재 브라우저의 현지 시각으로 입력합니다."
                    value={due}
                    disabled={busy}
                    onChange={(event) => setDue(event.currentTarget.value)}
                  />
                )}
              </Stack>
            )}
            <Checkbox
              label="진행 상태 변경"
              checked={changeStatus}
              disabled={busy}
              onChange={(event) => setChangeStatus(event.currentTarget.checked)}
            />
            {changeStatus && (
              <Select
                label="새 진행 상태"
                data={bulkStatuses.map((value) => ({
                  value,
                  label: label(value),
                }))}
                value={status}
                disabled={busy}
                allowDeselect={false}
                onChange={(value) => setStatus(value || "in_progress")}
              />
            )}
            <Text size="sm" c="dimmed">
              해결·오탐·위험 수용과 해당 상태의 재개는 개별 발견 건에서
              처리합니다.
            </Text>
            <Group justify="flex-end">
              <Button
                variant="default"
                disabled={busy}
                onClick={() => setOpened(false)}
              >
                취소
              </Button>
              <Button type="submit" loading={busy}>
                선택한 {items.length}개에 적용
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </>
  );
}
