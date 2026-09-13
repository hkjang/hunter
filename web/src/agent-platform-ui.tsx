import { useState, type ReactNode } from "react";
import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Text,
} from "@mantine/core";
import {
  IconArrowDown,
  IconArrowUp,
  IconPlugConnected,
} from "@tabler/icons-react";
import { dateText } from "./api";
import { movePriorityItem, type SecretChoice } from "./agent-platform-state";
import "./agent-platform.css";
export function PlatformSecret({
  mode,
  value,
  configured,
  onMode,
  onValue,
  label = "API 키",
}: {
  mode: SecretChoice;
  value: string;
  configured?: boolean;
  onMode: (mode: SecretChoice) => void;
  onValue: (value: string) => void;
  label?: string;
}) {
  return (
    <Stack gap="sm">
      <Group>
        <Text fw={600}>{label}</Text>
        <Badge color={configured ? "teal" : "gray"}>
          {configured ? "저장됨 · 원문 비공개" : "미설정"}
        </Badge>
      </Group>
      <Select
        label={label + " 관리"}
        value={mode}
        data={[
          { value: "keep", label: "저장한 값 유지" },
          { value: "replace", label: "새 값으로 교체" },
          { value: "clear", label: "저장한 값 삭제" },
        ]}
        onChange={(value) => {
          onMode((value || "keep") as SecretChoice);
        }}
      />
      {mode === "replace" && (
        <PasswordInput
          label={"새 " + label}
          value={value}
          autoComplete="new-password"
          onChange={(e) => onValue(e.currentTarget.value)}
        />
      )}
      <Text size="sm" c="dimmed">
        저장한 값은 암호화하여 보관합니다. 입력을 비워 두면 기존 값을 유지하고,
        삭제는 명시적으로 선택합니다.
      </Text>
    </Stack>
  );
}
export function PlatformStatus({ status }: { status?: string }) {
  const values: Record<string, [string, string]> = {
    healthy: ["정상", "teal"],
    enabled: ["사용 중", "teal"],
    available: ["사용 가능", "teal"],
    accepted: ["접수 완료", "teal"],
    degraded: ["일부 기능 저하", "orange"],
    recovering: ["회복 확인 중", "blue"],
    ok: ["정상", "teal"],
    closed: ["정상", "teal"],
    success: ["성공", "teal"],
    unknown: ["미확인", "gray"],
    untested: ["미확인", "gray"],
    open: ["회복 대기", "orange"],
    half_open: ["회복 확인 중", "blue"],
    disabled: ["사용 안 함", "gray"],
    failed: ["실패", "red"],
    error: ["오류", "red"],
    timeout: ["시간 초과", "orange"],
    unavailable: ["연결 불가", "orange"],
    sent: ["전송 완료", "teal"],
    queued: ["전송 대기", "blue"],
    retry: ["재시도 대기", "orange"],
    discarded: ["재시도 종료", "gray"],
  };
  const value = values[status || "unknown"];
  return (
    <Badge variant="light" color={value?.[1] || "gray"}>
      {value?.[0] || status}
    </Badge>
  );
}
export function ProviderPriority({
  value,
  options,
  onChange,
}: {
  value: string[];
  options: { value: string; label: string }[];
  onChange: (value: string[]) => void;
}) {
  return (
    <Stack gap="sm">
      {value.map((id, index) => (
        <Group
          className="platform-priority-row"
          key={id}
          justify="space-between"
          wrap="nowrap"
        >
          <Text>
            {index + 1}. {options.find((row) => row.value === id)?.label || id}
          </Text>
          <Group gap="xs" wrap="nowrap">
            <Button
              variant="default"
              size="compact-sm"
              aria-label={
                (options.find((row) => row.value === id)?.label || id) +
                " 우선순위 올리기"
              }
              disabled={index === 0}
              onClick={() => onChange(movePriorityItem(value, index, -1))}
            >
              <IconArrowUp size={16} />
            </Button>
            <Button
              variant="default"
              size="compact-sm"
              aria-label={
                (options.find((row) => row.value === id)?.label || id) +
                " 우선순위 내리기"
              }
              disabled={index === value.length - 1}
              onClick={() => onChange(movePriorityItem(value, index, 1))}
            >
              <IconArrowDown size={16} />
            </Button>
          </Group>
        </Group>
      ))}
    </Stack>
  );
}
export function PlatformProbe({
  name,
  onClose,
  onTest,
  description,
  children,
  renderResult,
}: {
  name: string;
  onClose: () => void;
  onTest: () => Promise<Record<string, unknown>>;
  description: string;
  children?: ReactNode;
  renderResult?: (result: Record<string, unknown>) => ReactNode;
}) {
  const [busy, setBusy] = useState(false),
    [result, setResult] = useState<Record<string, unknown> | null>(null),
    [error, setError] = useState("");
  async function test() {
    if (busy) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      setResult(await onTest());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      opened
      title={name + " 연결 시험"}
      size="lg"
      zIndex={350}
      onClose={() => {
        if (!busy) onClose();
      }}
      closeOnEscape={!busy}
      closeOnClickOutside={!busy}
      withCloseButton={!busy}
    >
      <Stack gap="lg">
        <Text>{description}</Text>
        <Alert color="teal">
          저장한 설정을 사용합니다. 시험 실패는 이 연동의 상태에 기록되며 기본
          서비스는 계속 사용할 수 있습니다.
        </Alert>
        <fieldset className="form-fields" disabled={busy}>
          {children}
        </fieldset>
        {error && <Alert color="red">{error}</Alert>}
        {result && (
          <div className="platform-test-result">
            <Group justify="space-between">
              <PlatformStatus
                status={
                  result.ok === true
                    ? "success"
                    : String(result.status || "failed")
                }
              />
              <Text>
                {typeof (result.latency_ms ?? result.elapsed_ms) === "number"
                  ? Number(
                      result.latency_ms ?? result.elapsed_ms,
                    ).toLocaleString() + " ms"
                  : ""}
              </Text>
            </Group>
            <Text mt="sm">
              처리 결과: {String(result.status || "확인 완료")}
            </Text>
            {typeof result.input_tokens === "number" && (
              <Text size="sm">
                입력 {result.input_tokens.toLocaleString()} / 출력{" "}
                {Number(result.output_tokens || 0).toLocaleString()} 토큰
              </Text>
            )}
            {Array.isArray(result.signals) && (
              <Stack gap="xs" mt="sm">
                {result.signals.map((signal, index) =>
                  typeof signal === "string" ? (
                    <Text key={index} size="sm">
                      전송 신호: {signal}
                    </Text>
                  ) : (
                    <Group key={index} justify="space-between">
                      <Text size="sm">{String(signal?.signal || "신호")}</Text>
                      <PlatformStatus
                        status={
                          signal?.ok === true
                            ? "accepted"
                            : String(signal?.status || "failed")
                        }
                      />
                    </Group>
                  ),
                )}
              </Stack>
            )}
            {renderResult?.(result)}
          </div>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose} disabled={busy}>
            닫기
          </Button>
          <Button
            leftSection={<IconPlugConnected size={17} />}
            loading={busy}
            onClick={test}
          >
            저장한 연결 시험
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
export function ProviderHealth({ row }: { row?: Record<string, unknown> }) {
  const state = String(row?.status || row?.state || "unknown"),
    checked = row?.checked_at || row?.last_test_at,
    open = row?.open_until || row?.circuit_open_until,
    code = row?.code || row?.last_error;
  return (
    <Stack gap={3}>
      <PlatformStatus status={state} />
      {!!checked && (
        <Text size="sm" c="dimmed">
          최근 확인 {dateText(String(checked))}
        </Text>
      )}
      {!!row?.last_success_at && (
        <Text size="sm" c="dimmed">
          최근 성공 {dateText(String(row.last_success_at))}
        </Text>
      )}
      {!!open && (
        <Text size="sm" c="orange">
          회복 예정 {dateText(String(open))}
        </Text>
      )}
      {!!code && (
        <Text
          size="sm"
          c={
            ["failed", "open", "degraded", "unavailable"].includes(state)
              ? "red"
              : "dimmed"
          }
        >
          최근 결과: {String(code)}
          {typeof row?.elapsed_ms === "number" ? ` · ${row.elapsed_ms} ms` : ""}
        </Text>
      )}
    </Stack>
  );
}
