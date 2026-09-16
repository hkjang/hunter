import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Group,
  Stack,
  Table,
  Text,
  TextInput,
} from "@mantine/core";
import { IconRefresh, IconSend } from "@tabler/icons-react";
import { api, fullDate, type Row, showError } from "./api";

export type MailDelivery = {
  id: string;
  event: string;
  event_label: string;
  recipient: string;
  subject: string;
  entity_id: string;
  status: "queued" | "sending" | "sent" | "failed";
  attempts: number;
  detail: string;
  created_at: string;
  sent_at: string | null;
};

const statusLabel: Record<string, string> = {
  queued: "대기",
  sending: "발송 중",
  sent: "발송됨",
  failed: "실패",
};
const statusColor: Record<string, string> = {
  queued: "gray",
  sending: "blue",
  sent: "teal",
  failed: "red",
};

// Relay settings are rarely right the first time: the test button sends one real
// message with the *saved* settings and shows the relay's answer in place. The log
// below lists every attempt (never a body) so "it never arrived" can be answered.
export function MailSettingsPanel({
  passwordConfigured,
  clearPassword,
  onClearPassword,
  dirty,
}: {
  passwordConfigured: boolean;
  clearPassword: boolean;
  onClearPassword: (value: boolean) => void;
  dirty: boolean;
}) {
  const [to, setTo] = useState("");
  const [sending, setSending] = useState(false);
  const [result, setResult] = useState<Row | null>(null);
  const [items, setItems] = useState<MailDelivery[]>([]);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api<{
        items: MailDelivery[];
        summary: { status: Record<string, number> };
      }>("/api/admin/mail/deliveries");
      setItems(data.items || []);
      setSummary(data.summary?.status || {});
    } catch (e) {
      showError(e);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  async function sendTest() {
    setSending(true);
    setResult(null);
    try {
      const r = await api<Row>("/api/admin/mail/test", {
        method: "POST",
        body: JSON.stringify({ to }),
      });
      setResult(r);
    } catch (e: any) {
      setResult({ state: "error", detail: e?.message || String(e) });
    } finally {
      setSending(false);
      void load();
    }
  }

  return (
    <Stack gap="lg" mt="xl">
      {passwordConfigured && (
        <div>
          <Badge color="teal" variant="light">
            SMTP 비밀번호 저장됨
          </Badge>
          <Checkbox
            mt="md"
            label="저장된 SMTP 비밀번호 삭제"
            checked={clearPassword}
            onChange={(e) => onClearPassword(e.currentTarget.checked)}
          />
        </div>
      )}
      <Alert color="teal" title="시험 발송" variant="light">
        <Text size="sm">
          저장된 설정으로 실제 메일 한 통을 보내고 릴레이의 응답을 바로
          보여 줍니다. 받는 사람을 비우면 내 계정의 메일 주소(연락처 또는 메일
          형식의 사용자 이름)로 보냅니다.
          {dirty && " 저장하지 않은 변경은 시험 발송에 반영되지 않습니다."}
        </Text>
        <Group mt="sm" align="flex-end" wrap="wrap">
          <TextInput
            id="settings-mail-test-to"
            label="받는 사람"
            placeholder="me@corp.local"
            value={to}
            onChange={(e) => setTo(e.currentTarget.value)}
            style={{ flex: 1, minWidth: 220 }}
          />
          <Button
            leftSection={<IconSend size={16} />}
            loading={sending}
            onClick={() => void sendTest()}
          >
            시험 발송
          </Button>
        </Group>
        {result && (
          <Alert
            mt="sm"
            color={result.state === "sent" ? "teal" : "red"}
            variant="light"
            title={
              result.state === "sent"
                ? "릴레이가 메일을 접수했습니다"
                : "시험 발송에 실패했습니다"
            }
          >
            <Text size="sm">
              {[result.recipient, result.code, result.detail]
                .filter(Boolean)
                .join(" · ")}
            </Text>
          </Alert>
        )}
      </Alert>
      <div>
        <Group justify="space-between" mb="xs" wrap="wrap">
          <div>
            <Text fw={600}>발송 기록</Text>
            <Text size="sm" c="dimmed">
              최근 200건 · 본문은 기록하지 않습니다.{" "}
              {Object.entries(summary)
                .map(([k, v]) => `${statusLabel[k] || k} ${v}`)
                .join(" · ")}
            </Text>
          </div>
          <Button
            variant="light"
            size="xs"
            leftSection={<IconRefresh size={14} />}
            loading={loading}
            onClick={() => void load()}
          >
            새로 고침
          </Button>
        </Group>
        {items.length === 0 ? (
          <Text size="sm" c="dimmed">
            아직 발송 기록이 없습니다.
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={720}>
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>시각</Table.Th>
                  <Table.Th>이벤트</Table.Th>
                  <Table.Th>받는 사람</Table.Th>
                  <Table.Th>제목</Table.Th>
                  <Table.Th>상태</Table.Th>
                  <Table.Th>결과</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((d) => (
                  <Table.Tr key={d.id}>
                    <Table.Td>{fullDate(d.created_at)}</Table.Td>
                    <Table.Td>{d.event_label}</Table.Td>
                    <Table.Td>{d.recipient}</Table.Td>
                    <Table.Td>{d.subject}</Table.Td>
                    <Table.Td>
                      <Badge
                        variant="light"
                        color={statusColor[d.status] || "gray"}
                      >
                        {statusLabel[d.status] || d.status}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">
                        {d.attempts > 0 ? `${d.attempts}회 · ` : ""}
                        {d.detail}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </div>
    </Stack>
  );
}
