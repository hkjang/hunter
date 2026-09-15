import {
  ActionIcon,
  Alert,
  Button,
  Group,
  MultiSelect,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import {
  emptyHandoffTarget,
  handoffFormat,
  handoffFormats,
  type HandoffFormat,
  type HandoffTarget,
} from "./handoff-state";
const formatOptions = handoffFormats.map((value) => ({ value, label: value }));

// The allow list of services a run report may be sent to. Seeded empty: until an
// administrator writes a service down here, the send menu does not exist.
export function HandoffTargetsEditor({
  targets,
  onChange,
  publicURL,
}: {
  targets: HandoffTarget[];
  onChange: (targets: HandoffTarget[]) => void;
  publicURL: string;
}) {
  function update(index: number, patch: Partial<HandoffTarget>) {
    onChange(targets.map((t, i) => (i === index ? { ...t, ...patch } : t)));
  }
  return (
    <Stack gap="md">
      <Text size="sm">
        여기에 적은 사내 서비스만 실행 보고서를 받아 갈 수 있습니다. Hunter는
        <strong> markdown</strong> 만 보내므로 받는 형식에 markdown 이 없는
        서비스는 저장되어도 보내기 메뉴에 나타나지 않습니다. 주소는 경로 없이
        스킴과 호스트(포트)까지만 적습니다.
      </Text>
      {targets.length === 0 && (
        <Alert color="gray" variant="light">
          보낼 곳이 없습니다. 실행 상세의 보고서 메뉴에 “다른 서비스로 보내기”가
          표시되지 않습니다.
        </Alert>
      )}
      {targets.map((target, index) => (
        <Group
          key={index}
          align="flex-start"
          wrap="wrap"
          className="handoff-target-row"
        >
          <TextInput
            id={`settings-handoff-name-${index}`}
            label="이름"
            required
            value={target.name}
            maxLength={60}
            placeholder="Ptium"
            onChange={(e) => update(index, { name: e.currentTarget.value })}
            style={{ flex: "1 1 140px" }}
          />
          <TextInput
            id={`settings-handoff-origin-${index}`}
            label="주소 (오리진)"
            required
            value={target.origin}
            placeholder="https://ptium.intra"
            onChange={(e) => update(index, { origin: e.currentTarget.value })}
            style={{ flex: "2 1 220px" }}
          />
          <MultiSelect
            id={`settings-handoff-formats-${index}`}
            label="그 서비스가 받는 형식"
            required
            data={formatOptions}
            value={target.formats || []}
            onChange={(formats) =>
              update(index, { formats: formats as HandoffFormat[] })
            }
            error={
              target.formats?.length && !target.formats.includes(handoffFormat)
                ? "markdown 이 없어 보내기 메뉴에 오르지 않습니다"
                : undefined
            }
            style={{ flex: "2 1 220px" }}
          />
          <ActionIcon
            variant="subtle"
            color="red"
            mt={28}
            aria-label={`${target.name || index + 1}번째 보낼 곳 삭제`}
            onClick={() => onChange(targets.filter((_, i) => i !== index))}
          >
            <IconTrash size={18} />
          </ActionIcon>
        </Group>
      ))}
      <Group>
        <Button
          variant="light"
          leftSection={<IconPlus size={16} />}
          disabled={targets.length >= 20}
          onClick={() => onChange([...targets, emptyHandoffTarget()])}
        >
          보낼 곳 추가
        </Button>
        <Text size="xs" c="dimmed">
          최대 20개
        </Text>
      </Group>
      <Alert color="teal" variant="light" title="받는 쪽에 알려 줄 것">
        <Text size="sm">
          받는 서비스의 관리자는 자기 허용 목록에 Hunter 의 오리진을 적어야
          합니다. 지금 설정된 값은 <code>{publicURL}</code> 입니다(기본 정보 →
          서비스 외부 접근 주소). 그쪽 목록에 없으면 받는 서비스는 Hunter 에
          아무 요청도 보내지 않고 거절합니다.
        </Text>
      </Alert>
    </Stack>
  );
}
