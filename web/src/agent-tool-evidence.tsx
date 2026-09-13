import { Alert, Anchor, Button, Group, Stack, Text } from "@mantine/core";
import { Link } from "react-router-dom";
import type { AgentTool } from "./agent-events";
import { webAddress } from "./agent-platform-state";
import { Status } from "./components";
function readResult(value: unknown): Record<string, unknown> | null {
  try {
    const parsed =
      typeof value === "string" && value.length <= 1048576
        ? JSON.parse(value)
        : value;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}
export function AgentToolEvidence({ tool }: { tool: AgentTool }) {
  const result = readResult(tool.completed?.data?.result);
  if (!result) return null;
  if (tool.name === "search_reference")
    return (
      <Stack mt="lg">
        {result.degraded === true && (
          <Alert color="yellow">
            검색 근거를 확인하지 못했거나 일부 연동을 사용할 수 없습니다. 내부
            근거와 함께 결과를 검토하세요.
          </Alert>
        )}
        <Text size="sm" c="dimmed">
          검색 자료는 출처가 있는 참고 정보입니다. 실제 실행 권한과 정책을
          변경하지 않습니다.
        </Text>
        {Array.isArray(result.items) &&
          result.items
            .slice(0, 10)
            .filter((row) => row && typeof row === "object")
            .map((row, index) => {
              const title =
                  typeof row.title === "string" ? row.title : "검색 결과",
                snippet = typeof row.snippet === "string" ? row.snippet : "",
                url = typeof row.url === "string" ? webAddress(row.url) : null;
              return (
                <div className="platform-form-section" key={index}>
                  {url ? (
                    <Anchor
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {title}
                    </Anchor>
                  ) : (
                    <Text fw={600}>{title}</Text>
                  )}
                  <Text mt="sm">{snippet}</Text>
                  {url && (
                    <Text
                      size="sm"
                      c="dimmed"
                      mt="xs"
                      style={{ overflowWrap: "anywhere" }}
                    >
                      {url}
                    </Text>
                  )}
                </div>
              );
            })}
      </Stack>
    );
  if (
    ["request_scan", "scan_result"].includes(tool.name) &&
    typeof result.id === "string"
  )
    return (
      <Group mt="lg" justify="space-between">
        <div>
          <Text fw={600}>
            {result.profile === "isolated"
              ? "격리 프로파일 진단 결과"
              : "연결된 진단 결과"}
          </Text>
          {typeof result.status === "string" && (
            <Status value={result.status} />
          )}
        </div>
        <Button
          component={Link}
          to={"/scans?item=" + encodeURIComponent(result.id)}
          variant="light"
        >
          진단 상세 보기
        </Button>
      </Group>
    );
  return null;
}
