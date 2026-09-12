import { Component, type ReactNode } from "react";
import { Button, Group, Paper, Stack, Text, Title } from "@mantine/core";
import { IconHome, IconRefresh } from "@tabler/icons-react";

// An unexpected render failure must leave the user a usable recovery path.
// Error messages and component state can contain private data, so the public
// fallback never renders those internals or sends them to an external service.
export class RenderBoundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main
        className="app-loading"
        style={{ minHeight: "100dvh", padding: 20 }}
      >
        <Paper withBorder p="xl" radius="lg" maw={560} w="100%">
          <Stack align="center" ta="center">
            <img src="/favicon.svg" width={54} height={54} alt="Hunter" />
            <Title order={1} size={23}>
              화면을 표시하지 못했습니다
            </Title>
            <Text c="dimmed">
              페이지를 다시 불러오거나 시작 화면으로 이동해 주세요. 저장한
              자료와 서버에서 실행 중인 진단은 유지됩니다.
            </Text>
            <Group justify="center">
              <Button
                leftSection={<IconRefresh size={17} />}
                onClick={() => window.location.reload()}
              >
                페이지 다시 불러오기
              </Button>
              <Button
                component="a"
                href="/"
                variant="default"
                leftSection={<IconHome size={17} />}
              >
                시작 화면으로
              </Button>
            </Group>
          </Stack>
        </Paper>
      </main>
    );
  }
}
