import { Button, Group, Tabs, Text } from "@mantine/core";
import { IconSettings } from "@tabler/icons-react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { PageHeader } from "./components";
import { switchWorkflowTab } from "./workflow-navigation";
import {
  platformTabs,
  platformTabLabels,
  type PlatformTab,
} from "./agent-platform-state";
import { PlatformSearch, PlatformMemory } from "./agent-platform-knowledge";
import { PlatformModels } from "./agent-platform-models";
import { PlatformObservability } from "./agent-platform-observability";
import { PlatformExecution } from "./agent-platform-execution";
import "./agent-platform.css";
export function AgentPlatformPage() {
  const [params, setParams] = useSearchParams(),
    location = useLocation();
  const tab = platformTabs.includes(params.get("tab") as PlatformTab)
    ? (params.get("tab") as PlatformTab)
    : "search";
  return (
    <>
      <PageHeader
        eyebrow="ADMINISTRATION"
        title="에이전트 통합 연동"
        description="필요한 검색·모델·실행·운영 연동을 선택하고, 저장한 연결과 장애 시 대체 경로를 확인합니다."
        action={
          <Button
            component={Link}
            to="/admin/settings?tab=agents"
            variant="default"
            leftSection={<IconSettings size={17} />}
          >
            에이전트 기본 설정
          </Button>
        }
      />
      <div className="automation-note">
        연동은 기본 사용 안 함으로 시작합니다. 사내 주소와 실행 정책을 확인한 뒤
        필요한 기능만 켜세요. 선택 연동의 장애는 기본 서비스와 분리하여
        처리합니다.
      </div>
      <Tabs
        className="platform-tabs"
        mt="xl"
        value={tab}
        onChange={(value) => {
          if (value)
            setParams(switchWorkflowTab(params, tab, value, platformTabs), {
              preventScrollReset: true,
              state: location.state,
            });
        }}
        keepMounted={false}
      >
        <Tabs.List mb="lg">
          {platformTabs.map((key) => (
            <Tabs.Tab key={key} value={key}>
              {platformTabLabels[key]}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel value="search">
          <PlatformSearch />
        </Tabs.Panel>
        <Tabs.Panel value="memory">
          <PlatformMemory />
        </Tabs.Panel>
        <Tabs.Panel value="models">
          <PlatformModels />
        </Tabs.Panel>
        <Tabs.Panel value="execution">
          <PlatformExecution />
        </Tabs.Panel>
        <Tabs.Panel value="observability">
          <PlatformObservability />
        </Tabs.Panel>
      </Tabs>
      <Group mt="xl" justify="space-between">
        <Text size="sm" c="dimmed">
          GraphQL 조회 API도 현재 사용자·키의 자료 접근 권한을 적용합니다.
        </Text>
        <Button
          component="a"
          href="/api/graphql/schema"
          download
          variant="default"
        >
          GraphQL 스키마 다운로드
        </Button>
      </Group>
    </>
  );
}
