import { Alert, Button, Group, Tabs } from "@mantine/core";
import {
  IconBell,
  IconCalendar,
  IconClipboardList,
  IconHistory,
  IconPlugConnected,
  IconShieldCheck,
  IconUsers,
} from "@tabler/icons-react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { PageHeader } from "./components";
import { useCan } from "./api";
import { switchWorkflowTab } from "./workflow-navigation";
import { automationTabs, type AutomationTab } from "./automation-state";
import {
  NotificationAutomationPanel,
  NotificationSimulationPanel,
} from "./notification-automation";
import { NotificationOperationsPanel } from "./notification-operations";
import {
  WorkflowAutomationPanel,
  WorkflowHistoryPanel,
} from "./workflow-automation";
import "./automation.css";
const labels: Record<AutomationTab, string> = {
  recipients: "연락처·당직",
  notifications: "알림 정책",
  providers: "채널 운영",
  workflows: "변경·ITSM 규칙",
  simulation: "모의 검사",
  history: "실행 이력",
  retention: "보존 관리",
};
export function AutomationPage() {
  const [params, setParams] = useSearchParams(),
    location = useLocation(),
    can = useCan(),
    tab = automationTabs.includes(params.get("tab") as AutomationTab)
      ? (params.get("tab") as AutomationTab)
      : "recipients";
  const historyAllowed = [
    "integrations:manage",
    "services:read",
    "findings:read",
    "scans:read",
  ].every(can);
  function change(value: string | null) {
    if (!value) return;
    setParams(
      switchWorkflowTab(params, tab, value, automationTabs, {
        workflows: ["workflow"],
        history: ["kind", "status"],
      }),
      { preventScrollReset: true, state: location.state },
    );
  }
  return (
    <>
      <PageHeader
        eyebrow="ADMINISTRATION"
        title="자동화 관리"
        description="현재 담당자와 운영 조건을 기준으로 알림·변경 진단·개선 업무를 연결합니다."
        action={
          <Button
            component={Link}
            to="/admin/notifications"
            variant="default"
            leftSection={<IconBell size={17} />}
          >
            알림센터
          </Button>
        }
      />
      <div className="automation-note">
        새 자동화는 사용 안 함 상태로 시작합니다. 수신자와 규칙을 저장하고 모의
        검사로 확인한 뒤 필요한 기능만 켜세요.
      </div>
      <Tabs
        className="automation-tabs"
        value={tab}
        onChange={change}
        mt="xl"
        keepMounted={false}
      >
        <Tabs.List mb="lg">
          {automationTabs.map((value) => (
            <Tabs.Tab key={value} value={value}>
              {labels[value]}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel value="recipients">
          <NotificationAutomationPanel view="recipients" />
        </Tabs.Panel>
        <Tabs.Panel value="notifications">
          <NotificationAutomationPanel view="notifications" />
        </Tabs.Panel>
        <Tabs.Panel value="providers">
          <NotificationOperationsPanel />
        </Tabs.Panel>
        <Tabs.Panel value="workflows">
          <WorkflowAutomationPanel />
        </Tabs.Panel>
        <Tabs.Panel value="simulation">
          <NotificationSimulationPanel />
        </Tabs.Panel>
        <Tabs.Panel value="history">
          {historyAllowed ? (
            <WorkflowHistoryPanel />
          ) : (
            <Alert color="orange">
              자동화 실행 이력에는 연동 관리·서비스 조회·발견 건 조회·진단 조회
              권한이 모두 필요합니다. 현재 역할의 권한을 관리자에게 확인하세요.
            </Alert>
          )}
        </Tabs.Panel>
        <Tabs.Panel value="retention">
          <NotificationAutomationPanel view="retention" />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
