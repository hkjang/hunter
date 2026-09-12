import { api, type Row } from "./api";
export type ChangeRule = {
  id: string;
  name: string;
  enabled: boolean;
  integration_id: string;
  service_id: string;
  event_types: string[];
  match: {
    paths: string[];
    api_paths: string[];
    components: string[];
    permissions: string[];
  };
  profile: string;
  scope_id: string;
  scenario_id: string;
};
export type TicketRule = {
  id: string;
  name: string;
  enabled: boolean;
  integration_id: string;
  service_id: string;
  poll_interval_minutes: number;
  read_url_template: string;
  field_map: {
    external_id: string;
    assignee: string;
    due_date: string;
    status: string;
    updated_at: string;
    deployment_reference: string;
    deployment_confirmed: string;
  };
  complete_statuses: string[];
  retest_on_deploy: boolean;
  scope_id: string;
};
export type WorkflowAutomationDocument = {
  enabled: boolean;
  change_rules: ChangeRule[];
  ticket_rules: TicketRule[];
  signing_secret: string;
  signing_secret_configured: boolean;
  updated_at: string;
};
export type WorkflowRun = {
  id: string;
  kind: string;
  integration_id: string;
  service_id: string;
  reference: string;
  status: string;
  result: Row;
  created_at: string;
};
export type WorkflowRunPage = {
  items: WorkflowRun[];
  total: number;
  page: number;
  page_size: number;
};
export type WorkflowPreview = {
  matched: {
    rule_id: string;
    rule_name: string;
    profile: string;
    scenario_id: string;
    scope_id: string;
    matched_changes: Record<string, string[]>;
    allowed: boolean;
    reason: string;
  }[];
  scan_count: number;
};
export const workflowAutomationAPI = {
  config: () => api<WorkflowAutomationDocument>("/api/workflow-automation"),
  save: (body: unknown) =>
    api<WorkflowAutomationDocument>("/api/workflow-automation", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  preview: (body: unknown) =>
    api<WorkflowPreview>("/api/workflow-automation/preview", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  sync: (body: unknown) =>
    api<WorkflowRun>("/api/workflow-automation/sync", {
      method: "POST",
      body: JSON.stringify(body),
    }),
};
export const changeEventOptions = [
  { value: "push", label: "코드 푸시" },
  { value: "pull_request", label: "변경 요청" },
  { value: "merge", label: "코드 병합" },
  { value: "image", label: "이미지 생성" },
  { value: "harbor_push", label: "Harbor 이미지 푸시" },
  { value: "deploy", label: "배포" },
  { value: "api_change", label: "API 변경" },
  { value: "iam_change", label: "권한 정책 변경" },
  { value: "prompt_change", label: "AI 프롬프트 변경" },
  { value: "manual", label: "수동 이벤트" },
];
export const profileOptions = [
  { value: "http-baseline", label: "웹 기본 점검" },
  { value: "authorization", label: "업무 권한 검증" },
  { value: "import-only", label: "외부 진단 결과 수입" },
];
export function newChangeRule(): ChangeRule {
  return {
    id: "",
    name: "",
    enabled: false,
    integration_id: "",
    service_id: "",
    event_types: ["push"],
    match: { paths: [], api_paths: [], components: [], permissions: [] },
    profile: "http-baseline",
    scope_id: "",
    scenario_id: "",
  };
}
export function newTicketRule(): TicketRule {
  return {
    id: "",
    name: "",
    enabled: false,
    integration_id: "",
    service_id: "",
    poll_interval_minutes: 15,
    read_url_template: "",
    field_map: {
      external_id: "id",
      assignee: "assignee",
      due_date: "due_date",
      status: "status",
      updated_at: "updated_at",
      deployment_reference: "deployment.id",
      deployment_confirmed: "deployment.confirmed",
    },
    complete_statuses: ["done"],
    retest_on_deploy: false,
    scope_id: "",
  };
}
export function workflowConfigBody(
  source: WorkflowAutomationDocument,
  revision: string,
) {
  if (!revision)
    throw new Error("설정 기준 시각이 없습니다. 최신 자료를 다시 불러오세요.");
  const doc = workflowConfigDraft(source);
  return {
    enabled: doc.enabled,
    change_rules: doc.change_rules.map((rule) => ({
      id: rule.id,
      name: rule.name,
      enabled: rule.enabled,
      integration_id: rule.integration_id,
      service_id: rule.service_id,
      event_types: [...rule.event_types],
      match: {
        paths: [...rule.match.paths],
        api_paths: [...rule.match.api_paths],
        components: [...rule.match.components],
        permissions: [...rule.match.permissions],
      },
      profile: rule.profile,
      scope_id: rule.scope_id,
      scenario_id: rule.scenario_id,
    })),
    ticket_rules: doc.ticket_rules.map((rule) => ({
      id: rule.id,
      name: rule.name,
      enabled: rule.enabled,
      integration_id: rule.integration_id,
      service_id: rule.service_id,
      poll_interval_minutes: rule.poll_interval_minutes,
      read_url_template: rule.read_url_template,
      field_map: { ...rule.field_map },
      complete_statuses: [...rule.complete_statuses],
      retest_on_deploy: rule.retest_on_deploy,
      scope_id: rule.scope_id,
    })),
    expected_updated_at: revision,
  };
}

export function workflowConfigDraft(
  doc: WorkflowAutomationDocument,
): WorkflowAutomationDocument {
  return {
    ...doc,
    change_rules: (doc.change_rules || []).map((row) => ({
      ...row,
      event_types: [...(row.event_types || [])],
      match: {
        paths: [...(row.match?.paths || [])],
        api_paths: [...(row.match?.api_paths || [])],
        components: [...(row.match?.components || [])],
        permissions: [...(row.match?.permissions || [])],
      },
    })),
    ticket_rules: (doc.ticket_rules || []).map((row) => ({
      ...row,
      field_map: { ...newTicketRule().field_map, ...row.field_map },
      complete_statuses: [...(row.complete_statuses || [])],
    })),
  };
}
