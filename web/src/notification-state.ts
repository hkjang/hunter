export const notificationTabs = ["channels", "rules", "history"] as const;
export type NotificationTab = (typeof notificationTabs)[number];
export type ChannelKind = "smtp" | "sms" | "kakao" | "webhook";
export type SecretMode = "keep" | "replace" | "clear";
export const channelKinds = [
  { value: "smtp", label: "이메일 · SMTP" },
  { value: "sms", label: "문자 · 사내 API" },
  { value: "kakao", label: "카카오톡 · 사내 API" },
  { value: "webhook", label: "일반 HTTP" },
];
export const notificationEvents = [
  { value: "finding.created", label: "새 발견 건 등록" },
  { value: "finding.updated", label: "발견 건 변경" },
  { value: "finding.due", label: "발견 건 조치 기한" },
  { value: "finding.due_soon", label: "조치 기한 예고" },
  { value: "finding.unacknowledged", label: "업무 미확인 후속 알림" },
  { value: "team.weekly", label: "팀 주간 보고" },
  { value: "scan.completed", label: "진단 완료" },
  { value: "scan.failed", label: "진단 실패" },
  { value: "approval.pending", label: "검토 · 승인 대기" },
];
export const deliveryStatuses = [
  { value: "queued", label: "발송 대기", color: "gray" },
  { value: "sending", label: "발송 중", color: "blue" },
  { value: "sent", label: "게이트웨이 접수", color: "teal" },
  { value: "retry", label: "재시도 대기", color: "orange" },
  { value: "failed", label: "발송 실패", color: "red" },
  { value: "uncertain", label: "결과 확인 필요", color: "yellow" },
  { value: "cancelled", label: "취소됨", color: "gray" },
];
export const defaultPayload = {
  to: "{{message.recipient}}",
  subject: "{{message.subject}}",
  message: "{{message.body}}",
  eventId: "{{message.id}}",
};
export const notificationPayloadPresets = [
  { id: "standard", label: "기본 HTTP 예시", value: defaultPayload },
  {
    id: "sms",
    label: "문자 게이트웨이 예시",
    value: {
      to: "{{message.recipient}}",
      from: "등록한 발신번호",
      text: "{{message.body}}",
    },
  },
  {
    id: "kakao",
    label: "알림톡 게이트웨이 예시",
    value: {
      recipient: "{{message.recipient}}",
      senderKey: "승인된 발신 프로필 키",
      templateCode: "승인된 템플릿 코드",
      message: "{{message.body}}",
    },
  },
];
export type ChannelDraft = {
  name: string;
  type: ChannelKind;
  enabled: boolean;
  config: Record<string, unknown>;
  headersJSON: string;
  bodyJSON: string;
  secretMode: SecretMode;
  secret: string;
};
export function channelDraft(source?: {
  name: string;
  type: ChannelKind;
  enabled: boolean;
  config: Record<string, unknown>;
}): ChannelDraft {
  const config = source?.config || {};
  return {
    name: source?.name || "",
    type: source?.type || "smtp",
    enabled: source?.enabled || false,
    config: { ...config },
    headersJSON: JSON.stringify(config.headers || {}, null, 2),
    bodyJSON: JSON.stringify(config.body_template || defaultPayload, null, 2),
    secretMode: source ? "keep" : "replace",
    secret: "",
  };
}
export function channelConfigDefaults(type: ChannelKind) {
  return type === "smtp"
    ? {
        host: "",
        port: 587,
        security: "starttls",
        from: "",
        username: "",
        auth: "plain",
        timeout_seconds: 20,
      }
    : {
        endpoint: "",
        method: "POST",
        format: "json",
        auth: "bearer",
        username: "",
        auth_header: "",
        success_path: "",
        success_value: "",
        id_path: "",
        idempotency_header: "Idempotency-Key",
        idempotency_supported: false,
        timeout_seconds: 20,
      };
}
function objectJSON(value: string, caption: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${caption}에 올바른 JSON을 입력하세요.`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error(`${caption}은 JSON 객체여야 합니다.`);
  return parsed as Record<string, unknown>;
}
export function channelPayload(
  draft: ChannelDraft,
  original?: { updated_at: string },
) {
  if (!draft.name.trim()) throw new Error("채널 이름을 입력하세요.");
  if (new TextEncoder().encode(draft.name.trim()).length > 200)
    throw new Error("채널 이름은 UTF-8 기준 200바이트까지 입력하세요.");
  const config: Record<string, unknown> = {
    ...channelConfigDefaults(draft.type),
    ...draft.config,
  };
  if (draft.type === "smtp") {
    if (!String(config.host || "").trim() || !String(config.from || "").trim())
      throw new Error("SMTP 서버와 발신 주소를 입력하세요.");
    if (
      config.security === "none" &&
      (String(config.username || "").trim() ||
        (draft.secretMode === "replace" && draft.secret))
    )
      throw new Error(
        "암호화 없는 사내 릴레이에서는 인증 정보를 사용할 수 없습니다.",
      );
  } else {
    if (!String(config.endpoint || "").trim())
      throw new Error("연결할 사내 API 주소를 입력하세요.");
    config.headers = objectJSON(draft.headersJSON, "정적 헤더");
    if (
      Object.values(config.headers as object).some(
        (value) => typeof value !== "string",
      )
    )
      throw new Error("정적 헤더의 값은 문자열이어야 합니다.");
    if (new TextEncoder().encode(draft.bodyJSON).length > 65536)
      throw new Error("요청 본문 템플릿은 64KiB 이하로 입력하세요.");
    config.body_template = objectJSON(draft.bodyJSON, "요청 본문 템플릿");
    if (
      config.format === "form" &&
      Object.values(config.body_template as object).some(
        (value) => typeof value !== "string",
      )
    )
      throw new Error("Form 방식의 본문은 중첩 없이 문자열 값으로 구성하세요.");
  }
  if (original && !original.updated_at)
    throw new Error(
      "수정 기준을 확인할 수 없습니다. 최신 채널을 다시 불러오세요.",
    );
  return {
    name: draft.name.trim(),
    type: draft.type,
    enabled: draft.enabled,
    config,
    ...(original ? { expected_updated_at: original.updated_at } : {}),
    ...(draft.secretMode === "clear"
      ? { clear_secret: true }
      : draft.secretMode === "replace" && draft.secret
        ? { secret: draft.secret }
        : {}),
  };
}
export function notificationHistoryQuery(params: URLSearchParams) {
  const result = new URLSearchParams();
  const status = params.get("status") || "";
  if (deliveryStatuses.some((item) => item.value === status))
    result.set("status", status);
  for (const key of ["channel_id", "event_type", "q"]) {
    const value = params.get(key);
    if (value) result.set(key, value.slice(0, 500));
  }
  const page = Number(params.get("page"));
  result.set(
    "page",
    Number.isSafeInteger(page) && page > 0 && page <= 1000000
      ? String(page)
      : "1",
  );
  const size = Number(params.get("size"));
  result.set("size", [10, 25, 50, 100].includes(size) ? String(size) : "25");
  const sort = params.get("sort");
  if (
    sort &&
    ["created_at", "updated_at", "available_at", "status", "attempts"].includes(
      sort,
    )
  ) {
    result.set("sort", sort);
    result.set("dir", params.get("dir") === "asc" ? "asc" : "desc");
  }
  return result.toString();
}
export const notificationVariables = [
  "event.label",
  "event.type",
  "event.time",
  "service.id",
  "service.name",
  "service.team",
  "resource.id",
  "resource.title",
  "resource.status",
  "resource.status_label",
  "resource.url",
  "finding.id",
  "finding.title",
  "finding.severity",
  "finding.severity_label",
  "finding.status",
  "finding.due_date",
  "finding.assignee",
  "finding.cve",
  "scan.id",
  "scan.name",
  "scan.status",
  "approval.id",
  "approval.status",
];
export type RuleDraft = {
  name: string;
  channel_id: string;
  enabled: boolean;
  events: string[];
  filters: { severities: string[]; service_ids: string[]; teams: string[] };
  recipients: string[];
  recipient_sources: string[];
  subject_template: string;
  body_template: string;
  max_attempts: number;
};
export function ruleDraft(source?: RuleDraft): RuleDraft {
  return source
    ? {
        name: source.name,
        channel_id: source.channel_id,
        enabled: source.enabled,
        subject_template: source.subject_template,
        body_template: source.body_template,
        max_attempts: source.max_attempts,
        events: [...(source.events || [])],
        recipients: [...(source.recipients || [])],
        recipient_sources: [...(source.recipient_sources || [])],
        filters: {
          severities: [...(source.filters?.severities || [])],
          service_ids: [...(source.filters?.service_ids || [])],
          teams: [...(source.filters?.teams || [])],
        },
      }
    : {
        name: "",
        channel_id: "",
        enabled: false,
        events: ["finding.created"],
        filters: { severities: [], service_ids: [], teams: [] },
        recipients: [],
        recipient_sources: [],
        subject_template: "[Hunter] {{event.label}} · {{resource.title}}",
        body_template:
          "{{resource.title}}\n서비스: {{service.name}}\n상태: {{resource.status_label}}\n이벤트: {{event.label}}\n시각: {{event.time}}\n자세히 보기: {{resource.url}}",
        max_attempts: 3,
      };
}
export function rulePayload(
  draft: RuleDraft,
  original?: { updated_at: string },
) {
  const size = (value: string) => new TextEncoder().encode(value).length;
  if (!draft.name.trim() || !draft.channel_id)
    throw new Error("규칙 이름과 발송 채널을 입력하세요.");
  if (size(draft.name.trim()) > 200)
    throw new Error("규칙 이름은 UTF-8 기준 200바이트까지 입력하세요.");
  if (
    !draft.events.length ||
    draft.events.some(
      (event) => !notificationEvents.some((item) => item.value === event),
    )
  )
    throw new Error("발송 이벤트를 하나 이상 선택하세요.");
  const recipients = [
    ...new Set(draft.recipients.map((value) => value.trim()).filter(Boolean)),
  ];
  const sources = [...new Set(draft.recipient_sources || [])];
  if (
    sources.some(
      (value) =>
        !["assignee", "service_owner", "team", "on_call"].includes(value),
    )
  )
    throw new Error("동적 수신자 종류를 확인하세요.");
  if ((!recipients.length && !sources.length) || recipients.length > 100)
    throw new Error(
      "고정 수신자를 1~100명 입력하거나 동적 수신자를 선택하세요.",
    );
  if (!draft.subject_template.trim() || size(draft.subject_template) > 200)
    throw new Error("제목 템플릿은 UTF-8 기준 1~200바이트로 입력하세요.");
  if (!draft.body_template.trim() || size(draft.body_template) > 16000)
    throw new Error("본문 템플릿은 UTF-8 기준 1~16,000바이트로 입력하세요.");
  if (
    !Number.isInteger(draft.max_attempts) ||
    draft.max_attempts < 1 ||
    draft.max_attempts > 5
  )
    throw new Error("최대 시도 횟수는 1~5회로 입력하세요.");
  if (original && !original.updated_at)
    throw new Error(
      "수정 기준을 확인할 수 없습니다. 최신 규칙을 다시 불러오세요.",
    );
  return {
    ...ruleDraft(draft),
    name: draft.name.trim(),
    recipients,
    ...(original ? { expected_updated_at: original.updated_at } : {}),
  };
}
