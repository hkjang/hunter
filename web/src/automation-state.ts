export type AutomationContact = {
  user_id: string;
  email: string;
  phone: string;
  webhook_id: string;
  verified: boolean;
};
export type OnCallAssignment = {
  team: string;
  user_id: string;
  starts_at: string;
  ends_at: string;
};
export type NotificationAutomationConfig = {
  enabled: boolean;
  timezone: string;
  contacts: AutomationContact[];
  on_call: OnCallAssignment[];
  grouping: {
    enabled: boolean;
    window_minutes: number;
    emergency_severities: string[];
    recipient_hourly_limit: number;
  };
  calendar: {
    enabled: boolean;
    weekdays: number[];
    holidays: string[];
    remind_business_days: number;
  };
  acknowledgement: { enabled: boolean; timeout_minutes: number };
  weekly: { enabled: boolean; weekday: number; hour: number };
  retention: { enabled: boolean; payload_days: number };
};
export const automationTabs = [
  "recipients",
  "notifications",
  "providers",
  "workflows",
  "simulation",
  "history",
  "retention",
] as const;
export type AutomationTab = (typeof automationTabs)[number];
export const weekdayOptions = [
  { value: "0", label: "일요일" },
  { value: "1", label: "월요일" },
  { value: "2", label: "화요일" },
  { value: "3", label: "수요일" },
  { value: "4", label: "목요일" },
  { value: "5", label: "금요일" },
  { value: "6", label: "토요일" },
];
export const recipientSourceOptions = [
  { value: "assignee", label: "현재 담당자" },
  { value: "service_owner", label: "서비스 소유자" },
  { value: "team", label: "서비스 담당 팀" },
  { value: "on_call", label: "현재 당직자" },
];
export const automationDefaults: NotificationAutomationConfig = {
  enabled: false,
  timezone: "Asia/Seoul",
  contacts: [],
  on_call: [],
  grouping: {
    enabled: false,
    window_minutes: 5,
    emergency_severities: ["critical"],
    recipient_hourly_limit: 30,
  },
  calendar: {
    enabled: false,
    weekdays: [1, 2, 3, 4, 5],
    holidays: [],
    remind_business_days: 2,
  },
  acknowledgement: { enabled: false, timeout_minutes: 60 },
  weekly: { enabled: false, weekday: 1, hour: 9 },
  retention: { enabled: false, payload_days: 90 },
};
export function notificationAutomationDraft(
  source: NotificationAutomationConfig,
): NotificationAutomationConfig {
  return {
    enabled: !!source.enabled,
    timezone: source.timezone || "Asia/Seoul",
    contacts: (source.contacts || []).map((v) => ({
      user_id: v.user_id,
      email: v.email || "",
      phone: v.phone || "",
      webhook_id: v.webhook_id || "",
      verified: !!v.verified,
    })),
    on_call: (source.on_call || []).map((v) => ({
      team: v.team,
      user_id: v.user_id,
      starts_at: v.starts_at,
      ends_at: v.ends_at,
    })),
    grouping: {
      enabled: !!source.grouping?.enabled,
      window_minutes: source.grouping?.window_minutes ?? 5,
      recipient_hourly_limit: source.grouping?.recipient_hourly_limit ?? 30,
      emergency_severities: [...(source.grouping?.emergency_severities || [])],
    },
    calendar: {
      enabled: !!source.calendar?.enabled,
      weekdays: [...(source.calendar?.weekdays || [])],
      holidays: [...(source.calendar?.holidays || [])],
      remind_business_days: source.calendar?.remind_business_days ?? 2,
    },
    acknowledgement: {
      enabled: !!source.acknowledgement?.enabled,
      timeout_minutes: source.acknowledgement?.timeout_minutes ?? 60,
    },
    weekly: {
      enabled: !!source.weekly?.enabled,
      weekday: source.weekly?.weekday ?? 1,
      hour: source.weekly?.hour ?? 9,
    },
    retention: {
      enabled: !!source.retention?.enabled,
      payload_days: source.retention?.payload_days ?? 90,
    },
  };
}
export function notificationAutomationPayload(
  source: NotificationAutomationConfig,
  revision: string,
) {
  if (!revision)
    throw new Error("설정 기준 시각이 없습니다. 최신 설정을 다시 불러오세요.");
  const config = notificationAutomationDraft(source);
  try {
    new Intl.DateTimeFormat("ko-KR", { timeZone: config.timezone });
  } catch {
    throw new Error(
      "시간대는 Asia/Seoul 같은 유효한 IANA 이름으로 입력하세요.",
    );
  }
  const limits: [string, number, number, number][] = [
    ["묶음 대기 시간", config.grouping.window_minutes, 5, 1440],
    ["수신자별 시간당 한도", config.grouping.recipient_hourly_limit, 1, 1000],
    ["기한 예고 영업일", config.calendar.remind_business_days, 1, 30],
    ["업무 확인 제한 시간", config.acknowledgement.timeout_minutes, 5, 10080],
    ["본문 보존 기간", config.retention.payload_days, 1, 3650],
    ["주간 보고 요일", config.weekly.weekday, 0, 6],
    ["주간 보고 시각", config.weekly.hour, 0, 23],
  ];
  for (const [label, value, min, max] of limits)
    if (!Number.isInteger(value) || value < min || value > max)
      throw new Error(`${label}은 ${min}~${max} 사이 정수로 입력하세요.`);
  if (config.contacts.length > 500 || config.on_call.length > 500)
    throw new Error(
      "연락처와 당직표는 각각 최대 500개까지 등록할 수 있습니다.",
    );
  if (
    new Set(config.contacts.map((v) => v.user_id)).size !==
    config.contacts.length
  )
    throw new Error("한 사용자의 연락처는 한 번만 등록하세요.");
  if (config.contacts.some((v) => !v.user_id))
    throw new Error("연락처의 사용자를 선택하세요.");
  if (
    config.on_call.some(
      (v) =>
        !v.team.trim() ||
        !v.user_id ||
        !Number.isFinite(Date.parse(v.starts_at)) ||
        !Number.isFinite(Date.parse(v.ends_at)) ||
        Date.parse(v.starts_at) >= Date.parse(v.ends_at),
    )
  )
    throw new Error(
      "당직표의 팀·사용자·시작과 종료 시각을 확인하세요. 종료는 시작 이후여야 합니다.",
    );
  if (
    config.calendar.holidays.length > 1000 ||
    config.calendar.holidays.some(
      (v) =>
        !/^\d{4}-\d{2}-\d{2}$/.test(v) ||
        !Number.isFinite(Date.parse(v + "T00:00:00Z")) ||
        new Date(v + "T00:00:00Z").toISOString().slice(0, 10) !== v,
    )
  )
    throw new Error("휴일은 유효한 YYYY-MM-DD 날짜를 최대 1,000개 입력하세요.");
  if (
    config.calendar.weekdays.some(
      (v) => !Number.isInteger(v) || v < 0 || v > 6,
    ) ||
    (config.calendar.enabled && !config.calendar.weekdays.length)
  )
    throw new Error("영업일을 하나 이상 선택하세요.");
  return { config, expected_updated_at: revision };
}
export function localDateTime(value: string) {
  if (!value) return "";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "";
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
}
export function isoDateTime(value: string) {
  if (!value) return "";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()))
    throw new Error("유효한 날짜와 시각을 입력하세요.");
  return date.toISOString();
}
export function boundedPageQuery(
  params: URLSearchParams,
  allowed: Record<string, readonly string[]>,
  defaults: Record<string, string> = {},
) {
  const out = new URLSearchParams();
  for (const [key, values] of Object.entries(allowed)) {
    const value = params.get(key) || defaults[key] || "";
    if (values.includes(value)) out.set(key, value);
  }
  const page = Number(params.get("page") || 1),
    size = Number(params.get("size") || 25);
  out.set(
    "page",
    String(Number.isInteger(page) && page > 0 ? Math.min(page, 1000000) : 1),
  );
  out.set("size", String([10, 25, 50, 100].includes(size) ? size : 25));
  return out;
}

export function inboxAcknowledgementState(row: {
  acknowledged_at?: string | null;
  ack_due_at?: string | null;
}): "acknowledged" | "pending" | "notice" {
  return row.acknowledged_at
    ? "acknowledged"
    : row.ack_due_at
      ? "pending"
      : "notice";
}
export const simulationReasonLabels: Record<string, string> = {
  matched: "현재 조건 일치",
  channel_disabled: "채널 사용 안 함",
  event_not_selected: "선택하지 않은 이벤트",
  source_unavailable: "원본 항목 조회 불가",
  rule_disabled_or_filter_mismatch: "규칙 사용 안 함 또는 필터 불일치",
  condition_no_longer_current: "현재 상태 조건 불일치",
  recipient_limit_exceeded: "수신자 한도 초과",
  no_current_recipient: "현재 유효한 수신자 없음",
};

// Optional change groups are null in valid Go JSON responses when no value matched.
export function changeEvidenceEntries(
  input: Record<string, unknown> | null | undefined,
) {
  const labels: Record<string, string> = {
    paths: "파일",
    api_paths: "API",
    components: "구성요소",
    permissions: "권한",
  };
  return Object.entries(labels).flatMap(([key, label]) => {
    const raw = input?.[key];
    const values = Array.isArray(raw)
      ? raw.filter(
          (value): value is string =>
            typeof value === "string" && value.length > 0,
        )
      : [];
    return values.length ? [{ key, label, values }] : [];
  });
}
