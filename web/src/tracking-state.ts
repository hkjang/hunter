export type TrackingPage = { path: string; title: string };
export type TrackingConfiguration = {
  enabled: boolean;
  name: string;
  script: string;
  allowed_origins: string[];
  revision: number;
  updated_at: string | null;
};
export type TrackingValidation = {
  ok: boolean;
  checks: { name: string; message: string; ok: boolean }[];
  preview_token: string;
  preview_url: string;
};
export type TrackingViolationReport = {
  blocked_uri: string;
  directive: string;
};
export type TrackingViolation = {
  origin: string;
  directive: string;
  page: string;
  count: number;
  first_seen: string;
  last_seen: string;
  allowed: boolean;
};
export const emptyTracking: TrackingConfiguration = {
  enabled: false,
  name: "방문 통계",
  script: "",
  allowed_origins: [],
  revision: 0,
  updated_at: null,
};

const pages: Record<string, string> = {
  "/dashboard": "보안 현황",
  "/triage": "조치함",
  "/services": "서비스 자산",
  "/software": "소프트웨어 구성",
  "/findings": "발견 건",
  "/remediations": "개선 요청",
  "/scans": "진단 실행",
  "/campaigns": "진단 캠페인",
  "/agents": "에이전트 진단",
  "/schedules": "진단 예약",
  "/graph": "영향 관계도",
  "/scenarios": "권한 검증",
  "/reports": "보고서",
  "/contributions": "보안 기여",
  "/copilot": "AI 분석 도우미",
};

// Only fixed templates and titles leave the application. Do not pass document
// titles, location.href, search/hash, component state, resource names or user IDs.
export function trackingPage(pathname: string): TrackingPage | null {
  if (pages[pathname]) return { path: pathname, title: pages[pathname] };
  for (const base of ["/software", "/campaigns", "/agents"]) {
    if (new RegExp(`^${base}/[^/]+/?$`).test(pathname))
      return { path: `${base}/:id`, title: `${pages[base]} 상세` };
  }
  return null;
}

export function trackingFrameURL(
  value: unknown,
  preview = false,
): string | null {
  if (
    typeof value !== "string" ||
    !value.startsWith("/api/tracking/") ||
    /[\\\u0000-\u0020\u007f]/.test(value)
  )
    return null;
  try {
    const url = new URL(value, "https://hunter.invalid");
    if (url.origin !== "https://hunter.invalid" || url.hash) return null;
    if (preview)
      return /^\/api\/tracking\/preview\/[A-Za-z0-9_-]+$/.test(url.pathname) &&
        !url.search
        ? url.pathname
        : null;
    if (
      url.pathname !== "/api/tracking/frame" ||
      [...url.searchParams.keys()].some((key) => key !== "revision") ||
      url.searchParams.getAll("revision").length !== 1 ||
      !/^\d+$/.test(url.searchParams.get("revision") || "")
    )
      return null;
    return url.pathname + url.search;
  } catch {
    return null;
  }
}

export function trackingStatus(
  value: unknown,
): "ready" | "error" | "blocked" | null {
  if (!value || typeof value !== "object") return null;
  const event = value as { type?: unknown; status?: unknown };
  return event.type === "hunter:tracking-status" &&
    typeof event.status === "string" &&
    ["ready", "error", "blocked"].includes(event.status)
    ? (event.status as "ready" | "error" | "blocked")
    : null;
}

// The sandboxed frame relays securitypolicyviolation events; only http(s)
// targets can ever be allowed, so anything else is dropped here.
export function trackingViolation(
  value: unknown,
): TrackingViolationReport | null {
  if (!value || typeof value !== "object") return null;
  const event = value as {
    type?: unknown;
    blocked_uri?: unknown;
    directive?: unknown;
  };
  if (
    event.type !== "hunter:tracking-violation" ||
    typeof event.blocked_uri !== "string" ||
    typeof event.directive !== "string" ||
    event.blocked_uri.length > 300 ||
    event.directive.length > 40 ||
    !/^https?:\/\//i.test(event.blocked_uri) ||
    !/^[a-z]+(?:-[a-z]+)*$/i.test(event.directive)
  )
    return null;
  return {
    blocked_uri: event.blocked_uri,
    directive: event.directive.toLowerCase(),
  };
}

// Origin an administrator could add to the allowed list for a blocked URI.
export function trackingViolationOrigin(blockedURI: string): string | null {
  try {
    const url = new URL(blockedURI);
    return ["http:", "https:"].includes(url.protocol) && url.host
      ? url.origin
      : null;
  } catch {
    return null;
  }
}

export function validateTrackingDraft(
  value: TrackingConfiguration,
  applicationOrigin: string,
): string[] {
  const errors: string[] = [];
  if (!value.name.trim() || [...value.name.trim()].length > 100)
    errors.push("이름은 1~100자로 입력하세요.");
  if (new TextEncoder().encode(value.script).length > 32768)
    errors.push("추적 스크립트는 최대 32KiB입니다.");
  if (value.enabled && !value.script.trim())
    errors.push("방문 추적을 사용하려면 스크립트를 입력하세요.");
  if (value.allowed_origins.length > 10)
    errors.push("허용 주소는 최대 10개입니다.");
  if (new TextEncoder().encode(value.allowed_origins.join(" ")).length > 1536)
    errors.push("허용 주소의 전체 길이는 1,536바이트 이하여야 합니다.");
  for (const origin of value.allowed_origins) {
    if (new TextEncoder().encode(origin).length > 300) {
      errors.push("각 허용 주소는 300바이트 이하여야 합니다.");
      break;
    }
    try {
      const url = new URL(origin);
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.pathname !== "/" ||
        url.search ||
        url.hash ||
        /[?*#;,"'\\\s]/.test(origin) ||
        url.origin === applicationOrigin
      )
        throw new Error();
    } catch {
      errors.push(
        "허용 주소는 Hunter와 다른 정확한 HTTP(S) 원점만 입력하세요. 경로·와일드카드·자격정보는 허용되지 않습니다.",
      );
      break;
    }
  }
  return errors;
}
