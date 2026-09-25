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

// trackingOrigin (internal/app/tracking.go) decides which origins can be saved,
// so the same rules are applied here on the raw text: the browser URL parser
// folds legacy IPv4 aliases (0177.0.0.1, 0x7f.1, 2130706433) into canonical
// addresses, which is exactly what the server refuses so aliases cannot bypass
// app-origin denial. internal/app/testdata/tracking-origins.json holds the
// vectors both readers run.
const trackingOriginForbidden = /[*;,'"\\ \t\r\n]/;
const trackingOriginShape = /^(https?):\/\/([^/?#]*)(?:\/?#?)$/i;
const trackingOriginIPv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const trackingOriginLabel = /^[a-z0-9-]+$/;
const trackingOriginUint64 = 18446744073709551615n;

// Canonical host, or null when the server would refuse it. Bracketed IPv6 and
// non-ASCII hosts are canonicalised by the URL parser, which also rejects
// invalid punycode; ASCII names are checked directly so numeric hosts never
// reach the parser's legacy IPv4 handling. IPv4-mapped IPv6 literals normalise
// to the compressed form here and to the dotted form on the server, and both
// forms are accepted by the server.
function trackingOriginHost(host: string): string | null {
  if (host.startsWith("[")) {
    try {
      const inner = new URL("http://" + host + "/").hostname;
      return inner.startsWith("[") ? inner : null;
    } catch {
      return null;
    }
  }
  const ipv4 = trackingOriginIPv4.exec(host);
  if (ipv4)
    return ipv4
      .slice(1)
      .every((part) => part === String(Number(part)) && Number(part) < 256)
      ? host
      : null;
  let ascii = host;
  if (/[^\x21-\x7e]/.test(host) || /(^|\.)xn--/.test(host)) {
    try {
      ascii = new URL("http://" + host + "/").hostname;
    } catch {
      return null;
    }
  }
  if (ascii.length > 253) return null;
  const labels = ascii.split(".");
  for (const label of labels)
    if (
      label.length > 63 ||
      label.startsWith("-") ||
      label.endsWith("-") ||
      !trackingOriginLabel.test(label)
    )
      return null;
  const last = labels[labels.length - 1];
  if (last.startsWith("0x")) return null;
  if (/^\d+$/.test(last) && BigInt(last) <= trackingOriginUint64) return null;
  return ascii;
}

// Normalised origin, or null when the server would refuse to store it.
export function normalizeTrackingOrigin(raw: string): string | null {
  if (
    new TextEncoder().encode(raw).length > 300 ||
    trackingOriginForbidden.test(raw)
  )
    return null;
  const shape = trackingOriginShape.exec(raw);
  if (!shape) return null;
  const scheme = shape[1].toLowerCase();
  const authority = shape[2].toLowerCase();
  if (!authority || authority.includes("@") || authority.includes("%"))
    return null;
  // A missing bracket leaves an unparsable host below, so no guard is needed.
  const close = authority.startsWith("[") ? authority.indexOf("]") + 1 : 0;
  const colon = authority.indexOf(":", close);
  const host = trackingOriginHost(
    colon < 0 ? authority : authority.slice(0, colon),
  );
  if (!host) return null;
  const port = colon < 0 ? "" : authority.slice(colon + 1);
  if (port === "") return scheme + "://" + host;
  if (!/^\d+$/.test(port)) return null;
  const number = Number(port);
  if (number < 1 || number > 65535) return null;
  return (number === 80 && scheme === "http") ||
    (number === 443 && scheme === "https")
    ? scheme + "://" + host
    : scheme + "://" + host + ":" + number;
}

// Origin an administrator could add to the allowed list for a blocked URI. The
// server reads the authority of the relayed URI the same way, so credentials
// are dropped and the path, query and fragment are ignored.
export function trackingViolationOrigin(blockedURI: string): string | null {
  const shape = /^(https?):\/\/([^/?#]*)/i.exec(blockedURI.trim());
  if (!shape) return null;
  const authority = shape[2].slice(shape[2].lastIndexOf("@") + 1);
  return normalizeTrackingOrigin(shape[1] + "://" + authority);
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
  // The server counts len+1 for each origin it keeps, so duplicates are
  // measured once and the limit is reached one byte earlier than a join would.
  const application =
    normalizeTrackingOrigin(applicationOrigin) ?? applicationOrigin;
  const kept: string[] = [];
  let bytes = 0;
  for (const raw of value.allowed_origins) {
    const origin = raw.trim();
    if (new TextEncoder().encode(origin).length > 300) {
      errors.push("각 허용 주소는 300바이트 이하여야 합니다.");
      break;
    }
    const normal = normalizeTrackingOrigin(origin);
    if (!normal || normal === application) {
      errors.push(
        "허용 주소는 Hunter와 다른 정확한 HTTP(S) 원점만 입력하세요. 경로·와일드카드·자격정보는 허용되지 않습니다.",
      );
      break;
    }
    if (kept.includes(normal)) continue;
    bytes += new TextEncoder().encode(normal).length + 1;
    if (bytes > 1536) {
      errors.push("허용 주소의 전체 길이는 1,536바이트 이하여야 합니다.");
      break;
    }
    kept.push(normal);
  }
  return errors;
}
