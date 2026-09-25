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

// RFC 3492 decoding of one xn-- label body, mirroring the decoder in
// golang.org/x/net/idna that the server reaches through idna.Lookup.ToASCII.
// URL parsers disagree on already-ASCII xn-- labels — Node 26 hands
// "xn--a.internal" back untouched while ICU builds reject it — so the decode is
// done here instead of being delegated, and only the Unicode direction, where
// the parsers agree, is left to the parser.
function trackingPunycodeDecode(encoded: string): string | null {
  if (encoded === "") return "";
  const pos0 = encoded.lastIndexOf("-") + 1;
  if (pos0 === 1) return null;
  if (pos0 === encoded.length) return encoded.slice(0, -1);
  const output = pos0 === 0 ? [] : [...encoded.slice(0, pos0 - 1)];
  let pos = pos0;
  let i = 0;
  let n = 128;
  let bias = 72;
  while (pos < encoded.length) {
    const oldI = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (pos === encoded.length) return null;
      const digit = trackingPunycodeDigit(encoded[pos]);
      if (digit === null) return null;
      pos += 1;
      i += digit * w;
      if (i > 0x7fffffff) return null;
      const t = Math.min(Math.max(k - bias, 1), 26);
      if (digit < t) break;
      w *= 36 - t;
      if (w > 0x7fffffff) return null;
    }
    const x = output.length + 1;
    bias = trackingPunycodeAdapt(i - oldI, x, oldI === 0);
    n += Math.floor(i / x);
    i %= x;
    if (n > 0x10ffff) return null;
    output.splice(i, 0, String.fromCodePoint(n));
    i += 1;
  }
  return output.join("");
}

function trackingPunycodeDigit(c: string): number | null {
  const n = c.charCodeAt(0);
  if (n >= 0x30 && n <= 0x39) return n - 0x30 + 26;
  if (n >= 0x61 && n <= 0x7a) return n - 0x61;
  return null;
}

function trackingPunycodeAdapt(
  delta: number,
  points: number,
  first: boolean,
): number {
  let d = first ? Math.floor(delta / 700) : Math.floor(delta / 2);
  d += Math.floor(d / points);
  let k = 0;
  for (; d > 455; k += 36) d = Math.floor(d / 35);
  return k + Math.floor((36 * d) / (d + 38));
}

// Canonical host, or null when the server would refuse it. Bracketed IPv6 and
// non-ASCII hosts are canonicalised by the URL parser; xn-- labels are decoded
// above and re-encoded through that same parser, the way idna.Lookup.ToASCII
// does on the server, so an undecodable or disallowed label is refused whatever
// the runtime would have made of its ASCII form. Plain ASCII names are checked
// directly so numeric hosts never reach the parser's legacy IPv4 handling.
// IPv4-mapped IPv6 literals normalise to the compressed form here and to the
// dotted form on the server, and both forms are accepted by the server.
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
  let unicode = host;
  if (/(^|\.)xn--/.test(host)) {
    const labels = host.split(".");
    for (let i = 0; i < labels.length; i += 1) {
      if (!labels[i].startsWith("xn--")) continue;
      // An ACE label is ASCII by definition, and every URL parser this screen
      // has relied on refuses a mixed spelling. idna decodes a few of them into
      // a name that is not the one on screen, so they stay refused here rather
      // than being shown as an origin the administrator did not write.
      if (/[^\x00-\x7f]/.test(labels[i])) return null;
      const decoded = trackingPunycodeDecode(labels[i].slice(4));
      // x/net/idna also refuses a non-empty xn-- label that decodes to plain
      // ASCII, because such a label is a second spelling of a name that is
      // already representable. An empty decode leaves an empty label, which the
      // label checks below refuse the way the server's DNS length check does.
      if (decoded === null || (decoded !== "" && !/[^\x00-\x7f]/.test(decoded)))
        return null;
      labels[i] = decoded;
    }
    unicode = labels.join(".");
  }
  let ascii = unicode;
  if (/[^\x21-\x7e]/.test(unicode)) {
    try {
      ascii = new URL("http://" + unicode + "/").hostname;
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
