export type NavigationEntry = { path: string; label: string; group?: string };
export type NavigationHistory = { favorites: string[]; recent: string[] };
export const navigationAliases: Record<string, string[]> = {
  "/admin/agent-platform": [
    "agent platform",
    "provider",
    "model",
    "search",
    "memory",
    "docker",
    "observability",
    "연동",
    "모델",
    "검색",
    "메모리",
    "관측성",
    "격리 실행",
  ],
  "/admin/automation": [
    "automation",
    "자동화",
    "당직",
    "묶음",
    "업무 확인",
    "주간 보고",
    "itsm",
    "콜백",
    "대체 채널",
  ],
  "/personal/inbox": ["inbox", "내 알림", "업무 알림", "확인 대기"],
  "/triage": ["triage", "queue", "risk", "조치", "위험", "기한", "sla"],
  "/software": [
    "software",
    "sbom",
    "component",
    "dependency",
    "구성",
    "의존성",
    "라이선스",
  ],
  "/campaigns": ["campaigns", "campaign", "compare", "캠페인", "결과 비교"],
  "/admin/intelligence": ["intelligence", "kev", "epss", "위협 정보", "반입"],
  "/admin/notifications": [
    "notifications",
    "notification",
    "알림",
    "문자",
    "메일",
    "카카오톡",
    "smtp",
  ],
  "/admin/operations": ["operations", "health", "운영", "점검"],
  "/dashboard": ["dashboard", "home", "홈", "대시보드", "현황"],
  "/services": ["services", "assets", "자산", "서비스"],
  "/findings": ["findings", "vulnerability", "취약점", "발견"],
  "/remediations": ["remediation", "fix", "개선", "수정"],
  "/scans": ["scans", "scan", "스캔", "진단"],
  "/agents": ["agents", "agent", "pentagi", "에이전트"],
  "/schedules": ["schedules", "schedule", "예약", "스케줄"],
  "/graph": ["graph", "관계", "그래프", "영향"],
  "/scenarios": ["scenarios", "authorization", "권한", "시나리오"],
  "/reports": ["reports", "report", "리포트", "보고서"],
  "/contributions": ["contributions", "bounty", "기여", "바운티"],
  "/copilot": ["copilot", "ai", "chat", "채팅", "분석"],
  "/approvals": ["approvals", "approval", "review", "승인", "검토"],
  "/admin/integrations": ["integrations", "integration", "연동", "연결"],
  "/admin/discovery": ["discovery", "discovery assets", "발견", "자동발견"],
  "/admin/policies": ["policies", "policy", "정책"],
  "/admin/scopes": ["scopes", "scope", "범위"],
  "/admin/auth-profiles": ["auth profiles", "인증", "테스트 계정"],
  "/admin/workers": ["workers", "worker", "워커", "이벤트"],
  "/admin/users": ["users", "user", "사용자", "계정", "역할"],
  "/admin/audit": ["audit", "logs", "감사", "로그"],
  "/admin/settings": [
    "settings",
    "setting",
    "설정",
    "sso",
    "oidc",
    "keycloak",
    "키클락",
    "ai 설정",
  ],
  "/personal/profile": ["profile", "프로필", "내 정보", "비밀번호"],
  "/personal/keys": ["keys", "api key", "mcp", "키", "토큰"],
};
const initialLetters = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ";
export function normalizeNavigationText(value: string) {
  return value
    .normalize("NFKC")
    .toLocaleLowerCase("ko-KR")
    .replace(/[^\p{L}\p{N}]/gu, "");
}
export function hangulInitials(value: string) {
  return [...value]
    .map((letter) => {
      const code = letter.charCodeAt(0) - 0xac00;
      return code >= 0 && code < 11172
        ? initialLetters[Math.floor(code / 588)]
        : letter;
    })
    .join("");
}
export function searchNavigation<T extends NavigationEntry>(
  entries: T[],
  query: string,
): T[] {
  const tokens = query
    .trim()
    .split(/\s+/u)
    .map(normalizeNavigationText)
    .filter(Boolean);
  if (!tokens.length) return entries;
  return entries
    .map((entry, index) => {
      const label = normalizeNavigationText(entry.label),
        initials = normalizeNavigationText(hangulInitials(entry.label));
      const aliases = (navigationAliases[entry.path] || []).map(
        normalizeNavigationText,
      );
      const fields = [
        label,
        initials,
        normalizeNavigationText(entry.path),
        ...aliases,
      ];
      if (
        !tokens.every((token) => fields.some((field) => field.includes(token)))
      )
        return null;
      const whole = normalizeNavigationText(query);
      const score =
        label === whole
          ? 0
          : label.startsWith(whole)
            ? 1
            : label.includes(whole)
              ? 2
              : initials.includes(whole)
                ? 3
                : 4;
      return { entry, index, score };
    })
    .filter(
      (value): value is { entry: T; index: number; score: number } =>
        value !== null,
    )
    .sort((a, b) => a.score - b.score || a.index - b.index)
    .map((value) => value.entry);
}
export function safeReturnPath(value: unknown): string | null {
  if (
    typeof value !== "string" ||
    value.length > 4096 ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    /[\\\u0000-\u001f\u007f]/.test(value)
  )
    return null;
  try {
    const url = new URL(value, "https://hunter.invalid");
    const decoded = decodeURIComponent(url.pathname);
    if (
      url.origin !== "https://hunter.invalid" ||
      decoded.startsWith("//") ||
      decoded.includes("\\") ||
      /[\u0000-\u001f\u007f]/.test(decoded) ||
      /^\/(login|api|mcp)(\/|$)/i.test(decoded) ||
      url.pathname === "/"
    )
      return null;
    return url.pathname + url.search;
  } catch {
    return null;
  }
}
function menuPaths(value: unknown): string[] {
  return Array.isArray(value)
    ? [
        ...new Set(
          value.filter(
            (item): item is string =>
              typeof item === "string" &&
              safeReturnPath(item) === item &&
              !item.includes("?") &&
              !item.includes("#"),
          ),
        ),
      ].slice(0, 50)
    : [];
}
export function parseNavigationHistory(
  value: string | null,
): NavigationHistory {
  try {
    const parsed = JSON.parse(value || "{}");
    return {
      favorites: menuPaths(parsed?.favorites),
      recent: menuPaths(parsed?.recent),
    };
  } catch {
    return { favorites: [], recent: [] };
  }
}
export function navigationStorageKey(userId: string) {
  return `hunter.navigation.v1:${encodeURIComponent(userId)}`;
}
export function recordMenuVisit(
  history: NavigationHistory,
  path: string,
): NavigationHistory {
  if (history.recent[0] === path) return history;
  return {
    ...history,
    recent: [path, ...history.recent.filter((value) => value !== path)].slice(
      0,
      8,
    ),
  };
}
export function toggleMenuFavorite(
  history: NavigationHistory,
  path: string,
): NavigationHistory {
  return {
    ...history,
    favorites: history.favorites.includes(path)
      ? history.favorites.filter((value) => value !== path)
      : [...history.favorites, path].slice(0, 50),
  };
}
export function visibleSavedMenus<T extends NavigationEntry>(
  entries: T[],
  paths: string[],
): T[] {
  const allowed = new Map(entries.map((entry) => [entry.path, entry]));
  return paths.flatMap((path) => {
    const entry = allowed.get(path);
    return entry ? [entry] : [];
  });
}
const returnKey = "hunter.login-return.v1";
export function saveLoginReturn(path: unknown, sso = false) {
  const safe = safeReturnPath(path);
  if (!safe) return;
  try {
    sessionStorage.setItem(
      returnKey,
      JSON.stringify({ path: safe, sso, createdAt: Date.now() }),
    );
  } catch {}
}
export function readLoginReturn(ssoOnly = false): string | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(returnKey) || "null");
    if (
      !value ||
      typeof value.createdAt !== "number" ||
      Date.now() - value.createdAt > 15 * 60 * 1000 ||
      Date.now() < value.createdAt
    )
      return null;
    if (ssoOnly && !value.sso) return null;
    return safeReturnPath(value.path);
  } catch {
    return null;
  }
}
export function clearLoginReturn() {
  try {
    sessionStorage.removeItem(returnKey);
  } catch {}
}
