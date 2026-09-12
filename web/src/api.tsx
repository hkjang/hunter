import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  useRef,
} from "react";
import { notifications } from "@mantine/notifications";
export type Row = Record<string, any>;
export type User = {
  id: string;
  username: string;
  name: string;
  role: string;
  team?: string;
  scopes?: string[];
  preferences?: Row;
};
export class APIError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}
export async function api<T = any>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body) headers.set("Content-Type", "application/json");
  if (options.method && !["GET", "HEAD"].includes(options.method))
    headers.set("X-Hunter-CSRF", "1");
  const res = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  const type = res.headers.get("content-type") || "";
  if (
    res.status === 401 &&
    !new URL(path, window.location.origin).pathname.startsWith("/api/auth/")
  )
    window.dispatchEvent(new Event("hunter:unauthorized"));
  if (res.status === 204 || res.status === 205) return null as T;
  if (res.ok && !type.includes("json"))
    throw new APIError(
      "서버 응답 형식을 확인할 수 없습니다. 잠시 후 다시 시도해 주세요.",
      res.status,
    );
  let body: any;
  try {
    body = type.includes("json") ? await res.json() : await res.text();
  } catch {
    throw new APIError(
      res.ok
        ? "서버 응답을 읽지 못했습니다. 새로고침 후 다시 시도해 주세요."
        : `요청을 처리하지 못했습니다 (${res.status})`,
      res.status,
    );
  }
  if (!res.ok)
    throw new APIError(
      typeof body?.error === "string"
        ? body.error
        : `요청을 처리하지 못했습니다 (${res.status})`,
      res.status,
    );
  return body as T;
}
export function useData<T = any>(path: string | null) {
  type Snapshot = {
    path: string | null;
    data: T | null;
    loading: boolean;
    error: string;
  };
  const [snapshot, setSnapshot] = useState<Snapshot>({
    path,
    data: null,
    loading: !!path,
    error: "",
  });
  const request = useRef<AbortController | null>(null);
  const currentPath = useRef(path);
  currentPath.current = path;
  const fetchData = useCallback(
    async (silent: boolean) => {
      if (!path || currentPath.current !== path) return;
      if (silent && request.current) return;
      request.current?.abort();
      const controller = new AbortController();
      request.current = controller;
      if (!silent)
        setSnapshot((previous) => ({
          path,
          data: previous.path === path ? previous.data : null,
          loading: previous.path !== path || previous.data === null,
          error: "",
        }));
      try {
        const data = await api<T>(path, { signal: controller.signal });
        if (!controller.signal.aborted && currentPath.current === path)
          setSnapshot({ path, data, loading: false, error: "" });
      } catch (error) {
        if (!controller.signal.aborted && currentPath.current === path)
          setSnapshot((previous) => ({
            path,
            data: previous.path === path ? previous.data : null,
            loading: false,
            error:
              error instanceof Error
                ? error.message
                : "정보를 불러오지 못했습니다",
          }));
      } finally {
        if (request.current === controller) request.current = null;
      }
    },
    [path],
  );
  const reload = useCallback(() => fetchData(false), [fetchData]);
  useEffect(() => {
    if (!path)
      setSnapshot({ path: null, data: null, loading: false, error: "" });
    else void reload();
    return () => {
      request.current?.abort();
      request.current = null;
    };
  }, [path, reload]);
  useEffect(() => {
    if (
      !path ||
      (!/^\/api\/(scans|workers|approvals)\/[^/?]+$/.test(path) &&
        ![
          "/api/dashboard",
          "/api/scans",
          "/api/agent-runs",
          "/api/workers",
          "/api/approvals",
          "/api/events",
          "/api/schedules",
        ].includes(path))
    )
      return;
    const timer = window.setInterval(() => {
      if (!document.hidden && navigator.onLine !== false) void fetchData(true);
    }, 10000);
    return () => window.clearInterval(timer);
  }, [path, fetchData]);
  const setData = useCallback(
    (value: T | null | ((previous: T | null) => T | null)) => {
      if (currentPath.current !== path || !path) return;
      request.current?.abort();
      request.current = null;
      setSnapshot((previous) => ({
        path,
        data:
          typeof value === "function"
            ? (value as (previous: T | null) => T | null)(
                previous.path === path ? previous.data : null,
              )
            : value,
        loading: false,
        error: "",
      }));
    },
    [path],
  );
  // A new URL must never render the previous URL's rows, even before effects run.
  const visible =
    path && snapshot.path === path
      ? snapshot
      : { data: null, loading: !!path, error: "" };
  return { ...visible, reload, setData };
}
export const SessionContext = createContext<{
  user: User | null;
  setUser: (v: User | null) => void;
  config: Row;
  refreshConfig: () => void;
}>({ user: null, setUser: () => {}, config: {}, refreshConfig: () => {} });
export const useSession = () => useContext(SessionContext);
export function useCan() {
  const { user } = useSession();
  return (scope: string) =>
    user?.role === "admin" ||
    (user?.scopes !== undefined
      ? user.scopes.includes(scope)
      : user?.role === "lead" ||
        (user?.role === "analyst" &&
          !scope.startsWith("admin:") &&
          !scope.includes(":manage")));
}
export function showError(e: unknown) {
  notifications.show({
    title: "요청을 완료하지 못했습니다",
    message: e instanceof Error ? e.message : String(e),
    color: "red",
    autoClose: 7000,
  });
}
export function success(message = "변경 사항을 저장했습니다") {
  notifications.show({ title: "완료", message, color: "teal" });
}
export function dateText(s: any) {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime())
    ? String(s)
    : d.toLocaleString("ko-KR", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
}
export function fullDate(s: any) {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? String(s) : d.toLocaleDateString("ko-KR");
}
export const labels: Record<string, string> = {
  critical: "심각",
  high: "높음",
  medium: "보통",
  low: "낮음",
  info: "정보",
  candidate: "탐지 후보",
  confirmed: "확인됨",
  in_progress: "개선 중",
  retest: "재검증 대기",
  resolved: "해결",
  inconclusive: "판단 불가",
  false_positive: "오탐",
  accepted: "위험 수용",
  queued: "대기 중",
  running: "진행 중",
  completed: "완료",
  failed: "실패",
  cancelled: "취소됨",
  pending: "검토 대기",
  pending_approval: "승인 대기",
  approved: "승인",
  rejected: "반려",
  production: "운영",
  staging: "검증",
  development: "개발",
  admin: "서비스 관리자",
  lead: "팀장",
  analyst: "분석가",
  viewer: "열람자",
  tier1: "Tier 1 · 핵심",
  tier2: "Tier 2 · 중요",
  tier3: "Tier 3 · 일반",
  tier4: "Tier 4 · 낮음",
  "http-baseline": "HTTP 보안 헤더",
  "import-only": "결과 가져오기",
  authorization: "업무 권한 검증",
  rest: "REST API",
  postgres: "PostgreSQL",
  webhook: "웹훅",
  "scanner-import": "진단 결과 수입",
  active: "활성",
  inactive: "비활성",
  online: "온라인",
  offline: "오프라인",
  awaiting_import: "결과 수입 대기",
  bypassed: "검토 생략",
  draft: "초안",
  dispatched: "전송 완료",
  dispatching: "전송 중",
  headers: "사용자 정의 헤더",
  bearer: "Bearer 토큰",
  basic: "Basic 인증",
  true: "예",
  false: "아니요",
};
export const label = (v: any) => labels[String(v)] || String(v ?? "—");
export const colors: Record<string, string> = {
  critical: "red",
  high: "orange",
  medium: "yellow",
  low: "blue",
  info: "gray",
  confirmed: "red",
  candidate: "orange",
  in_progress: "blue",
  retest: "violet",
  resolved: "teal",
  inconclusive: "gray",
  false_positive: "gray",
  accepted: "yellow",
  queued: "gray",
  running: "blue",
  completed: "teal",
  failed: "red",
  cancelled: "gray",
  pending: "orange",
  pending_approval: "orange",
  approved: "teal",
  rejected: "red",
  production: "orange",
  staging: "teal",
  development: "blue",
  online: "teal",
  offline: "gray",
};
export const allScopes = [
  "services:read",
  "services:write",
  "findings:read",
  "findings:write",
  "scans:read",
  "scans:write",
  "scans:approve",
  "agents:read",
  "agents:write",
  "integrations:manage",
  "admin:manage",
  "audit:read",
  "ai:use",
];
export const scopeNames: Record<string, string> = {
  "services:read": "서비스 조회",
  "services:write": "서비스 관리",
  "findings:read": "발견 건 조회",
  "findings:write": "발견 건 관리",
  "scans:read": "진단 조회",
  "scans:write": "진단 요청",
  "scans:approve": "진단 검토 · 승인",
  "agents:read": "에이전트 진단 조회",
  "agents:write": "에이전트 진단 실행 · 중지",
  "integrations:manage": "연동 관리",
  "admin:manage": "서비스 관리",
  "audit:read": "감사 기록 조회",
  "ai:use": "AI 분석 사용",
};
