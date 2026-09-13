import { safeReturnPath } from "./navigation.ts";

export type LoginConfiguration = {
  oidc_enabled?: boolean;
  oidc_auto_login?: boolean;
  oidc_auto_login_allowed?: boolean;
  version?: string;
};

const automaticAttemptKey = "hunter.oidc-auto.v1";
const automaticAttemptTTL = 10 * 60 * 1000;

export function safeLoginReturn(value: unknown): string | null {
  const path = safeReturnPath(value, true);
  return path && new TextEncoder().encode(path).length <= 4096 ? path : null;
}

export function loginReturn(
  location: {
    pathname: string;
    search: string;
    hash?: string;
    state?: { from?: unknown } | null;
  },
  stored?: string | null,
): string | null {
  const query = new URLSearchParams(location.search);
  return (
    safeLoginReturn(location.state?.from) ||
    (location.pathname === "/login"
      ? safeLoginReturn(query.get("return_to"))
      : null) ||
    safeLoginReturn(
      location.pathname + location.search + (location.hash || ""),
    ) ||
    safeLoginReturn(stored)
  );
}

export function automaticLoginSuppressed(now = Date.now()): boolean {
  try {
    const until = Number(sessionStorage.getItem(automaticAttemptKey));
    return (
      Number.isFinite(until) &&
      until > now &&
      until <= now + 24 * 60 * 60 * 1000
    );
  } catch {
    return false;
  }
}

export function suppressAutomaticLogin(duration = automaticAttemptTTL) {
  try {
    sessionStorage.setItem(automaticAttemptKey, String(Date.now() + duration));
  } catch {}
}

export function clearAutomaticLoginSuppression() {
  try {
    sessionStorage.removeItem(automaticAttemptKey);
  } catch {}
}

export function shouldAutomaticallyLogin(
  authStatus: number,
  config: LoginConfiguration,
  search: string,
  suppressed: boolean,
): boolean {
  const query = new URLSearchParams(search);
  return (
    authStatus === 401 &&
    config.oidc_enabled === true &&
    config.oidc_auto_login === true &&
    config.oidc_auto_login_allowed === true &&
    !suppressed &&
    query.get("local") !== "1" &&
    query.get("sso") !== "skip" &&
    !query.has("error")
  );
}

export function oidcLoginURL(
  mode: "auto" | "interactive",
  target: unknown,
): string {
  const query = new URLSearchParams({
    mode,
    return_to: safeLoginReturn(target) || "/dashboard",
  });
  return `/api/auth/oidc/login?${query}`;
}

export function localLoginURL(target: unknown): string {
  const query = new URLSearchParams({ local: "1" });
  const safe = safeLoginReturn(target);
  if (safe) query.set("return_to", safe);
  return `/login?${query}`;
}

export function oidcLoginMessage(search: string): string {
  const code = new URLSearchParams(search).get("error");
  if (!code) return "";
  if (["oidc_login_required", "oidc_interaction_required"].includes(code))
    return "유효한 사내 로그인 세션이 없거나 추가 인증이 필요합니다. 사내 SSO 또는 로컬 계정으로 로그인해 주세요.";
  if (code === "oidc_configuration")
    return "사내 인증 서버에 연결하지 못했습니다. 로컬 계정으로 로그인하거나 관리자에게 SSO 설정 확인을 요청해 주세요.";
  return "SSO 로그인을 완료하지 못했습니다. 사내 SSO를 다시 선택하거나 로컬 계정으로 로그인해 주세요.";
}
