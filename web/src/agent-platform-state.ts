export const platformTabs = [
  "search",
  "memory",
  "models",
  "execution",
  "observability",
] as const;
export type PlatformTab = (typeof platformTabs)[number];
export type SecretChoice = "keep" | "replace" | "clear";
export function newPlatformID(): string {
  // getRandomValues also works on approved intranet HTTP origins where
  // randomUUID is not exposed. IDs are stable for the lifetime of a draft.
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return (
    "p-" +
    Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")
  );
}
export const platformTabLabels: Record<PlatformTab, string> = {
  search: "검색",
  memory: "지식 메모리",
  models: "모델",
  execution: "격리 실행",
  observability: "관측성",
};
export const modelTypes = [
  { value: "openai", label: "OpenAI 호환" },
  { value: "anthropic", label: "Anthropic" },
  { value: "gemini", label: "Gemini" },
  { value: "ollama", label: "Ollama" },
];
export const modelRoles = [
  ["default", "공통 기본"],
  ["primary_agent", "주 에이전트"],
  ["assistant", "보조 에이전트"],
  ["simple", "간단 작업"],
  ["simple_json", "구조화 응답"],
  ["adviser", "자문"],
  ["generator", "계획 생성"],
  ["refiner", "계획 보완"],
  ["searcher", "검색"],
  ["enricher", "정보 보완"],
  ["coder", "코드 분석"],
  ["installer", "환경 준비"],
  ["pentester", "진단 분석"],
  ["reflector", "검토·성찰"],
  ["copilot", "AI 분석 도우미"],
].map(([value, label]) => ({ value, label }));
export function movePriorityItem<T>(
  items: readonly T[],
  index: number,
  direction: -1 | 1,
): T[] {
  const next = [...items],
    target = index + direction;
  if (index < 0 || index >= next.length || target < 0 || target >= next.length)
    return next;
  [next[index], next[target]] = [next[target], next[index]];
  return next;
}
export function secretChange(
  mode: SecretChoice,
  value: string,
  name = "api_key",
): Record<string, string | boolean> {
  if (mode === "clear") return { ["clear_" + name]: true };
  if (mode === "replace") {
    if (!value.trim()) throw new Error("교체할 새 비밀값을 입력하세요.");
    return { [name]: value };
  }
  return {};
}
export function webAddress(value: string) {
  try {
    const url = new URL(value);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password
    )
      return null;
    return url.href;
  } catch {
    return null;
  }
}
export function providerEndpoint(value: string) {
  const address = webAddress(value);
  if (!address)
    throw new Error("사용자 정보가 없는 HTTP 또는 HTTPS 주소를 입력하세요.");
  const url = new URL(address);
  if (url.search || url.hash)
    throw new Error("연결 주소에 쿼리 문자열이나 해시를 포함할 수 없습니다.");
  return value.trim();
}
export function safeProviderFields<T extends Record<string, unknown>>(
  value: T,
): T {
  return Object.fromEntries(
    Object.entries(value).filter(
      ([key]) =>
        !key.endsWith("_configured") &&
        !key.startsWith("clear_") &&
        key !== "api_key" &&
        key !== "client_key_pem",
    ),
  ) as T;
}
