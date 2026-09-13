export type AgentControlAction = "pause" | "resume" | "input";
export const resumableAgentStates = [
  "waiting_input",
  "paused",
  "waiting_provider",
] as const;
export function agentInputBytes(value: string) {
  return new TextEncoder().encode(value).length;
}
export function agentControlRevision(run: {
  control_updated_at?: unknown;
  updated_at?: unknown;
}) {
  return String(run.control_updated_at || run.updated_at || "");
}
export function agentControlPayload(
  action: AgentControlAction,
  revision: string,
  message = "",
) {
  if (!revision) throw new Error("현재 실행 상태를 다시 확인하세요.");
  if (action === "input") {
    if (!message.trim()) throw new Error("추가 지시를 입력하세요.");
    if (agentInputBytes(message) > 16000)
      throw new Error("추가 지시는 UTF-8 기준 16,000바이트까지 입력하세요.");
    return { expected_updated_at: revision, message };
  }
  return { expected_updated_at: revision };
}
export function agentReportPath(id: string, format: "md" | "html" | "pdf") {
  return `/api/agent-runs/${encodeURIComponent(id)}/report?format=${format}`;
}
