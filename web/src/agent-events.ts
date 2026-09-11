/** Hunter's persisted agent-event protocol. Independent of UI and transport. */
export type AgentEvent = {
  id: string | number;
  run_id: string;
  type: string;
  role?: string;
  message?: string;
  tool_name?: string;
  tool_call_id?: string;
  status?: string;
  data?: Record<string, unknown>;
  created_at?: string;
};
export type SSEFrame = { event: string; id: string; data: string };

/** Handles CRLF, multi-line data, comments, and chunk boundaries. */
export class SSEDecoder {
  private buffer = "";
  private data: string[] = [];
  private event = "";
  private id = "";
  push(chunk: string): SSEFrame[] {
    this.buffer += chunk;
    const frames: SSEFrame[] = [];
    let end: number;
    while ((end = this.buffer.indexOf("\n")) !== -1) {
      let line = this.buffer.slice(0, end);
      this.buffer = this.buffer.slice(end + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      if (line === "") {
        if (this.data.length)
          frames.push({
            event: this.event || "message",
            id: this.id,
            data: this.data.join("\n"),
          });
        else if (this.event === "done")
          frames.push({ event: "done", id: this.id, data: "" });
        this.data = [];
        this.event = "";
        this.id = "";
        continue;
      }
      if (line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon < 0 ? line : line.slice(0, colon);
      let value = colon < 0 ? "" : line.slice(colon + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "data") this.data.push(value);
      if (field === "event") this.event = value;
      if (field === "id" && !value.includes("\0")) this.id = value;
    }
    return frames;
  }
}
export type AgentMessage = {
  id: string;
  role: string;
  content: string;
  created_at?: string;
  group?: string;
};
export type AgentTool = {
  id: string;
  name: string;
  status: string;
  started_at?: string;
  finished_at?: string;
  started?: AgentEvent;
  completed?: AgentEvent;
};
export type AgentActivity = {
  events: AgentEvent[];
  messages: AgentMessage[];
  tools: AgentTool[];
  received: number;
  trimmed: boolean;
};
export const emptyActivity = (): AgentActivity => ({
  events: [],
  messages: [],
  tools: [],
  received: 0,
  trimmed: false,
});
export function applyAgentEvents(
  previous: AgentActivity,
  incoming: AgentEvent[],
): AgentActivity {
  if (!incoming.length) return previous;
  let events = [...previous.events];
  const messages = previous.messages.map((m) => ({ ...m }));
  const tools = previous.tools.map((t) => ({ ...t }));
  const known = new Set(events.map((e) => String(e.id)));
  let received = previous.received;
  for (const event of incoming) {
    if (known.has(String(event.id))) continue;
    known.add(String(event.id));
    received++;
    const previousEvent = events.at(-1);
    events.push(event);
    if (event.type === "message.delta" && typeof event.message === "string") {
      const role = event.role || "에이전트";
      const group =
        typeof event.data?.message_id === "string"
          ? event.data.message_id
          : undefined;
      const latest = messages.at(-1);
      if (
        latest &&
        latest.role === role &&
        ((group && latest.group === group) ||
          (!group && previousEvent?.type === "message.delta"))
      )
        latest.content += event.message;
      else
        messages.push({
          id: String(event.id),
          role,
          content: event.message,
          created_at: event.created_at,
          group,
        });
    }
    if (event.type === "tool.started" || event.type === "tool.completed") {
      const id = event.tool_call_id || String(event.id);
      let tool = tools.find((t) => t.id === id);
      if (!tool) {
        tool = {
          id,
          name: event.tool_name || "도구",
          status: event.status || "running",
        };
        tools.push(tool);
      }
      tool.name = event.tool_name || tool.name;
      tool.status =
        event.status ||
        (event.type === "tool.started" ? "running" : "completed");
      if (event.type === "tool.started") {
        tool.started = event;
        tool.started_at = event.created_at;
      } else {
        tool.completed = event;
        tool.finished_at = event.created_at;
      }
    }
  }
  const trimmed =
    previous.trimmed || events.length > 1500 || messages.length > 150;
  return {
    events: events.slice(-1500),
    messages: messages.slice(-150),
    tools,
    received,
    trimmed,
  };
}
export function isTerminalRun(status: string | undefined) {
  return ["completed", "failed", "cancelled", "inconclusive"].includes(
    status || "",
  );
}
/** Defensive display redaction; the API remains responsible for protecting secrets. */
export function displayMetadata(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(displayMetadata);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, v]) => [
        key,
        /(?:password|secret|authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|^token)$/i.test(
          key,
        )
          ? "[보호된 값]"
          : displayMetadata(v),
      ]),
    );
  return value;
}
