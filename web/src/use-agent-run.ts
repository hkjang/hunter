import { useCallback, useEffect, useRef, useState } from "react";
import { api, APIError, type Row } from "./api";
import {
  applyAgentEvents,
  emptyActivity,
  isTerminalRun,
  SSEDecoder,
  type AgentEvent,
} from "./agent-events";
export type AgentRun = Row & {
  id: string;
  status: string;
  service_id: string;
  title?: string;
  tasks?: Row[];
  scans?: Row[];
  allowed_actions?: string[];
};
export type AgentConnection =
  "connecting" | "live" | "reconnecting" | "closed" | "error";
const delay = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  });
export function useAgentRun(id: string) {
  const [restart, setRestart] = useState(0);
  const [run, setRun] = useState<AgentRun | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [connection, setConnection] = useState<AgentConnection>("connecting"),
    [streamError, setStreamError] = useState(""),
    [activity, setActivity] = useState(emptyActivity);
  const reloadRef = useRef<() => Promise<void>>(async () => {});
  const reload = useCallback(() => reloadRef.current(), []);
  useEffect(() => {
    const controller = new AbortController(),
      signal = controller.signal;
    let latest: AgentRun | null = null,
      cursor = "0",
      attempt = 0,
      done = false,
      snapshotRevision = 0,
      refreshTimer: ReturnType<typeof setTimeout> | undefined,
      flushTimer: ReturnType<typeof setTimeout> | undefined;
    let pending: AgentEvent[] = [];
    const seen = new Set<string>();
    setRun(null);
    setLoading(true);
    setError("");
    setConnection("connecting");
    setStreamError("");
    setActivity(emptyActivity());
    const refresh = async () => {
      const revision = ++snapshotRevision;
      try {
        const next = await api<AgentRun>(
          `/api/agent-runs/${encodeURIComponent(id)}`,
          { signal },
        );
        if (signal.aborted || revision !== snapshotRevision) return;
        latest = next;
        setRun(next);
        setError("");
      } catch (e) {
        if (signal.aborted) return;
        setError((e as Error).message);
        throw e;
      } finally {
        if (!signal.aborted) setLoading(false);
      }
    };
    reloadRef.current = async () => {
      try {
        await refresh();
      } catch {
        /* Visible in-page error; initial/stream paths decide retries. */
      }
    };
    const scheduleRefresh = () => {
      if (refreshTimer || signal.aborted) return;
      refreshTimer = setTimeout(() => {
        refreshTimer = undefined;
        void refresh().catch(() => {});
      }, 400);
    };
    const flush = () => {
      if (flushTimer) clearTimeout(flushTimer);
      flushTimer = undefined;
      if (signal.aborted || !pending.length) return;
      const batch = pending;
      pending = [];
      setActivity((previous) => applyAgentEvents(previous, batch));
    };
    const receive = (event: AgentEvent, frameId: string) => {
      if (event.run_id && event.run_id !== id) return;
      const eventId = frameId || String(event.id ?? "");
      if (!eventId || eventId === "undefined") return;
      if (seen.has(eventId)) return;
      seen.add(eventId);
      cursor = eventId;
      pending.push({ ...event, id: eventId });
      if (!flushTimer) flushTimer = setTimeout(flush, 75);
      if (
        ["run.updated", "task.updated", "subtask.updated", "usage"].includes(
          event.type,
        )
      )
        scheduleRefresh();
    };
    const connect = async () => {
      try {
        await refresh();
      } catch {
        setConnection("error");
        reloadRef.current = async () => setRestart((value) => value + 1);
        return;
      }
      while (!signal.aborted && !done) {
        if (attempt) {
          setConnection("reconnecting");
          await delay(
            Math.min(15000, 1000 * 2 ** Math.min(attempt, 4)),
            signal,
          );
          if (signal.aborted) break;
          try {
            await refresh();
          } catch (e) {
            if (e instanceof APIError && [401, 403, 404].includes(e.status)) {
              setConnection("error");
              break;
            }
          }
        }
        try {
          const response = await fetch(
            `/api/agent-runs/${encodeURIComponent(id)}/events?after=${encodeURIComponent(cursor)}`,
            {
              credentials: "same-origin",
              headers: { Accept: "text/event-stream" },
              signal,
            },
          );
          if (!response.ok) {
            let message = `실행 이벤트 연결에 실패했습니다 (${response.status})`;
            try {
              message = (await response.json()).error || message;
            } catch {}
            if (response.status === 401)
              window.dispatchEvent(new Event("hunter:unauthorized"));
            throw new APIError(message, response.status);
          }
          if (
            !response.body ||
            !response.headers.get("content-type")?.includes("text/event-stream")
          )
            throw new Error("실행 서버가 이벤트 스트림을 반환하지 않았습니다.");
          setConnection("live");
          setStreamError("");
          const reader = response.body.getReader(),
            decoder = new TextDecoder(),
            parser = new SSEDecoder();
          try {
            while (!signal.aborted && !done) {
              const chunk = await reader.read();
              if (chunk.done) break;
              for (const frame of parser.push(
                decoder.decode(chunk.value, { stream: true }),
              )) {
                if (frame.event === "done") {
                  done = true;
                  break;
                }
                if (frame.event === "error") {
                  let message = "실행 이벤트를 수신하지 못했습니다.";
                  try {
                    message = JSON.parse(frame.data).error || message;
                  } catch {}
                  throw new Error(message);
                }
                if (frame.event !== "agent.event") continue;
                let event: AgentEvent;
                try {
                  event = JSON.parse(frame.data);
                } catch {
                  throw new Error(
                    "실행 이벤트 형식이 올바르지 않습니다. 다시 동기화합니다.",
                  );
                }
                receive(event, frame.id);
                attempt = 0;
              }
            }
          } finally {
            await reader.cancel().catch(() => {});
            reader.releaseLock();
          }
          flush();
          if (signal.aborted) break;
          if (done) {
            setConnection("closed");
            setStreamError("");
            await refresh().catch(() => {});
            break;
          }
          // A closed connection does not cancel a server-side run. Re-fetch its
          // durable state and resume the event cursor, including final events.
          await refresh();
          attempt++;
          setStreamError(
            "연결이 끊겨 다시 연결하고 있습니다. 서버의 실행은 계속됩니다.",
          );
        } catch (e) {
          flush();
          if (signal.aborted) break;
          setStreamError((e as Error).message);
          if (e instanceof APIError && [401, 403, 404].includes(e.status)) {
            setConnection("error");
            break;
          }
          attempt++;
        }
      }
    };
    void connect();
    const poll = setInterval(() => {
      if (!signal.aborted && !document.hidden && !isTerminalRun(latest?.status))
        void refresh().catch(() => {});
    }, 10000);
    return () => {
      controller.abort();
      clearInterval(poll);
      if (refreshTimer) clearTimeout(refreshTimer);
      if (flushTimer) clearTimeout(flushTimer);
      reloadRef.current = async () => {};
    };
  }, [id, restart]);
  return { run, loading, error, reload, connection, streamError, activity };
}
