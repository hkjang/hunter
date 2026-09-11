import assert from "node:assert/strict";
import test from "node:test";
import {
  SSEDecoder,
  applyAgentEvents,
  emptyActivity,
  displayMetadata,
  isTerminalRun,
} from "../src/agent-events.ts";
const event = (id, type, extra = {}) => ({
  id,
  run_id: "run-1",
  type,
  ...extra,
});
test("SSE reconstructs split CRLF frames, multiline JSON and final marker", () => {
  const source =
    ': connected\r\n\r\nid: 73\r\nevent: agent.event\r\ndata: {"id":73,\r\ndata: "message":"한글 응답"}\r\n\r\nevent: done\r\ndata: {}\r\n\r\n';
  for (const size of [1, 2, 3, 7, 31, 1024]) {
    const parser = new SSEDecoder();
    let frames = [];
    for (let i = 0; i < source.length; i += size)
      frames.push(...parser.push(source.slice(i, i + size)));
    assert.equal(frames.length, 2);
    assert.equal(frames[0].id, "73");
    assert.equal(frames[0].event, "agent.event");
    assert.deepEqual(JSON.parse(frames[0].data), {
      id: 73,
      message: "한글 응답",
    });
    assert.equal(frames[1].event, "done");
  }
});
test("SSE waits for blank line and ignores heartbeat; data-less done is valid", () => {
  const parser = new SSEDecoder();
  assert.deepEqual(
    parser.push(': heartbeat\n\nevent: agent.event\ndata: {"id":1}'),
    [],
  );
  assert.equal(parser.push("\n\n")[0].data, '{"id":1}');
  assert.equal(parser.push("event: done\n\n")[0].event, "done");
});
test("replayed events never duplicate streamed deltas and different roles stay separate", () => {
  const first = event(1, "message.delta", {
    role: "primary_agent",
    message: "서비스 ",
  });
  const next = event(2, "message.delta", {
    role: "primary_agent",
    message: "확인",
  });
  let state = applyAgentEvents(emptyActivity(), [first, next]);
  state = applyAgentEvents(state, [
    first,
    next,
    event(3, "message.delta", { role: "adviser", message: "추가 검토" }),
  ]);
  assert.equal(state.received, 3);
  assert.equal(state.messages.length, 2);
  assert.equal(state.messages[0].content, "서비스 확인");
  assert.equal(state.messages[1].content, "추가 검토");
});
test("tool calls correlate by actual id and preserve request/result metadata", () => {
  const state = applyAgentEvents(emptyActivity(), [
    event(1, "tool.started", {
      tool_call_id: "call-1",
      tool_name: "service_context",
      data: { arguments: { service_id: "svc-1" } },
    }),
    event(2, "tool.started", {
      tool_call_id: "call-2",
      tool_name: "list_findings",
    }),
    event(3, "tool.completed", {
      tool_call_id: "call-1",
      tool_name: "service_context",
      status: "completed",
      data: { result: { name: "실제 서비스" } },
    }),
    event(4, "tool.completed", {
      tool_call_id: "call-2",
      status: "failed",
      data: { result: "권한 없음" },
    }),
  ]);
  assert.equal(state.tools.length, 2);
  assert.equal(state.tools[0].status, "completed");
  assert.deepEqual(state.tools[0].started.data, {
    arguments: { service_id: "svc-1" },
  });
  assert.equal(state.tools[0].completed.data.result.name, "실제 서비스");
  assert.equal(state.tools[1].status, "failed");
});
test("message id joins delta parts across usage events without changing source state", () => {
  const original = applyAgentEvents(emptyActivity(), [
    event(1, "message.delta", {
      role: "primary",
      message: "A",
      data: { message_id: "m1" },
    }),
  ]);
  const next = applyAgentEvents(original, [
    event(2, "usage"),
    event(3, "message.delta", {
      role: "primary",
      message: "B",
      data: { message_id: "m1" },
    }),
  ]);
  assert.equal(original.messages[0].content, "A");
  assert.equal(next.messages[0].content, "AB");
});
test("retained raw event history is bounded while received count stays accurate", () => {
  const state = applyAgentEvents(
    emptyActivity(),
    Array.from({ length: 1600 }, (_, i) =>
      event(i + 1, "log", { message: "실행 기록" }),
    ),
  );
  assert.equal(state.received, 1600);
  assert.equal(state.events.length, 1500);
  assert.equal(state.events[0].id, 101);
  assert.equal(state.trimmed, true);
});
test("metadata redacts nested secrets but preserves token accounting", () => {
  assert.deepEqual(
    displayMetadata({
      input_tokens: 40,
      output_tokens: 10,
      args: {
        api_key: "secret",
        password: "secret",
        items: [{ authorization: "bearer", safe: "표시" }],
      },
    }),
    {
      input_tokens: 40,
      output_tokens: 10,
      args: {
        api_key: "[보호된 값]",
        password: "[보호된 값]",
        items: [{ authorization: "[보호된 값]", safe: "표시" }],
      },
    },
  );
});
test("stopping and approval wait are not treated as completed server work", () => {
  for (const status of ["queued", "running", "stopping", "waiting_approval"])
    assert.equal(isTerminalRun(status), false);
  for (const status of ["completed", "failed", "cancelled", "inconclusive"])
    assert.equal(isTerminalRun(status), true);
});
