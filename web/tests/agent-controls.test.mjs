import test from "node:test";
import assert from "node:assert/strict";
import {
  agentControlPayload,
  agentControlRevision,
  agentInputBytes,
  agentReportPath,
} from "../src/agent-control-state.ts";
import { isTerminalRun } from "../src/agent-events.ts";
import { changeResourceField } from "../src/resource-form-state.ts";
test("automatic run progress does not replace the reviewed control revision", () => {
  const run = {
    updated_at: "new-progress",
    control_updated_at: "reviewed-control",
  };
  assert.equal(agentControlRevision(run), "reviewed-control");
  assert.equal(
    agentControlRevision({ ...run, updated_at: "later-progress" }),
    "reviewed-control",
  );
  assert.equal(agentControlRevision({ updated_at: "legacy" }), "legacy");
  assert.equal(agentControlRevision({}), "");
});
test("same-run controls preserve the reviewed revision and never silently resume an input request", () => {
  const revision = "2026-09-13T10:11:12.123456789Z";
  assert.deepEqual(
    agentControlPayload("input", revision, "추가 확인\n근거를 정리해 주세요"),
    {
      expected_updated_at: revision,
      message: "추가 확인\n근거를 정리해 주세요",
    },
  );
  assert.deepEqual(agentControlPayload("resume", revision, "ignored"), {
    expected_updated_at: revision,
  });
  assert.deepEqual(agentControlPayload("pause", revision), {
    expected_updated_at: revision,
  });
  assert.throws(
    () => agentControlPayload("input", "", "body"),
    /현재 실행 상태/,
  );
  assert.throws(
    () => agentControlPayload("input", revision, " \n "),
    /추가 지시/,
  );
});
test("input limit measures Korean UTF8 bytes and waiting states remain resumable rather than completed", () => {
  assert.equal(agentInputBytes("한글"), 6);
  assert.doesNotThrow(() =>
    agentControlPayload("input", "revision", "가".repeat(5333)),
  );
  assert.throws(
    () => agentControlPayload("input", "revision", "가".repeat(5334)),
    /16,000바이트/,
  );
  for (const state of ["waiting_input", "waiting_provider", "paused"])
    assert.equal(isTerminalRun(state), false);
  assert.equal(isTerminalRun("completed"), true);
});
test("report URLs encode the current run and do not carry unrelated page query parameters", () => {
  assert.equal(
    agentReportPath("id/with?query", "pdf"),
    "/api/agent-runs/id%2Fwith%3Fquery/report?format=pdf",
  );
});
test("changing service or leaving isolated scans clears only the selected execution profile", () => {
  const fields = [
    { key: "service_id" },
    { key: "profile" },
    { key: "execution_profile_id", type: "execution" },
  ];
  const row = {
    service_id: "service-one",
    profile: "isolated",
    execution_profile_id: "profile-one",
    note: "keep",
  };
  assert.deepEqual(
    changeResourceField(row, "service_id", "service-two", fields),
    { ...row, service_id: "service-two", execution_profile_id: "" },
  );
  assert.equal(
    changeResourceField(row, "profile", "http-baseline", fields)
      .execution_profile_id,
    "",
  );
  assert.equal(
    changeResourceField(row, "profile", "isolated", fields)
      .execution_profile_id,
    "profile-one",
  );
});
