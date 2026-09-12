import test from "node:test";
import assert from "node:assert/strict";
import { changed, reconcileDrafts, requiredIssues } from "../src/form-state.ts";

test("draft comparison ignores object key ordering but preserves meaningful input changes", () => {
  assert.equal(
    changed(
      { name: "Hunter", nested: { a: 1, b: false } },
      { nested: { b: false, a: 1 }, name: "Hunter" },
    ),
    false,
  );
  assert.equal(
    changed({ password: "" }, { password: "entered-not-persisted" }),
    true,
  );
  assert.equal(changed({ enabled: false }, { enabled: true }), true);
  assert.equal(changed({ name: "a" }, { name: "a", unused: undefined }), false);
});
test("server refresh preserves dirty groups while updating unchanged groups without mutation", () => {
  const baseline = {
    general: { name: "old" },
    ai: { model: "old", api_key: "" },
    security: { hours: 12 },
  };
  const current = {
    general: { name: "draft" },
    ai: { model: "old", api_key: "draft-key" },
    security: { hours: 12 },
  };
  const incoming = {
    general: { name: "server" },
    ai: { model: "server", api_key: "" },
    security: { hours: 24 },
  };
  const result = reconcileDrafts(baseline, current, incoming);
  assert.deepEqual(result, {
    general: { name: "draft" },
    ai: { model: "old", api_key: "draft-key" },
    security: { hours: 24 },
  });
  assert.equal(incoming.ai.api_key, "");
  assert.equal(current.security.hours, 12);
});
test("successful group save can clear only its sensitive draft while preserving another group", () => {
  const baseline = {
    ai: { model: "old", api_key: "" },
    general: { name: "old" },
  };
  const current = {
    ai: { model: "old", api_key: "draft-key" },
    general: { name: "unsaved" },
  };
  const saved = { model: "new", api_key: "" };
  const next = reconcileDrafts(
    { ...baseline, ai: saved },
    { ...current, ai: saved },
    { ai: saved, general: { name: "old" } },
  );
  assert.equal(next.ai.api_key, "");
  assert.equal(next.general.name, "unsaved");
});
test("required-field guidance names fields without reflecting secret or entered values", () => {
  const issues = requiredIssues([
    { fieldId: "name", label: "표시 이름", value: "  " },
    { fieldId: "password", label: "비밀번호", value: "private-secret" },
    { fieldId: "choices", label: "권한", value: [] },
  ]);
  assert.deepEqual(issues, [
    { fieldId: "name", message: "표시 이름 항목을 입력하세요." },
    { fieldId: "choices", message: "권한 항목을 입력하세요." },
  ]);
  assert.ok(!JSON.stringify(issues).includes("private-secret"));
});
