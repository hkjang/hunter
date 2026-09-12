import test from "node:test";
import assert from "node:assert/strict";
import {
  changeResourceField,
  withEditRevision,
  resourceDetailPath,
} from "../src/resource-form-state.ts";
test("changing service clears declared child IDs while preserving unrelated draft fields", () => {
  const source = {
    service_id: "A",
    scope_id: "scope-A",
    scenario_id: "scenario-A",
    finding_id: "finding-A",
    authorized_profile_id: "auth-A",
    title: "내가 쓴 설명",
    secret: "private",
  };
  const fields = [
    { key: "scope_id", type: "scope" },
    { key: "scenario_id", type: "scenario" },
    { key: "finding_id" },
    { key: "authorized_profile_id", type: "auth" },
  ];
  const changed = changeResourceField(source, "service_id", "B", fields);
  for (const key of [
    "scope_id",
    "scenario_id",
    "finding_id",
    "authorized_profile_id",
  ])
    assert.equal(changed[key], "");
  assert.equal(changed.title, source.title);
  assert.equal(changed.secret, source.secret);
  assert.equal(source.scope_id, "scope-A");
  assert.equal(
    changeResourceField(source, "service_id", "A", fields).scope_id,
    "scope-A",
  );
});
test("leaving authorization clears scenario without clearing unrelated scope", () => {
  const value = changeResourceField(
    { profile: "authorization", scenario_id: "one", scope_id: "same" },
    "profile",
    "http-baseline",
    [{ key: "scenario_id", type: "scenario" }],
  );
  assert.equal(value.scenario_id, "");
  assert.equal(value.scope_id, "same");
});
test("edit concurrency token is the original server revision and never a draft override", () => {
  const original = { updated_at: "2026-09-12T12:34:56.123456Z" };
  assert.equal(
    withEditRevision(
      { title: "draft", expected_updated_at: "forged" },
      original,
    ).expected_updated_at,
    original.updated_at,
  );
  assert.deepEqual(
    withEditRevision({ title: "create", expected_updated_at: "forged" }),
    { title: "create" },
  );
  assert.throws(() => withEditRevision({ title: "draft" }, {}), /최신 자료/);
});
test("canonical detail links contain only selected ID and the valid finding activity tab", () => {
  assert.equal(
    resourceDetailPath("findings", "id & /", true),
    "/findings?item=id+%26+%2F&detail_tab=activity",
  );
  assert.equal(
    resourceDetailPath("scopes", "scope-one", true),
    "/admin/scopes?item=scope-one",
  );
  assert.equal(resourceDetailPath("scans", "scan-one"), "/scans?item=scan-one");
});
