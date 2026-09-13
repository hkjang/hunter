import test from "node:test";
import assert from "node:assert/strict";
import {
  modelRoles,
  movePriorityItem,
  secretChange,
  safeProviderFields,
  providerEndpoint,
  webAddress,
  platformTabs,
  newPlatformID,
} from "../src/agent-platform-state.ts";
import { switchWorkflowTab } from "../src/workflow-navigation.ts";

test("provider draft IDs meet backend identity constraints without secure-context randomUUID", () => {
  const values = Array.from({ length: 100 }, () => newPlatformID());
  assert.equal(new Set(values).size, 100);
  for (const value of values) assert.match(value, /^[a-zA-Z0-9_-]{1,64}$/);
});

test("provider edits keep secrets by stable ID while explicit replacement and deletion remain distinguishable", () => {
  const raw = {
    id: "provider-two",
    name: "사내 모델",
    api_key: "never-copy",
    api_key_configured: true,
    clear_api_key: true,
    client_key_pem: "never-copy-either",
    priority: 4,
  };
  const publicFields = safeProviderFields(raw);
  assert.deepEqual(publicFields, {
    id: "provider-two",
    name: "사내 모델",
    priority: 4,
  });
  assert.deepEqual(
    { ...publicFields, ...secretChange("keep", "ignored") },
    publicFields,
  );
  assert.deepEqual(secretChange("clear", ""), { clear_api_key: true });
  assert.deepEqual(secretChange("replace", " new-value "), {
    api_key: " new-value ",
  });
  assert.deepEqual(secretChange("replace", "a\nb", "client_key_pem"), {
    client_key_pem: "a\nb",
  });
  assert.throws(() => secretChange("replace", "  "), /새 비밀값/);
  assert.equal(raw.api_key, "never-copy");
});
test("model fallback order changes preserve all IDs without mutating other role mappings", () => {
  const roles = { default: ["alpha", "beta", "gamma"], searcher: ["beta"] };
  assert.deepEqual(movePriorityItem(roles.default, 1, -1), [
    "beta",
    "alpha",
    "gamma",
  ]);
  assert.deepEqual(movePriorityItem(roles.default, 0, -1), roles.default);
  assert.deepEqual(movePriorityItem(roles.default, 2, 1), roles.default);
  assert.deepEqual(roles, {
    default: ["alpha", "beta", "gamma"],
    searcher: ["beta"],
  });
  assert.ok(modelRoles.some((r) => r.value === "primary_agent"));
  assert.ok(!modelRoles.some((r) => r.value === "planner"));
});
test("rendered provider result links reject script and credential URLs; configuration additionally rejects URL query secrets", () => {
  for (const value of [
    "javascript:alert(1)",
    "data:text/html,test",
    "https://user:secret@host.internal/",
    "/relative",
    "not a URL",
  ])
    assert.equal(webAddress(value), null);
  assert.equal(
    webAddress("https://evidence.internal/result?id=1"),
    "https://evidence.internal/result?id=1",
  );
  assert.equal(
    providerEndpoint("http://models.internal:11434"),
    "http://models.internal:11434",
  );
  assert.throws(
    () => providerEndpoint("https://models.internal/v1?token=secret"),
    /쿼리/,
  );
  assert.throws(
    () => providerEndpoint("https://models.internal/#secret"),
    /해시/,
  );
});
test("integration tabs restore their own search and pagination without serializing draft credentials", () => {
  const start = new URLSearchParams(
    "tab=search&q=사내&page=3&sort=priority&dir=asc",
  );
  const models = switchWorkflowTab(start, "search", "models", platformTabs);
  assert.equal(models.has("q"), false);
  models.set("q", "기본 모델");
  models.set("page", "2");
  const back = switchWorkflowTab(models, "models", "search", platformTabs);
  assert.equal(back.get("q"), "사내");
  assert.equal(back.get("page"), "3");
  assert.equal(back.get("sort"), "priority");
  assert.equal(back.has("api_key"), false);
});
