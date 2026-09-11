import assert from "node:assert/strict";
import test from "node:test";
import {
  agentReadScopes,
  canReadAgents,
  canStartAgents,
} from "../src/agent-permissions.ts";
const permission = (scopes) => (scope) => scopes.includes(scope);
test("agent history requires every evidence read permission", () => {
  assert.equal(canReadAgents(permission(agentReadScopes)), true);
  for (const missing of agentReadScopes)
    assert.equal(
      canReadAgents(
        permission(agentReadScopes.filter((scope) => scope !== missing)),
      ),
      false,
      missing,
    );
  assert.equal(canReadAgents(permission(["agents:read"])), false);
});
test("creation and retry require evidence reads, agent write, and AI use", () => {
  const all = [...agentReadScopes, "agents:write", "ai:use"];
  assert.equal(canStartAgents(permission(all)), true);
  for (const missing of all)
    assert.equal(
      canStartAgents(permission(all.filter((scope) => scope !== missing))),
      false,
      missing,
    );
  assert.equal(
    canStartAgents(() => undefined),
    false,
  );
});
