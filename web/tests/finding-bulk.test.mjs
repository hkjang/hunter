import test from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { findingBulkPatch } from "../src/finding-bulk-state.ts";

// The bulk change form pre-validates the assignee, but POST /api/findings/bulk
// decides. Both readers run internal/app/testdata/finding-bulk-assignee.json
// (Go: TestFindingBulkAssigneeSharedVectors) so the form never submits a name
// validateFindingBulk would answer with 400 — the operator sees the Korean
// message beside the field instead of a round trip.
const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../../internal/app/testdata/finding-bulk-assignee.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("assignee verdicts follow the shared server bulk change vectors", () => {
  assert.ok(fixture.cases.length > 0);
  const base = {
    changeAssignee: true,
    changeDue: false,
    clearDue: false,
    due: "",
    changeStatus: false,
    status: "",
  };
  for (const { name, assignee, accepted, reason } of fixture.cases) {
    if (!accepted) {
      assert.throws(
        () => findingBulkPatch({ ...base, assignee }),
        reason === "control" ? /제어 문자/u : /200바이트/u,
        name,
      );
      continue;
    }
    assert.equal(reason, "ok", name);
    // The byte limit is counted on the raw string, but the submitted value stays
    // the trimmed one the server would store.
    assert.deepEqual(
      findingBulkPatch({ ...base, assignee }),
      { assignee: assignee.trim() },
      name,
    );
  }
});
