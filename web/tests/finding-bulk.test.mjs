import test from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { findingBulkPatch } from "../src/finding-bulk-state.ts";

// The bulk change form pre-validates the assignee, but POST /api/findings/bulk
// decides. The form submits the trimmed name, so the fixture carries both the
// typed string and that request body, and Go runs the request body through
// validateFindingBulk (TestFindingBulkAssigneeSharedVectors). The form must not
// reject a name the server would store and must not submit one it answers with
// 400 — either way the operator loses a round trip or a usable name.
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
  for (const { name, assignee, wire, accepted, reason } of fixture.cases) {
    // Keeps the column the Go side measures equal to this form's request body.
    assert.equal(assignee.trim(), wire, name);
    if (!accepted) {
      assert.throws(
        () => findingBulkPatch({ ...base, assignee }),
        reason === "control" ? /제어 문자/u : /200바이트/u,
        name,
      );
      continue;
    }
    assert.equal(reason, "ok", name);
    assert.deepEqual(
      findingBulkPatch({ ...base, assignee }),
      { assignee: wire },
      name,
    );
  }
});
