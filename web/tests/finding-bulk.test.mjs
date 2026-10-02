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

// The due date is converted before it is sent: findingBulkPatch submits
// new Date(due).toISOString(), and ECMA-262 emits the expanded year form
// (+YYYYYY / -YYYYYY) once that instant leaves 0000-9999, which the server's
// time.Parse(time.RFC3339, s) cannot read. The conversion is browser-time-zone
// dependent, so the typed value alone does not decide: 9999-12-31T23:59 is an
// ordinary datetime-local value that stays in range east of UTC and overflows
// west of it. The fixture carries the wire string for each (zone, typed value)
// pair and the verdict Go reaches on it (TestFindingBulkDueDateSharedVectors).
const dueFixture = JSON.parse(
  readFileSync(
    new URL(
      "../../internal/app/testdata/finding-bulk-due-date.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("the form only submits a due date the server accepts, in every browser time zone", () => {
  assert.ok(dueFixture.cases.length > 0);
  const accepted = new Map(
    [...dueFixture.cases, ...dueFixture.wireOnly].map((v) => [
      v.wire,
      v.accepted,
    ]),
  );
  const base = {
    changeAssignee: false,
    assignee: "",
    changeDue: true,
    clearDue: false,
    due: "",
    changeStatus: false,
    status: "",
  };
  const original = process.env.TZ;
  try {
    for (const { name, form, wire, accepted: ok } of dueFixture.cases) {
      // Node re-reads process.env.TZ for each new Date, so this is the browser
      // zone the operator's machine is set to.
      process.env.TZ = form.tz;
      let patch;
      try {
        patch = findingBulkPatch({ ...base, due: form.due });
      } catch (error) {
        assert.match(error.message, /조치 기한/u, name);
        assert.equal(ok, false, `${name} must not be rejected by the form`);
        continue;
      }
      // Whatever it did submit has to be a string the server takes, and it has
      // to be the instant the fixture pins rather than some other encoding.
      assert.deepEqual(patch, { due_date: wire }, name);
      assert.equal(
        accepted.get(patch.due_date),
        true,
        `${name} submitted ${patch.due_date}, which the server answers with 400`,
      );
    }
  } finally {
    if (original === undefined) delete process.env.TZ;
    else process.env.TZ = original;
  }
});

test("clearing the due date and rejecting an unusable one keep their own answers", () => {
  const base = {
    changeAssignee: false,
    assignee: "",
    changeDue: true,
    clearDue: false,
    due: "",
    changeStatus: false,
    status: "",
  };
  assert.deepEqual(findingBulkPatch({ ...base, clearDue: true, due: "" }), {
    due_date: null,
  });
  // Clearing wins over whatever the hidden input still holds, including a value
  // the submit guard would otherwise reject.
  assert.deepEqual(
    findingBulkPatch({ ...base, clearDue: true, due: "9999-12-31T23:59" }),
    { due_date: null },
  );
  for (const due of ["", "invalid", "2026-13-45T99:99"])
    assert.throws(
      () => findingBulkPatch({ ...base, due }),
      /유효한 조치 기한/u,
      due,
    );
});
