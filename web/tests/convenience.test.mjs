import test from "node:test";
import assert from "node:assert/strict";
import { csvCell, listCSV, listSharePath } from "../src/list-export.ts";
import { findingBulkPatch } from "../src/finding-bulk-state.ts";

test("CSV exports only declared display fields and preserves Korean, quotes and multiline values", () => {
  const rows = [{ title: '결제 "API"\n검토', secret: "never-export", n: 0 }];
  const text = listCSV(rows, [
    { key: "title", label: "발견 건", value: (row) => row.title },
    { key: "n", label: "점수", value: (row) => row.n },
  ]);
  assert.equal(text, '\uFEFF"발견 건","점수"\r\n"결제 ""API""\n검토","0"\r\n');
  assert.equal(csvCell({ secret: "never-export" }), '""');
  assert.equal(csvCell(["a", { secret: "never-export" }, "b"]), '"a · b"');
});

test("spreadsheet formula prefixes including leading whitespace are inert CSV text", () => {
  for (const value of [
    '=HYPERLINK("https://invalid")',
    "+1",
    "-2",
    "@sum(a1)",
    " \t=cmd",
    "\rpayload",
    "\npayload",
    "\t42",
  ])
    assert.ok(csvCell(value).startsWith("\"'"), value);
  assert.equal(csvCell("CVE-2026-1234"), '"CVE-2026-1234"');
  assert.equal(csvCell(0), '"0"');
});

test("list sharing preserves the active query and comparison but strips arbitrary data", () => {
  const id = "11111111-2222-4333-8444-555555555555";
  const path = listSharePath(
    `/software/${id}`,
    new URLSearchParams(
      `tab=compare&baseline=${id}&q=한글&sort=name&dir=desc&f_service_id=service&item=hidden&token=secret&draft=text`,
    ),
    ["name"],
    ["service_id"],
    2,
  );
  const result = new URL(path, "http://hunter.invalid");
  assert.equal(result.searchParams.get("q"), "한글");
  assert.equal(result.searchParams.get("baseline"), id);
  assert.equal(result.searchParams.get("page"), "2");
  assert.equal(result.searchParams.get("f_service_id"), "service");
  for (const key of ["item", "token", "draft"])
    assert.equal(result.searchParams.has(key), false);
  assert.equal(
    listSharePath(
      "/findings",
      new URLSearchParams("tab=secret&baseline=bad"),
      [],
      [],
      1,
    ),
    "/findings",
  );
});

test("bulk patches distinguish unchanged fields from intentional clearing and disallow resolution", () => {
  const base = {
    changeAssignee: false,
    assignee: "unselected",
    changeDue: false,
    clearDue: false,
    due: "",
    changeStatus: false,
    status: "resolved",
  };
  assert.throws(() => findingBulkPatch(base), /하나 이상/);
  assert.deepEqual(
    findingBulkPatch({ ...base, changeAssignee: true, assignee: "  " }),
    { assignee: "" },
  );
  assert.deepEqual(
    findingBulkPatch({ ...base, changeDue: true, clearDue: true }),
    { due_date: null },
  );
  assert.throws(
    () => findingBulkPatch({ ...base, changeStatus: true }),
    /상태/,
  );
  assert.throws(() => findingBulkPatch({ ...base, changeDue: true }), /기한/);
  assert.throws(
    () =>
      findingBulkPatch({
        ...base,
        changeAssignee: true,
        assignee: "한".repeat(67),
      }),
    /200바이트/,
  );
  assert.deepEqual(
    findingBulkPatch({
      ...base,
      changeStatus: true,
      status: "in_progress",
      changeDue: true,
      due: "2026-10-02T03:00:00Z",
    }),
    { status: "in_progress", due_date: "2026-10-02T03:00:00.000Z" },
  );
});
