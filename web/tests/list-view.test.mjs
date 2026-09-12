import test from "node:test";
import assert from "node:assert/strict";
import {
  matchesSearch,
  sortRows,
  readListState,
  paginateRows,
  patchListParams,
} from "../src/list-view.ts";

test("search combines Korean words across visible columns and normalizes case and Unicode", () => {
  assert.equal(
    matchesSearch(["결제 API", "심각", "확인됨"], " 결제  심각 "),
    true,
  );
  assert.equal(matchesSearch(["결제 API", "심각"], "api 높음"), false);
  assert.equal(matchesSearch(["ＡＰＩ", "검증"], "api 검증"), true);
});

test("search never serializes credentials or arbitrary object payloads", () => {
  assert.equal(
    matchesSearch([{ secret: "do-not-index" }, ["허용된 값"]], "do-not-index"),
    false,
  );
  assert.equal(
    matchesSearch([{ secret: "do-not-index" }, ["허용된 값"]], "허용된"),
    true,
  );
});

test("natural ordering handles names with numbers, is stable, and leaves inputs intact", () => {
  const rows = [
    { name: "API 10", id: "a" },
    { name: "API 2", id: "b" },
    { name: "API 2", id: "c" },
  ];
  const columns = [{ key: "name", label: "이름", value: (row) => row.name }];
  assert.deepEqual(
    sortRows(rows, columns, { key: "name", direction: "asc" }).map(
      (row) => row.id,
    ),
    ["b", "c", "a"],
  );
  assert.deepEqual(
    rows.map((row) => row.id),
    ["a", "b", "c"],
  );
});

test("numbers and missing timestamps sort consistently in both directions", () => {
  const rows = [{ n: 100 }, { n: null }, { n: 5 }, { n: 20 }, { n: NaN }];
  const columns = [{ key: "n", label: "호출 수", value: (row) => row.n }];
  assert.deepEqual(
    sortRows(rows, columns, { key: "n", direction: "asc" }).map((row) => row.n),
    [5, 20, 100, null, NaN],
  );
  assert.deepEqual(
    sortRows(rows, columns, { key: "n", direction: "desc" }).map(
      (row) => row.n,
    ),
    [100, 20, 5, null, NaN],
  );
});

test("business severity order is independent of alphabetical labels", () => {
  const order = ["정보", "낮음", "보통", "높음", "심각"];
  const columns = [
    {
      key: "severity",
      label: "심각도",
      value: (row) => row.severity,
      compare: (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
    },
  ];
  assert.deepEqual(
    sortRows(
      order.map((severity) => ({ severity })),
      columns,
      { key: "severity", direction: "desc" },
    ).map((row) => row.severity),
    ["심각", "높음", "보통", "낮음", "정보"],
  );
});

test("untrusted URL settings use safe defaults and only declared columns and filters", () => {
  const state = readListState(
    new URLSearchParams(
      "sort=secret&dir=oops&page=Infinity&size=100000&f_status=running&f_secret=x",
    ),
    ["name"],
    ["status"],
  );
  assert.equal(state.sort, null);
  assert.equal(state.page, 1);
  assert.equal(state.pageSize, 25);
  assert.deepEqual(state.filters, { status: "running" });
  for (const page of ["0", "-1", "2.1", "NaN"])
    assert.equal(
      readListState(new URLSearchParams(`page=${page}`), [], []).page,
      1,
    );
});

test("pagination clamps after deletions or filtering, and handles zero results", () => {
  const rows = Array.from({ length: 37 }, (_, id) => ({ id }));
  assert.deepEqual(paginateRows(rows, 5, 25), {
    page: 2,
    pageCount: 2,
    rows: rows.slice(25),
  });
  assert.deepEqual(paginateRows([], 7, 25), {
    page: 1,
    pageCount: 1,
    rows: [],
  });
});

test("search/filter changes reset page while preserving independent deep-link parameters", () => {
  const params = new URLSearchParams(
    "page=5&scan=run-123&tab=events&f_status=running&sort=name&dir=desc",
  );
  const next = patchListParams(params, { q: "결제", f_status: null }, true);
  assert.equal(next.get("page"), null);
  assert.equal(next.get("scan"), "run-123");
  assert.equal(next.get("tab"), "events");
  assert.equal(next.get("sort"), "name");
  assert.equal(next.get("q"), "결제");
  assert.equal(next.get("f_status"), null);
  assert.equal(params.get("page"), "5");
});
