import test from "node:test";
import assert from "node:assert/strict";
import {
  listPreferenceKey,
  readListPreferences,
  savedListQuery,
  savedListQueryLimit,
  savedListQueryTooLong,
  applySavedListQuery,
} from "../src/saved-list-views.ts";

test("browser preferences isolate users and menus, including delimiter characters", () => {
  const keys = [
    listPreferenceKey("alice", "/findings"),
    listPreferenceKey("bob", "/findings"),
    listPreferenceKey("alice", "/services"),
    listPreferenceKey("alice:/services", "/findings"),
    listPreferenceKey("alice", "/services:/findings"),
  ];
  assert.equal(new Set(keys).size, keys.length);
});

test("invalid browser storage falls back safely and malformed saved views are discarded", () => {
  const defaults = { density: "comfortable", expanded: false, views: [] };
  for (const raw of [null, "broken", "null", "42", "[]"])
    assert.deepEqual(readListPreferences(raw), defaults);
  const valid = {
    id: "one",
    name: "  심각한 발견 건  ",
    query: "f_severity=critical",
  };
  assert.deepEqual(
    readListPreferences(
      JSON.stringify({
        density: "tiny",
        expanded: "true",
        views: [
          null,
          {},
          valid,
          valid,
          { id: "two", name: " ", query: "" },
          { id: "three", name: "a", query: "x".repeat(8193) },
        ],
      }),
    ),
    { ...defaults, views: [{ ...valid, name: "심각한 발견 건" }] },
  );
  assert.equal(
    readListPreferences(
      JSON.stringify({
        views: Array.from({ length: 20 }, (_, i) => ({
          id: String(i),
          name: String(i),
          query: "",
        })),
      }),
    ).views.length,
    8,
  );
});

test("a saved view stores only declared list controls and omits selected records and arbitrary data", () => {
  const params = new URLSearchParams(
    "q=결제&sort=severity&dir=desc&size=50&page=4&f_status=open&f_severity=critical&f_unknown=hidden&item=private-record&tab=secret&token=do-not-store",
  );
  const query = savedListQuery(params, ["severity"], ["severity", "status"]);
  assert.deepEqual(
    [...new URLSearchParams(query)],
    [
      ["q", "결제"],
      ["sort", "severity"],
      ["dir", "desc"],
      ["size", "50"],
      ["f_severity", "critical"],
      ["f_status", "open"],
    ],
  );
  assert.equal(params.get("page"), "4");
});

test("restoring an edited saved query preserves current deep links and resets pagination", () => {
  const current = new URLSearchParams(
    "q=old&sort=title&dir=asc&page=5&size=10&f_status=open&item=current&tab=events",
  );
  const next = applySavedListQuery(
    current,
    "q=새검색&sort=severity&dir=desc&size=50&f_severity=critical&page=99&item=other&tab=other&token=secret",
    ["title", "severity"],
    ["status", "severity"],
  );
  assert.equal(next.get("q"), "새검색");
  assert.equal(next.get("page"), null);
  assert.equal(next.get("f_status"), null);
  assert.equal(next.get("f_severity"), "critical");
  assert.equal(next.get("item"), "current");
  assert.equal(next.get("tab"), "events");
  assert.equal(next.get("token"), null);
  assert.equal(current.get("page"), "5");
});

test("unknown and oversized controls cannot override accepted list configuration", () => {
  const params = new URLSearchParams(
    "sort=secret&dir=desc&size=100000&f_unknown=value",
  );
  params.set("q", "가".repeat(501));
  params.set("f_status", "나".repeat(501));
  const restored = new URLSearchParams(
    savedListQuery(params, ["title"], ["status"]),
  );
  assert.equal(restored.get("sort"), null);
  assert.equal(restored.get("dir"), null);
  assert.equal(restored.get("size"), null);
  assert.equal(restored.get("f_unknown"), null);
  assert.equal(restored.get("q").length, 500);
  assert.equal(restored.get("f_status").length, 500);
  // Saving and restoring compare the same snapshot string, so the default keeps
  // the storage limit even though sharing an address opts out of it.
  assert.equal(
    savedListQuery(params, ["title"], ["status"]),
    restored.toString(),
  );
});

test("a snapshot browser storage would silently discard is rejected before it is saved", () => {
  // Each Hangul character costs nine characters once the snapshot is URL
  // encoded, so a search and one filter at the 500 character limit already pass
  // the storage limit that readListPreferences enforces when reading.
  const params = new URLSearchParams();
  params.set("q", "가".repeat(500));
  params.set("f_service_id", "가".repeat(500));
  const snapshot = savedListQuery(params, ["title"], ["service_id"]);
  assert.ok(
    snapshot.length > savedListQueryLimit,
    `snapshot is only ${snapshot.length} characters`,
  );
  // Saving this snapshot reports success, but the next visit reads nothing.
  assert.deepEqual(
    readListPreferences(
      JSON.stringify({
        views: [{ id: "one", name: "긴 조건", query: snapshot }],
      }),
    ).views,
    [],
  );
  assert.equal(savedListQueryTooLong(snapshot), true);

  const short = new URLSearchParams();
  short.set("q", "가".repeat(300));
  short.set("f_service_id", "결제");
  const kept = savedListQuery(short, ["title"], ["service_id"]);
  assert.equal(savedListQueryTooLong(kept), false);
  assert.deepEqual(
    readListPreferences(
      JSON.stringify({
        views: [{ id: "one", name: "짧은 조건", query: kept }],
      }),
    ).views,
    [{ id: "one", name: "짧은 조건", query: kept }],
  );
});

test("clipping a long search or filter never splits a surrogate pair into replacement characters", () => {
  const long = "가".repeat(499) + "🚀" + "나";
  const params = new URLSearchParams();
  params.set("q", long);
  params.set("f_status", long);
  const restored = new URLSearchParams(
    savedListQuery(params, ["title"], ["status"]),
  );
  for (const key of ["q", "f_status"]) {
    const value = restored.get(key);
    assert.ok(!value.includes("�"), `${key} kept a replacement character`);
    assert.ok(long.startsWith(value), `${key} is not a prefix of the original`);
    assert.equal(value.length, 499);
  }
});
