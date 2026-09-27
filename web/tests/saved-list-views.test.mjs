import test from "node:test";
import assert from "node:assert/strict";
import {
  listPreferenceKey,
  readListPreferences,
  savedListQuery,
  savedListQueryLimit,
  savedListQueryTooLong,
  savedViewSaveError,
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

const prefsWith = (...names) => ({
  density: "comfortable",
  expanded: false,
  views: names.map((name, i) => ({ id: `id-${i}`, name, query: "" })),
});
const COLUMNS = ["title"];
const FILTERS = ["service_id"];
// Each Hangul character costs nine characters once the snapshot is URL encoded,
// so a search and one filter at the 500 character value limit already pass the
// limit readListPreferences validates against.
const longParams = new URLSearchParams();
longParams.set("q", "가".repeat(500));
longParams.set("f_service_id", "가".repeat(500));
const shortParams = new URLSearchParams();
shortParams.set("q", "가".repeat(300));
shortParams.set("f_service_id", "결제");
const saveError = (prefs, title, params) =>
  savedViewSaveError(
    prefs,
    title,
    params,
    FILTERS,
    savedListQuery(params, COLUMNS, FILTERS),
  );

test("saving a view whose snapshot reading would discard is refused instead of reported as saved", () => {
  const snapshot = savedListQuery(longParams, COLUMNS, FILTERS);
  assert.ok(
    snapshot.length > savedListQueryLimit,
    `snapshot is only ${snapshot.length} characters`,
  );
  // Reading throws this view away, so reporting a successful save would lie.
  assert.deepEqual(
    readListPreferences(
      JSON.stringify({
        views: [{ id: "one", name: "긴 조건", query: snapshot }],
      }),
    ).views,
    [],
  );
  assert.deepEqual(saveError(prefsWith(), "긴 조건", longParams), {
    message:
      "검색어와 필터가 너무 길어 이 보기를 저장할 수 없습니다. 조건을 줄여 주세요.",
    focusName: false,
  });
});

test("saving a view reading would keep is accepted and restores on the next visit", () => {
  const snapshot = savedListQuery(shortParams, COLUMNS, FILTERS);
  assert.equal(savedListQueryTooLong(snapshot), false);
  assert.equal(
    saveError(prefsWith("다른 보기"), "짧은 조건", shortParams),
    null,
  );
  assert.deepEqual(
    readListPreferences(
      JSON.stringify({
        views: [{ id: "one", name: "짧은 조건", query: snapshot }],
      }),
    ).views,
    [{ id: "one", name: "짧은 조건", query: snapshot }],
  );
});

test("saving a view without a name is refused and returns focus to the name field", () => {
  assert.deepEqual(saveError(prefsWith(), "", shortParams), {
    message: "보기 이름을 입력해 주세요.",
    focusName: true,
  });
});

test("saving a ninth view is refused because reading keeps only eight", () => {
  const eight = prefsWith("1", "2", "3", "4", "5", "6", "7", "8");
  assert.equal(readListPreferences(JSON.stringify(eight)).views.length, 8);
  assert.deepEqual(saveError(eight, "아홉", shortParams), {
    message:
      "보기를 최대 8개까지 저장할 수 있습니다. 사용하지 않는 보기를 삭제해 주세요.",
    focusName: false,
  });
  assert.equal(saveError(prefsWith("1", "2", "3"), "넷", shortParams), null);
});

test("saving a duplicate name is refused and returns focus to the name field", () => {
  const prefs = prefsWith("심각한 발견 건");
  assert.deepEqual(saveError(prefs, "심각한 발견 건", shortParams), {
    message: "같은 이름의 보기가 있습니다. 다른 이름을 입력해 주세요.",
    focusName: true,
  });
  assert.equal(saveError(prefs, "심각한 발견 건 2", shortParams), null);
});

test("saving a search or filter value over 500 characters is refused before the snapshot is measured", () => {
  const expected = {
    message: "검색어나 필터 값이 너무 깁니다. 500자 이하로 줄여 주세요.",
    focusName: false,
  };
  const overQuery = new URLSearchParams({ q: "a".repeat(501) });
  assert.deepEqual(saveError(prefsWith(), "긴 검색어", overQuery), expected);
  const overFilter = new URLSearchParams({ f_service_id: "a".repeat(501) });
  assert.deepEqual(saveError(prefsWith(), "긴 필터", overFilter), expected);
  // Clipping keeps the snapshot short, so only this guard can catch the raw
  // value; an untracked filter key is not one of this list's conditions.
  assert.ok(
    !savedListQueryTooLong(savedListQuery(overQuery, COLUMNS, FILTERS)),
  );
  assert.equal(
    saveError(
      prefsWith(),
      "무관한 값",
      new URLSearchParams({ f_other: "a".repeat(501) }),
    ),
    null,
  );
  assert.equal(
    saveError(prefsWith(), "경계", new URLSearchParams({ q: "a".repeat(500) })),
    null,
  );
});

test("save conditions are decided in form order, from the name to the snapshot length", () => {
  // Every condition fails at once: the message names the one the user can fix
  // first, and only the last one depends on the encoded snapshot length.
  const full = prefsWith("겹침", "2", "3", "4", "5", "6", "7", "8");
  assert.equal(
    saveError(full, "", longParams).message,
    "보기 이름을 입력해 주세요.",
  );
  assert.match(saveError(full, "겹침", longParams).message, /최대 8개/);
  assert.match(
    saveError(prefsWith("겹침"), "겹침", longParams).message,
    /같은 이름의 보기가 있습니다/,
  );
  assert.match(
    saveError(prefsWith(), "겹침", longParams).message,
    /검색어와 필터가 너무 길어/,
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
