import assert from "node:assert/strict";
import test from "node:test";
import {
  searchNavigation,
  safeReturnPath,
  parseNavigationHistory,
  recordMenuVisit,
  toggleMenuFavorite,
  visibleSavedMenus,
  navigationStorageKey,
  saveLoginReturn,
  readLoginReturn,
  clearLoginReturn,
} from "../src/navigation.ts";
const entries = [
  { path: "/dashboard", label: "보안 현황" },
  { path: "/services", label: "서비스 자산" },
  { path: "/scans", label: "진단 실행" },
  { path: "/admin/settings", label: "서비스 설정" },
  { path: "/personal/keys", label: "개인 API 키" },
];
test("Korean initials and English aliases find the intended permitted menu", () => {
  assert.deepEqual(
    searchNavigation(entries, "ㅂㅇㅎㅎ").map((e) => e.path),
    ["/dashboard"],
  );
  assert.deepEqual(
    searchNavigation(entries, "ScAn").map((e) => e.path),
    ["/scans"],
  );
  assert.deepEqual(
    searchNavigation(entries, "API key").map((e) => e.path),
    ["/personal/keys"],
  );
  assert.deepEqual(
    searchNavigation(entries, "키클락").map((e) => e.path),
    ["/admin/settings"],
  );
  assert.equal(searchNavigation(entries, "없는 메뉴").length, 0);
});
test("menu ranking prioritizes exact names and tolerates Korean spacing", () => {
  assert.equal(searchNavigation(entries, "서비스자산")[0].path, "/services");
  assert.equal(
    searchNavigation(entries, "서비스 설정")[0].path,
    "/admin/settings",
  );
  assert.deepEqual(searchNavigation(entries, " "), entries);
});
test("saved favorites never reintroduce menus absent from the permission filtered list", () => {
  const limited = entries.filter((e) => !e.path.startsWith("/admin"));
  assert.deepEqual(
    visibleSavedMenus(limited, [
      "/admin/settings",
      "/services",
      "https://external.invalid",
    ]),
    [entries[1]],
  );
  assert.equal(searchNavigation(limited, "keycloak").length, 0);
});
test("history validates local menu paths and tolerates corrupt or unavailable storage", () => {
  assert.deepEqual(parseNavigationHistory("broken"), {
    favorites: [],
    recent: [],
  });
  assert.deepEqual(
    parseNavigationHistory(
      JSON.stringify({
        favorites: [
          "/services",
          "/services",
          "https://bad.invalid",
          "/api/settings",
          "/findings?q=secret",
        ],
        recent: null,
      }),
    ),
    { favorites: ["/services"], recent: [] },
  );
  assert.notEqual(
    navigationStorageKey("user-a"),
    navigationStorageKey("user-b"),
  );
});
test("recent menus are unique, bounded, and update only on a new visit", () => {
  let history = { favorites: ["/services"], recent: [] };
  for (let i = 0; i < 10; i++) history = recordMenuVisit(history, "/item" + i);
  assert.equal(history.recent.length, 8);
  history = recordMenuVisit(history, "/item5");
  assert.equal(history.recent[0], "/item5");
  assert.equal(history.recent.filter((p) => p === "/item5").length, 1);
  assert.equal(recordMenuVisit(history, "/item5"), history);
  assert.deepEqual(history.favorites, ["/services"]);
});
test("favorite toggling preserves recents and removes an existing favorite", () => {
  const history = { favorites: [], recent: ["/scans"] };
  const added = toggleMenuFavorite(history, "/services");
  assert.deepEqual(added, { favorites: ["/services"], recent: ["/scans"] });
  assert.deepEqual(toggleMenuFavorite(added, "/services"), history);
});
test("login return keeps the query and blocks external redirects or auth endpoints", () => {
  assert.equal(
    safeReturnPath("/findings?q=권한&sort=severity&dir=desc"),
    "/findings?q=%EA%B6%8C%ED%95%9C&sort=severity&dir=desc",
  );
  assert.equal(
    safeReturnPath("/agents/run-1?tab=logs#ignored"),
    "/agents/run-1?tab=logs",
  );
  for (const value of [
    "//evil.invalid",
    "https://evil.invalid",
    "/\\evil.invalid",
    "/%2f%2fevil.invalid",
    "/%5cevil.invalid",
    "/api/auth/logout",
    "/login?next=/services",
    "/mcp",
    "/",
    "/services\n",
    null,
  ])
    assert.equal(safeReturnPath(value), null, String(value));
});
test("SSO return is explicitly marked, expires, and can be cleared after login", () => {
  const values = new Map();
  globalThis.sessionStorage = {
    setItem: (key, value) => values.set(key, value),
    getItem: (key) => values.get(key) || null,
    removeItem: (key) => values.delete(key),
  };
  saveLoginReturn("/scans?q=running");
  assert.equal(readLoginReturn(), "/scans?q=running");
  assert.equal(readLoginReturn(true), null);
  saveLoginReturn("/scans?q=running", true);
  assert.equal(readLoginReturn(true), "/scans?q=running");
  const key = [...values.keys()][0];
  const item = JSON.parse(values.get(key));
  values.set(
    key,
    JSON.stringify({ ...item, createdAt: Date.now() - 16 * 60 * 1000 }),
  );
  assert.equal(readLoginReturn(true), null);
  clearLoginReturn();
  assert.equal(values.size, 0);
  delete globalThis.sessionStorage;
});
