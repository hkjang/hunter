import assert from "node:assert/strict";
import test from "node:test";
import {
  automaticLoginSuppressed,
  clearAutomaticLoginSuppression,
  localLoginURL,
  loginReturn,
  oidcLoginMessage,
  oidcLoginURL,
  safeLoginReturn,
  shouldAutomaticallyLogin,
  suppressAutomaticLogin,
} from "../src/auth-flow.ts";

const enabled = {
  oidc_enabled: true,
  oidc_auto_login: true,
  oidc_auto_login_allowed: true,
};
test("automatic SSO requires an explicit unauthenticated response and all policy flags", () => {
  assert.equal(shouldAutomaticallyLogin(401, enabled, "", false), true);
  for (const status of [0, 200, 403, 500])
    assert.equal(shouldAutomaticallyLogin(status, enabled, "", false), false);
  for (const key of Object.keys(enabled))
    assert.equal(
      shouldAutomaticallyLogin(401, { ...enabled, [key]: false }, "", false),
      false,
    );
  for (const search of [
    "?local=1",
    "?sso=skip",
    "?error=oidc_login_required",
    "?error=",
    "?sso=skip&return_to=/services",
  ])
    assert.equal(shouldAutomaticallyLogin(401, enabled, search, false), false);
  assert.equal(shouldAutomaticallyLogin(401, enabled, "", true), false);
});
test("SSO preserves internal deep-link query and hash without accepting external or auth redirects", () => {
  const destination = "/agents/run-1?tab=messages&q=hello#message-2";
  assert.equal(
    loginReturn({
      pathname: "/agents/run-1",
      search: "?tab=messages&q=hello",
      hash: "#message-2",
    }),
    destination,
  );
  const auto = new URL(
    oidcLoginURL("auto", destination),
    "https://hunter.invalid",
  );
  assert.equal(auto.searchParams.get("mode"), "auto");
  assert.equal(auto.searchParams.get("return_to"), destination);
  const callback = {
    pathname: "/login",
    search: "?sso=skip&return_to=" + encodeURIComponent(destination),
  };
  assert.equal(loginReturn(callback, "/dashboard"), destination);
  assert.equal(
    new URL(
      localLoginURL(destination),
      "https://hunter.invalid",
    ).searchParams.get("return_to"),
    destination,
  );
  for (const path of [
    "https://evil.invalid/",
    "//evil.invalid",
    "/%2f%2fevil.invalid",
    "/api/auth/logout",
    "/login",
    "/services\\evil",
    "/services\n",
    "/services?x=" + "가".repeat(500),
  ])
    assert.equal(safeLoginReturn(path), null, path.slice(0, 40));
  assert.equal(
    new URL(
      oidcLoginURL("interactive", "https://evil.invalid"),
      "https://hunter.invalid",
    ).searchParams.get("return_to"),
    "/dashboard",
  );
});
test("a tab-level attempt guard survives a callback and fails closed on blocked storage", () => {
  const values = new Map();
  globalThis.sessionStorage = {
    getItem: (key) => values.get(key),
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
  assert.equal(automaticLoginSuppressed(), false);
  suppressAutomaticLogin();
  assert.equal(automaticLoginSuppressed(), true);
  assert.equal(automaticLoginSuppressed(Date.now() + 11 * 60 * 1000), false);
  clearAutomaticLoginSuppression();
  assert.equal(automaticLoginSuppressed(), false);
  globalThis.sessionStorage = {
    getItem() {
      throw new Error();
    },
    setItem() {
      throw new Error();
    },
    removeItem() {
      throw new Error();
    },
  };
  assert.doesNotThrow(() => suppressAutomaticLogin());
  // Unreadable storage counts as "already attempted": treating it as a fresh
  // tab would send prompt=none on every load and bounce the browser in a loop.
  assert.equal(automaticLoginSuppressed(), true);
  assert.equal(
    shouldAutomaticallyLogin(401, enabled, "", automaticLoginSuppressed()),
    false,
  );
  assert.doesNotThrow(() => clearAutomaticLoginSuppression());
  delete globalThis.sessionStorage;
  // No storage object at all is likewise not a reason to start an attempt.
  assert.equal(automaticLoginSuppressed(), true);
});
test("OIDC errors become fixed Korean recovery guidance rather than reflected query text", () => {
  assert.match(oidcLoginMessage("?error=oidc_login_required"), /추가 인증/);
  assert.match(oidcLoginMessage("?error=oidc_configuration"), /인증 서버/);
  assert.equal(
    oidcLoginMessage("?error=<script>secret</script>").includes("secret"),
    false,
  );
});
