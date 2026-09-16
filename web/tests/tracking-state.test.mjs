import assert from "node:assert/strict";
import test from "node:test";
import {
  emptyTracking,
  trackingFrameURL,
  trackingPage,
  trackingSnippetOrigins,
  trackingStatus,
  trackingViolation,
  trackingViolationOrigin,
  validateTrackingDraft,
} from "../src/tracking-state.ts";

test("frame policy violations are relayed only for allowable http(s) targets", () => {
  assert.deepEqual(
    trackingViolation({
      type: "hunter:tracking-violation",
      blocked_uri: "https://stats.internal/collect?x=1",
      directive: "Connect-Src",
    }),
    {
      blocked_uri: "https://stats.internal/collect?x=1",
      directive: "connect-src",
    },
  );
  for (const value of [
    null,
    "blocked",
    { type: "hunter:tracking-status", status: "blocked" },
    {
      type: "hunter:tracking-violation",
      blocked_uri: "inline",
      directive: "script-src",
    },
    {
      type: "hunter:tracking-violation",
      blocked_uri: "data:text/plain,a",
      directive: "img-src",
    },
    {
      type: "hunter:tracking-violation",
      blocked_uri: "https://stats.internal",
      directive: "connect-src; script-src *",
    },
    {
      type: "hunter:tracking-violation",
      blocked_uri: "https://" + "a".repeat(300),
      directive: "img-src",
    },
    {
      type: "hunter:tracking-violation",
      blocked_uri: "https://stats.internal",
      directive: 1,
    },
  ])
    assert.equal(trackingViolation(value), null, JSON.stringify(value));
  assert.equal(
    trackingViolationOrigin("HTTPS://Stats.Internal:443/collect?id=1#frag"),
    "https://stats.internal",
  );
  assert.equal(
    trackingViolationOrigin("http://collector.internal:8443/pixel.gif"),
    "http://collector.internal:8443",
  );
  for (const uri of [
    "inline",
    "data:text/plain,a",
    "blob:https://x/1",
    "https://",
  ])
    assert.equal(trackingViolationOrigin(uri), null, uri);
});

test("tracking emits only fixed ordinary-page templates and titles", () => {
  assert.deepEqual(trackingPage("/services"), {
    path: "/services",
    title: "서비스 자산",
  });
  const detail = trackingPage("/agents/secret-uuid-123");
  assert.deepEqual(detail, {
    path: "/agents/:id",
    title: "에이전트 진단 상세",
  });
  assert.equal(JSON.stringify(detail).includes("secret"), false);
  for (const path of [
    "/login",
    "/admin/settings",
    "/admin/notifications",
    "/personal/keys",
    "/personal/profile",
    "/personal/inbox",
    "/api/auth/me",
    "/mcp",
    "/approvals",
    "/unknown",
    "/findings?q=private",
    "/services#secret",
    "/agents/x/nested",
  ])
    assert.equal(trackingPage(path), null, path);
});
test("only expected local frame URLs and plain statuses are accepted", () => {
  assert.equal(
    trackingFrameURL("/api/tracking/frame?revision=12"),
    "/api/tracking/frame?revision=12",
  );
  assert.equal(
    trackingFrameURL("/api/tracking/preview/synthetic-token", true),
    "/api/tracking/preview/synthetic-token",
  );
  for (const url of [
    "https://evil.invalid/frame",
    "//evil.invalid",
    "/api/auth/me",
    "/api/tracking/frame?revision=1&token=secret",
    "/api/tracking/frame?revision=1&revision=2",
    "/api/tracking/frame?revision=1#private",
    "/api/tracking/preview/../../auth/me",
  ])
    assert.equal(trackingFrameURL(url), null, url);
  assert.equal(
    trackingStatus({ type: "hunter:tracking-status", status: "ready" }),
    "ready",
  );
  for (const data of [
    null,
    "ready",
    { type: "other", status: "ready" },
    { type: "hunter:tracking-status", status: { toString: "bad" } },
    { type: "hunter:tracking-status", status: "injected" },
  ])
    assert.equal(trackingStatus(data), null);
});
test("script bytes, Unicode name length and exact permitted origins match the admin contract", () => {
  const config = {
    ...emptyTracking,
    enabled: true,
    script: "window.example = true",
    allowed_origins: ["https://analytics.internal:8443"],
  };
  assert.deepEqual(
    validateTrackingDraft(config, "https://hunter.internal"),
    [],
  );
  assert.deepEqual(
    validateTrackingDraft(
      { ...config, name: "한".repeat(100) },
      "https://hunter.internal",
    ),
    [],
  );
  assert.equal(
    validateTrackingDraft(
      { ...config, name: "한".repeat(101) },
      "https://hunter.internal",
    ).length,
    1,
  );
  assert.equal(
    validateTrackingDraft(
      { ...config, script: "한".repeat(10923) },
      "https://hunter.internal",
    ).length,
    1,
  );
  for (const origin of [
    "https://hunter.internal",
    "https://*.internal",
    "https://user:pass@analytics.internal",
    "https://analytics.internal/path",
    "https://analytics.internal?",
    "javascript:alert(1)",
  ])
    assert.equal(
      validateTrackingDraft(
        { ...config, allowed_origins: [origin] },
        "https://hunter.internal",
      ).length,
      1,
      origin,
    );
  assert.deepEqual(
    validateTrackingDraft({ ...emptyTracking }, "https://hunter.internal"),
    [],
  );
  assert.match(
    validateTrackingDraft(
      { ...config, allowed_origins: ["https://" + "a".repeat(301)] },
      "https://hunter.internal",
    ).join(" "),
    /300바이트/,
  );
  assert.match(
    validateTrackingDraft(
      {
        ...config,
        allowed_origins: Array.from(
          { length: 10 },
          (_, i) => `https://${"a".repeat(155)}${i}.internal`,
        ),
      },
      "https://hunter.internal",
    ).join(" "),
    /1,536바이트/,
  );
});

test("snippet origins are extracted with ASCII-only scheme matching and browser normalization", () => {
  const app = "https://hunter.internal";
  const snippet = `<script async src="HTTPS://Stats.Internal:443/hunter.js"></script>
<script>
  // 이름: "방문 통계 İ" — 다국어 주석 뒤에도 위치가 어긋나지 않아야 한다
  fetch('https://collector.internal:8443/collect?x=1', {mode:'no-cors'});
  new Image().src = "http://img.internal:80/p.gif#f";
  fetch("https://stats.internal/other");
  fetch(\`https://\${host}/collect\`);
  const idn = 'https://통계.example/x';
  const v6 = 'http://[::1]:9000/';
  const self = 'https://hunter.internal/api/tracking/violations';
</script>`;
  assert.deepEqual(trackingSnippetOrigins(snippet, app), [
    "https://stats.internal",
    "https://collector.internal:8443",
    "http://img.internal",
    "https://xn--989an41e.example",
    "http://[::1]:9000",
  ]);
  // Unicode case folding must not turn lookalike schemes into http(s):
  // U+212A KELVIN SIGN folds to "k" and U+017F LONG S folds to "s"; U+0130 changes
  // length when lowercased. None of these may produce or shift an origin.
  for (const text of [
    "\u210Cttps://fold.internal",
    "HTTP\u017F://fold.internal",
    "\u0130ttps://fold.internal",
    "https://",
    "https://user:pw@cred.internal",
    "https://esc%2Eexample",
    "https://under_score.internal",
    "wss://socket.internal",
    "https://${host}",
  ])
    assert.deepEqual(
      trackingSnippetOrigins(text, app),
      [],
      JSON.stringify(text),
    );
  assert.deepEqual(
    trackingSnippetOrigins(
      "\u212Attp://x.internal https://\u212Aelvin.internal",
      app,
    ),
    ["https://kelvin.internal"],
  );
  assert.deepEqual(trackingSnippetOrigins("", app), []);
});
