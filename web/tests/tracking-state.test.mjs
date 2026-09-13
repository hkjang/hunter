import assert from "node:assert/strict";
import test from "node:test";
import {
  emptyTracking,
  trackingFrameURL,
  trackingPage,
  trackingStatus,
  validateTrackingDraft,
} from "../src/tracking-state.ts";

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
