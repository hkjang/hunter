import test from "node:test";
import assert from "node:assert/strict";
import {
  channelDraft,
  channelPayload,
  ruleDraft,
  rulePayload,
  notificationHistoryQuery,
  notificationTabs,
} from "../src/notification-state.ts";
import { switchWorkflowTab } from "../src/workflow-navigation.ts";
const stamp = "2026-09-12T12:00:00.123456Z";
const http = {
  name: "사내 알림",
  type: "webhook",
  enabled: false,
  config: {
    endpoint: "http://gateway.internal/messages",
    auth: "bearer",
    headers: { "X-Client": "hunter" },
    body_template: { to: "{{message.recipient}}", text: "{{message.body}}" },
  },
};
test("channel secrets remain omitted until explicitly replaced or cleared, never copied from server output", () => {
  const source = {
    ...http,
    secret: "must-not-copy",
    secret_configured: true,
    updated_at: stamp,
  };
  const draft = channelDraft(source);
  assert.equal(draft.secret, "");
  assert.equal(draft.secretMode, "keep");
  const kept = channelPayload(draft, source);
  assert.equal(kept.expected_updated_at, stamp);
  assert.equal("secret" in kept, false);
  assert.equal("clear_secret" in kept, false);
  const replaced = channelPayload(
    { ...draft, secretMode: "replace", secret: "new-token" },
    source,
  );
  assert.equal(replaced.secret, "new-token");
  const cleared = channelPayload(
    { ...draft, secretMode: "clear", secret: "not-used" },
    source,
  );
  assert.equal(cleared.clear_secret, true);
  assert.equal("secret" in cleared, false);
  assert.equal(source.secret, "must-not-copy");
});
test("HTTP body accepts structured JSON and checks form-only strings, no accidental unsafe parse or hidden fields", () => {
  const draft = channelDraft(http);
  assert.deepEqual(
    channelPayload(draft).config.body_template,
    http.config.body_template,
  );
  assert.throws(() => channelPayload({ ...draft, headersJSON: "[]" }), /객체/);
  assert.throws(
    () => channelPayload({ ...draft, bodyJSON: "not json" }),
    /JSON/,
  );
  assert.throws(
    () =>
      channelPayload({
        ...draft,
        config: { ...draft.config, format: "form" },
        bodyJSON: '{"nested":{"x":1}}',
      }),
    /중첩/,
  );
  assert.throws(
    () =>
      channelPayload({
        ...draft,
        bodyJSON: '{"value":"' + "가".repeat(22000) + '"}',
      }),
    /64KiB/,
  );
  assert.throws(
    () => channelPayload({ ...draft, name: "가".repeat(67) }),
    /200바이트/,
  );
});
test("plaintext SMTP configuration cannot accidentally submit an account or a replacement password", () => {
  const draft = channelDraft({
    name: "내부 릴레이",
    type: "smtp",
    enabled: false,
    config: {
      host: "127.0.0.1",
      port: 2525,
      security: "none",
      from: "qa@example.internal",
    },
  });
  assert.equal(channelPayload(draft).config.port, 2525);
  assert.throws(
    () =>
      channelPayload({
        ...draft,
        config: { ...draft.config, username: "account" },
      }),
    /인증 정보/,
  );
  assert.throws(
    () =>
      channelPayload({ ...draft, secretMode: "replace", secret: "password" }),
    /인증 정보/,
  );
});
test("rule drafts whitelist editable fields, preserve arrays without mutation and tolerate omitted optional filters", () => {
  const source = {
    ...ruleDraft(),
    id: "rule-1",
    created_at: stamp,
    updated_at: stamp,
    name: "합성 규칙",
    channel_id: "channel-1",
    recipients: ["qa@example.internal"],
    secret: "never",
    filters: { severities: null, teams: [], service_ids: [] },
  };
  const draft = ruleDraft(source);
  assert.equal("id" in draft, false);
  assert.equal("secret" in draft, false);
  assert.deepEqual(draft.filters.severities, []);
  draft.recipients.push("two@example.internal");
  assert.equal(source.recipients.length, 1);
  const payload = rulePayload({ ...draft, unexpected: "ignored" }, source);
  assert.equal(payload.expected_updated_at, stamp);
  assert.equal("unexpected" in payload, false);
  assert.equal("updated_at" in payload, false);
});
test("rule validation counts UTF8 limits and requires explicit static recipients and known events", () => {
  const valid = {
    ...ruleDraft(),
    name: "규칙",
    channel_id: "channel-1",
    recipients: ["one@example.internal", "one@example.internal"],
  };
  assert.deepEqual(rulePayload(valid).recipients, ["one@example.internal"]);
  assert.throws(
    () => rulePayload({ ...valid, subject_template: "가".repeat(67) }),
    /200바이트/,
  );
  assert.throws(
    () => rulePayload({ ...valid, body_template: "가".repeat(5334) }),
    /16,000바이트/,
  );
  assert.throws(() => rulePayload({ ...valid, events: ["unknown"] }), /이벤트/);
  assert.throws(() => rulePayload({ ...valid, recipients: [] }), /수신자/);
  assert.throws(() => rulePayload({ ...valid, max_attempts: 6 }), /1~5회/);
});
test("history URL sanitizes status, pagination and sorting while keeping tabs independent", () => {
  const query = new URLSearchParams(
    notificationHistoryQuery(
      new URLSearchParams(
        "status=failed&page=-3&size=500&sort=password&secret=hidden",
      ),
    ),
  );
  assert.equal(query.get("status"), "failed");
  assert.equal(query.get("page"), "1");
  assert.equal(query.get("size"), "25");
  assert.equal(query.has("sort"), false);
  assert.equal(query.has("secret"), false);
  const current = new URLSearchParams(
    "tab=history&q=channel&status=failed&page=3&delivery=d-1",
  );
  const extras = {
    history: ["status", "channel_id", "event_type", "delivery"],
  };
  const rules = switchWorkflowTab(
    current,
    "history",
    "rules",
    notificationTabs,
    extras,
  );
  assert.equal(rules.has("q"), false);
  assert.equal(rules.has("delivery"), false);
  rules.set("q", "my rule");
  const back = switchWorkflowTab(
    rules,
    "rules",
    "history",
    notificationTabs,
    extras,
  );
  assert.equal(back.get("q"), "channel");
  assert.equal(back.get("status"), "failed");
  assert.equal(back.get("page"), "3");
  assert.equal(back.get("delivery"), "d-1");
});
