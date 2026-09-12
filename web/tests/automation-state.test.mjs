import test from "node:test";
import assert from "node:assert/strict";
import {
  automationDefaults,
  notificationAutomationDraft,
  notificationAutomationPayload,
  localDateTime,
  isoDateTime,
  boundedPageQuery,
  inboxAcknowledgementState,
  automationTabs,
} from "../src/automation-state.ts";
import { ruleDraft, rulePayload } from "../src/notification-state.ts";
import { switchWorkflowTab } from "../src/workflow-navigation.ts";
const revision = "2026-09-12T03:04:05.123456789Z";
test("automation drafts omit read-only and credential fields and isolate nested mutable arrays", () => {
  const raw = {
    ...structuredClone(automationDefaults),
    updated_at: revision,
    secret: "not-allowed",
    contacts: [
      {
        user_id: "u1",
        email: "one@example.internal",
        phone: "",
        webhook_id: "",
        verified: true,
        secret: "no",
      },
    ],
    grouping: {
      ...automationDefaults.grouping,
      internal_audit: "not-editable",
    },
  };
  const draft = notificationAutomationDraft(raw);
  assert.equal("secret" in draft, false);
  assert.equal("secret" in draft.contacts[0], false);
  assert.equal("updated_at" in draft, false);
  assert.equal("internal_audit" in draft.grouping, false);
  draft.contacts[0].email = "changed@example.internal";
  draft.grouping.emergency_severities.push("high");
  assert.equal(raw.contacts[0].email, "one@example.internal");
  assert.deepEqual(raw.grouping.emergency_severities, ["critical"]);
  const payload = notificationAutomationPayload(draft, revision);
  assert.equal(payload.expected_updated_at, revision);
  assert.equal(payload.config.enabled, false);
  assert.throws(() => notificationAutomationPayload(draft, ""), /기준 시각/);
});
test("calendar validation rejects normalized impossible dates and invalid on-call intervals before submission", () => {
  const draft = structuredClone(automationDefaults);
  draft.calendar.holidays = ["2028-02-29"];
  assert.equal(
    notificationAutomationPayload(draft, revision).config.calendar.holidays[0],
    "2028-02-29",
  );
  draft.calendar.holidays = ["2027-02-29"];
  assert.throws(() => notificationAutomationPayload(draft, revision), /휴일/);
  draft.calendar.holidays = [];
  draft.on_call = [
    {
      team: "보안팀",
      user_id: "u1",
      starts_at: "2030-01-01T09:00:00+09:00",
      ends_at: "2030-01-01T08:00:00+09:00",
    },
  ];
  assert.throws(() => notificationAutomationPayload(draft, revision), /종료/);
});
test("dynamic-only recipients are valid while unknown sources and entirely empty recipients remain rejected", () => {
  const draft = {
    ...ruleDraft(),
    name: "현재 담당자 알림",
    channel_id: "c1",
    recipients: [],
    recipient_sources: ["assignee"],
    events: ["finding.due_soon", "finding.unacknowledged", "team.weekly"],
  };
  const body = rulePayload(draft, { updated_at: revision });
  assert.deepEqual(body.recipient_sources, ["assignee"]);
  assert.deepEqual(body.recipients, []);
  assert.equal(body.expected_updated_at, revision);
  assert.throws(
    () => rulePayload({ ...draft, recipient_sources: [] }),
    /수신자/,
  );
  assert.throws(
    () => rulePayload({ ...draft, recipient_sources: ["email_from_evidence"] }),
    /수신자/,
  );
  assert.deepEqual(
    ruleDraft({ ...draft, recipient_sources: null }).recipient_sources,
    [],
  );
});
test("delivery accepted state does not imply acknowledgement in the personal inbox", () => {
  assert.equal(inboxAcknowledgementState({ status: "sent" }), "notice");
  assert.equal(
    inboxAcknowledgementState({
      status: "sent",
      ack_due_at: "2030-01-01T00:00:00Z",
    }),
    "pending",
  );
  assert.equal(
    inboxAcknowledgementState({
      status: "sent",
      ack_due_at: "2030-01-01T00:00:00Z",
      acknowledged_at: "2029-12-31T23:00:00Z",
    }),
    "acknowledged",
  );
});
test("date-time editing preserves the instant across browser-local display and RFC3339 encoding", () => {
  const value = "2031-06-01T13:24:00.000Z";
  assert.equal(isoDateTime(localDateTime(value)), value);
  assert.equal(isoDateTime(""), "");
  assert.equal(localDateTime("invalid"), "");
  assert.throws(() => isoDateTime("invalid"), /유효한/);
});
test("server-paged query only carries declared filters and bounded paging, never local search or unrelated values", () => {
  const result = boundedPageQuery(
    new URLSearchParams(
      "status=pending&page=-2&size=500&q=내부&secret=private&sort=body",
    ),
    { status: ["all", "pending", "acknowledged"] },
  );
  assert.equal(result.toString(), "status=pending&page=1&size=25");
  assert.equal(
    boundedPageQuery(new URLSearchParams("page=999999999&size=10"), {}).get(
      "page",
    ),
    "1000000",
  );
});
test("automation tab return restores only its owned history filters, without exposing them in contact queries", () => {
  const extra = { history: ["kind", "status"], workflows: ["workflow"] };
  const first = new URLSearchParams(
    "tab=history&kind=ticket_sync&status=conflict&page=4",
  );
  const contacts = switchWorkflowTab(
    first,
    "history",
    "recipients",
    automationTabs,
    extra,
  );
  assert.equal(contacts.has("status"), false);
  assert.equal(contacts.has("page"), false);
  const back = switchWorkflowTab(
    contacts,
    "recipients",
    "history",
    automationTabs,
    extra,
  );
  assert.equal(back.get("status"), "conflict");
  assert.equal(back.get("kind"), "ticket_sync");
  assert.equal(back.get("page"), "4");
});

const { changeEvidenceEntries } = await import("../src/automation-state.ts");
test("변경 미리보기의 null 그룹과 잘못된 배열은 제외하고 실제 문자열 근거만 표시한다", () => {
  assert.deepEqual(
    changeEvidenceEntries({
      paths: ["src/auth.ts"],
      api_paths: null,
      components: "wrong",
      permissions: [null, 3, "", "role.read"],
      ignored: ["outside"],
    }),
    [
      { key: "paths", label: "파일", values: ["src/auth.ts"] },
      { key: "permissions", label: "권한", values: ["role.read"] },
    ],
  );
  assert.deepEqual(changeEvidenceEntries(null), []);
});
