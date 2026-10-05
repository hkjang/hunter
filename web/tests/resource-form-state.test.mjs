import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  changeResourceField,
  resourceSubmitBody,
  withEditRevision,
  resourceDetailPath,
} from "../src/resource-form-state.ts";
const dateFixture = JSON.parse(
  readFileSync(
    new URL(
      "../../internal/app/testdata/resource-datetime.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
test("changing service clears declared child IDs while preserving unrelated draft fields", () => {
  const source = {
    service_id: "A",
    scope_id: "scope-A",
    scenario_id: "scenario-A",
    finding_id: "finding-A",
    authorized_profile_id: "auth-A",
    title: "내가 쓴 설명",
    secret: "private",
  };
  const fields = [
    { key: "scope_id", type: "scope" },
    { key: "scenario_id", type: "scenario" },
    { key: "finding_id" },
    { key: "authorized_profile_id", type: "auth" },
  ];
  const changed = changeResourceField(source, "service_id", "B", fields);
  for (const key of [
    "scope_id",
    "scenario_id",
    "finding_id",
    "authorized_profile_id",
  ])
    assert.equal(changed[key], "");
  assert.equal(changed.title, source.title);
  assert.equal(changed.secret, source.secret);
  assert.equal(source.scope_id, "scope-A");
  assert.equal(
    changeResourceField(source, "service_id", "A", fields).scope_id,
    "scope-A",
  );
});
test("leaving authorization clears scenario without clearing unrelated scope", () => {
  const value = changeResourceField(
    { profile: "authorization", scenario_id: "one", scope_id: "same" },
    "profile",
    "http-baseline",
    [{ key: "scenario_id", type: "scenario" }],
  );
  assert.equal(value.scenario_id, "");
  assert.equal(value.scope_id, "same");
});
test("edit concurrency token is the original server revision and never a draft override", () => {
  const original = { updated_at: "2026-09-12T12:34:56.123456Z" };
  assert.equal(
    withEditRevision(
      { title: "draft", expected_updated_at: "forged" },
      original,
    ).expected_updated_at,
    original.updated_at,
  );
  assert.deepEqual(
    withEditRevision({ title: "create", expected_updated_at: "forged" }),
    { title: "create" },
  );
  assert.throws(() => withEditRevision({ title: "draft" }, {}), /최신 자료/);
});
test("canonical detail links contain only selected ID and the valid finding activity tab", () => {
  assert.equal(
    resourceDetailPath("findings", "id & /", true),
    "/findings?item=id+%26+%2F&detail_tab=activity",
  );
  assert.equal(
    resourceDetailPath("scopes", "scope-one", true),
    "/admin/scopes?item=scope-one",
  );
  assert.equal(resourceDetailPath("scans", "scan-one"), "/scans?item=scan-one");
});
// The four datetime fields of the common resource form (findings due_date and
// expires_at, schedules next_run_at, scopes expires_at) are all read on the
// server with time.Parse(time.RFC3339, s). The fixture's "accepted" column is
// asserted against those real validators in
// internal/app/resource_datetime_test.go, so anything it marks accepted:false is
// a string no server validator can read and the submission is lost to a 400.
test("the common resource form only submits a datetime the server accepts, in every browser time zone", () => {
  assert.ok(dateFixture.cases.length > 0);
  const accepted = new Map(
    [...dateFixture.cases, ...dateFixture.wireOnly].map((v) => [
      v.wire,
      v.accepted,
    ]),
  );
  const fields = [
    { key: "title", label: "제목", required: true },
    { key: "expires_at", label: "위험 수용 만료 일시", type: "datetime" },
  ];
  const original = process.env.TZ;
  try {
    for (const { name, form, wire, accepted: ok } of dateFixture.cases) {
      // Node re-reads process.env.TZ for each new Date, so this is the browser
      // zone the operator's machine is set to.
      process.env.TZ = form.tz;
      let body;
      try {
        body = resourceSubmitBody(fields, {
          title: "검증 대상",
          expires_at: form.value,
        });
      } catch (error) {
        assert.match(error.message, /위험 수용 만료 일시/u, name);
        assert.equal(ok, false, `${name} must not be rejected by the form`);
        continue;
      }
      // Whatever it did submit has to be a string the server takes, and it has
      // to be the instant the fixture pins rather than some other encoding.
      assert.equal(body.expires_at, wire, name);
      assert.equal(
        accepted.get(body.expires_at),
        true,
        `${name} submitted ${body.expires_at}, which the server cannot read`,
      );
      assert.equal(body.title, "검증 대상", name);
    }
    for (const { name, form } of dateFixture.unsendable) {
      // toISOString throws RangeError on these, which reached the operator as
      // the untranslated browser text "Invalid time value".
      process.env.TZ = form.tz;
      assert.throws(
        () =>
          resourceSubmitBody(fields, {
            title: "검증 대상",
            expires_at: form.value,
          }),
        /위험 수용 만료 일시/u,
        name,
      );
    }
  } finally {
    if (original === undefined) delete process.env.TZ;
    else process.env.TZ = original;
  }
});
test("an empty datetime stays empty and a required empty datetime is reported by label", () => {
  assert.equal(
    resourceSubmitBody(
      [{ key: "due_date", label: "조치 기한", type: "datetime" }],
      { due_date: "" },
    ).due_date,
    "",
  );
  assert.throws(
    () =>
      resourceSubmitBody(
        [
          {
            key: "next_run_at",
            label: "첫 실행 일시",
            type: "datetime",
            required: true,
          },
        ],
        { next_run_at: "" },
      ),
    /첫 실행 일시 항목을 입력해 주세요/u,
  );
});
// The two JSON fields of the common resource form declare the container the
// server reads them back as: services "targets" declares [] and is asserted to
// be []any in internal/app/domain.go, integrations "config" declares {}. The
// field pairs below are the real declarations from web/src/resources.tsx.
const targetsField = {
  key: "targets",
  label: "추가 공격 표면",
  type: "json",
  default: [],
};
const configField = {
  key: "config",
  label: "연동 세부 설정 (JSON)",
  type: "json",
  default: {},
};
test("clearing a JSON field submits the container its declaration promised", () => {
  // An operator who selects everything in the JsonInput and deletes it used to
  // submit {} for an array field, which the asset graph reads with
  // s["targets"].([]any) and drops without a word.
  for (const blank of ["", "   ", "\n\t "])
    assert.deepEqual(
      resourceSubmitBody([targetsField], { targets: blank }).targets,
      [],
      JSON.stringify(blank),
    );
  assert.deepEqual(
    resourceSubmitBody([configField], { config: "" }).config,
    {},
  );
});
test("a JSON field whose container differs from its declaration is reported by label", () => {
  for (const wrong of ["{}", '{"type":"api"}', "5", "null", '"api"', "true"])
    assert.throws(
      () => resourceSubmitBody([targetsField], { targets: wrong }),
      /추가 공격 표면: .*배열/u,
      wrong,
    );
  for (const wrong of ["[]", '[{"type":"api"}]', "0"])
    assert.throws(
      () => resourceSubmitBody([configField], { config: wrong }),
      /연동 세부 설정 \(JSON\): .*객체/u,
      wrong,
    );
  // The existing malformed-JSON wording stays the answer for text that is not
  // JSON at all, so the operator is told which of the two problems they have.
  assert.throws(
    () => resourceSubmitBody([targetsField], { targets: "[{type:" }),
    /추가 공격 표면: 올바른 JSON 형식을 입력해 주세요\./u,
  );
  // Valid input of the declared container reaches the server byte for byte.
  const valid = '[{"type":"api","value":"https://service.internal/api"}]';
  assert.deepEqual(
    resourceSubmitBody([targetsField], { targets: valid }).targets,
    JSON.parse(valid),
  );
  assert.deepEqual(
    resourceSubmitBody([configField], { config: '{"path":"/a"}' }).config,
    { path: "/a" },
  );
});
