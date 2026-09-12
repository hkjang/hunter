import test from "node:test";
import assert from "node:assert/strict";
import {
  switchWorkflowTab,
  normalizeSoftwareParams,
  utf8Length,
  sbomLabelError,
  copyCampaignDraft,
} from "../src/workflow-navigation.ts";
import {
  savedListQuery,
  applySavedListQuery,
} from "../src/saved-list-views.ts";

test("document and component tabs keep independent search, order and page through URL reload", () => {
  const tabs = ["documents", "components"];
  let next = switchWorkflowTab(
    new URLSearchParams(
      "q=배포문서&sort=created_at&dir=desc&page=3&size=50&f_service_id=s1",
    ),
    "documents",
    "components",
    tabs,
  );
  assert.equal(next.get("q"), null);
  assert.equal(next.get("page"), null);
  assert.equal(next.get("f_service_id"), "s1");
  next.set("q", "인증");
  next.set("page", "2");
  next.set("sort", "name");
  next = switchWorkflowTab(
    new URLSearchParams(next.toString()),
    "components",
    "documents",
    tabs,
  );
  assert.equal(next.get("q"), "배포문서");
  assert.equal(next.get("page"), "3");
  assert.equal(next.get("size"), "50");
  assert.equal(next.get("sort"), "created_at");
  next = switchWorkflowTab(next, "documents", "components", tabs);
  assert.equal(next.get("q"), "인증");
  assert.equal(next.get("page"), "2");
  assert.equal(next.get("sort"), "name");
});
test("detail comparison baseline and component selection return only to their declared tab", () => {
  const tabs = ["components", "dependencies", "compare", "metadata"],
    extras = { components: ["component"], compare: ["baseline"] };
  let next = switchWorkflowTab(
    new URLSearchParams("component=id%3Aref&q=auth&page=4"),
    "components",
    "compare",
    tabs,
    extras,
  );
  assert.equal(next.get("component"), null);
  next.set("baseline", "base-id");
  next.set("q", "추가");
  next = switchWorkflowTab(next, "compare", "components", tabs, extras);
  assert.equal(next.get("component"), "id:ref");
  assert.equal(next.get("baseline"), null);
  assert.equal(next.get("q"), "auth");
  next = switchWorkflowTab(next, "components", "compare", tabs, extras);
  assert.equal(next.get("baseline"), "base-id");
  assert.equal(next.get("q"), "추가");
});
test("tab snapshots never capture arbitrary URL values or unrecognized namespaces", () => {
  const next = switchWorkflowTab(
    new URLSearchParams(
      "q=service&token=never-store&_view_runs_token=bad&_view_unknown_q=wrong",
    ),
    "runs",
    "compare",
    ["runs", "compare"],
    { compare: ["baseline"] },
  );
  assert.equal(next.get("token"), "never-store");
  assert.equal(next.has("_view_runs_token"), false);
  assert.equal(next.has("_view_unknown_q"), false);
  assert.equal(
    [...next.keys()].filter((k) => k.startsWith("_view_")).join(","),
    "_view_runs_q",
  );
  assert.equal(
    switchWorkflowTab(next, "compare", "not-a-tab", [
      "runs",
      "compare",
    ]).toString(),
    next.toString(),
  );
});
test("legacy service URL becomes a supported saved-view filter without overriding an explicit filter", () => {
  const legacy = normalizeSoftwareParams(
    new URLSearchParams("service=a&q=core"),
  );
  assert.equal(legacy.get("service"), null);
  assert.equal(legacy.get("f_service_id"), "a");
  const snapshot = savedListQuery(legacy, ["name"], ["service_id"]);
  const restored = applySavedListQuery(
    new URLSearchParams("f_service_id=b&tab=components&page=3"),
    snapshot,
    ["name"],
    ["service_id"],
  );
  assert.equal(restored.get("f_service_id"), "a");
  assert.equal(restored.get("tab"), "components");
  assert.equal(restored.has("page"), false);
  assert.equal(
    normalizeSoftwareParams(
      new URLSearchParams("service=a&f_service_id=b"),
    ).get("f_service_id"),
    "b",
  );
});
test("SBOM name limit measures submitted UTF8 bytes including Korean and emoji", () => {
  assert.equal(utf8Length("한".repeat(66) + "ab"), 200);
  assert.equal(sbomLabelError("한".repeat(66) + "ab"), "");
  assert.ok(sbomLabelError("한".repeat(67)));
  assert.equal(sbomLabelError("😀".repeat(50)), "");
  assert.ok(sbomLabelError("😀".repeat(51)));
  assert.equal(sbomLabelError("  이름  "), "");
  assert.equal(sbomLabelError(""), "");
});
test("campaign copy keeps only editable draft fields and never carries runs or execution state", () => {
  const source = {
    id: "previous",
    name: "😀".repeat(200),
    description: "검토 목적",
    status: "completed",
    scans: [{ id: "old-run" }],
    targets: [
      {
        service_id: "s1",
        profile: "http-baseline",
        scope_id: "scope1",
        scenario_id: "irrelevant",
        secret: "never-copy",
      },
      { service_id: "s2", profile: "authorization", scenario_id: "scenario2" },
    ],
  };
  const draft = copyCampaignDraft(source);
  assert.ok(Array.from(draft.name).length <= 200);
  assert.ok(!draft.name.includes("\ud83d ·"));
  assert.equal(draft.description, source.description);
  assert.deepEqual(Object.keys(draft).sort(), [
    "description",
    "name",
    "targets",
  ]);
  assert.deepEqual(draft.targets, [
    { service_id: "s1", profile: "http-baseline", scope_id: "scope1" },
    { service_id: "s2", profile: "authorization", scenario_id: "scenario2" },
  ]);
  draft.targets[0].service_id = "different";
  assert.equal(source.targets[0].service_id, "s1");
  assert.equal(source.status, "completed");
});
