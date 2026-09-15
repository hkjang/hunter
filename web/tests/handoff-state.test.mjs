import assert from "node:assert/strict";
import test from "node:test";
import {
  handoffClaimRequest,
  handoffOpenURL,
  handoffTargetsPayload,
} from "../src/handoff-state.ts";

test("the claim request carries the standard's shape and Hunter's one format", () => {
  assert.deepEqual(handoffClaimRequest("run-1"), {
    resource: "run-1",
    format: "markdown",
  });
});

test("the receiving service is opened at /handoff with source and claim encoded", () => {
  assert.equal(
    handoffOpenURL("https://ptium.intra", "https://hunter.intra", "a+b/c=&d?"),
    "https://ptium.intra/handoff?source=https%3A%2F%2Fhunter.intra&claim=a%2Bb%2Fc%3D%26d%3F",
  );
  assert.equal(
    handoffOpenURL("HTTP://Weekly.Intra:8080/", "http://h", "c"),
    "http://weekly.intra:8080/handoff?source=http%3A%2F%2Fh&claim=c",
  );
  for (const origin of [
    "ptium.intra",
    "javascript:alert(1)",
    "https://ptium.intra/other",
    "https://ptium.intra/?x=1",
    "https://ptium.intra/#x",
    "https://user@ptium.intra",
    "",
  ])
    assert.throws(
      () => handoffOpenURL(origin, "https://hunter.intra", "c"),
      /주소/,
      origin,
    );
  assert.throws(() => handoffOpenURL("https://ptium.intra", "", "c"), /표/);
  assert.throws(
    () => handoffOpenURL("https://ptium.intra", "https://hunter.intra", ""),
    /표/,
  );
});

test("blank target rows are dropped and the rest trimmed before saving", () => {
  assert.deepEqual(
    handoffTargetsPayload([
      {
        name: " Ptium ",
        origin: " https://ptium.intra ",
        formats: ["markdown"],
      },
      { name: "", origin: "", formats: [] },
      { name: "Weekly", origin: "", formats: undefined },
    ]),
    {
      targets: [
        { name: "Ptium", origin: "https://ptium.intra", formats: ["markdown"] },
        { name: "Weekly", origin: "", formats: [] },
      ],
    },
  );
});
