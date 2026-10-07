import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resourceNumberBounds } from "../src/resource-form-state.ts";
const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../../internal/app/testdata/resource-number-bounds.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const resourcesSource = readFileSync(
  new URL("../src/resources.tsx", import.meta.url),
  "utf8",
);

// The Go half of this fixture (internal/app/resource_number_bounds_test.go)
// derives its probes from the same min/max columns and runs them through the
// real validateScope, validatePolicy, validateContributionPoints and
// validateSchedule, so these columns are the range the server accepts rather
// than a second opinion about it. Asserting the shared table against them is
// what keeps the declarations from drifting back: a Mantine NumberInput clamps
// the typed value to its declared min/max on blur, so a bound the server refuses
// is not merely unhelpful, it moves the operator's value for them - and a field
// that declares no max at all, as findings contribution_points did, lets the
// operator past the ceiling and answers only with the save's 400.
test("the form number bounds table is the range the server accepts", () => {
  const expected = {};
  for (const b of fixture.bounds) {
    assert.ok(b.kind && b.field, `malformed fixture row: ${JSON.stringify(b)}`);
    expected[b.kind] ??= {};
    expected[b.kind][b.field] = {
      min: b.min,
      max: b.max,
      integer: b.integer,
    };
  }
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(resourceNumberBounds)),
    expected,
  );
});

// The declarations live in resources.tsx, which the test runner cannot import
// because Node only strips types from .ts. Reading the source keeps the table
// from being exported but unused: every field has to spread it instead of
// restating a literal bound beside it.
test("every bounded number field spreads the shared bounds", () => {
  for (const b of fixture.bounds) {
    assert.ok(
      resourcesSource.includes(`...resourceNumberBounds.${b.kind}.${b.field}`),
      `${b.kind}.${b.field} does not spread the shared bounds table`,
    );
  }
});

// Whatever decimal is submitted, the server truncates it to an integer and
// stores that instead - or refuses it for a floor the typed value never looked
// like it crossed. Both outcomes are silent, so the declaration has to carry the
// integer lock the renderer turns into allowDecimal={false}.
test("the fields the server truncates are declared integer-only", () => {
  const seen = new Set();
  for (const d of fixture.decimals) {
    const bound = resourceNumberBounds[d.kind]?.[d.field];
    assert.ok(bound, `${d.kind}.${d.field} is missing from the bounds table`);
    assert.equal(
      bound.integer,
      true,
      `${d.kind}.${d.field} accepts decimals the server would change`,
    );
    assert.ok(!Number.isInteger(d.value), `${d.name} is not a decimal case`);
    seen.add(`${d.kind}.${d.field}`);
  }
  assert.equal(
    seen.size,
    fixture.bounds.length,
    "every bounded field needs a decimal case",
  );
  // The lock has to be read off the declaration rather than hardcoded into the
  // branch, which every kind shares - settings.tsx renders its own number fields
  // through the same FieldForm and declares no integer lock on them.
  assert.ok(
    /allowDecimal=\{[^}]*f\.integer[^}]*\}/.test(resourcesSource),
    "the number renderer does not take allowDecimal from the field declaration",
  );
});
