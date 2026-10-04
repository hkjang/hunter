type Values = Record<string, unknown>;
type Field = { key: string; type?: string };
type Draft = Record<string, any>;
type SubmitField = {
  key: string;
  label: string;
  type?: string;
  required?: boolean;
};

/** Reset only declared relationships when their parent service/profile changes. */
export function changeResourceField(
  values: Values,
  key: string,
  value: unknown,
  fields: readonly Field[],
): Values {
  const next = { ...values, [key]: value };
  if (values[key] === value) return next;
  const declared = new Set(fields.map((field) => field.key));
  if (key === "service_id") {
    for (const child of [
      "scope_id",
      "execution_profile_id",
      "scenario_id",
      "finding_id",
      "authorized_profile_id",
      "unauthorized_profile_id",
    ])
      if (declared.has(child)) next[child] = "";
    for (const field of fields)
      if (["scope", "scenario", "auth"].includes(field.type || ""))
        next[field.key] = "";
  }
  if (
    key === "profile" &&
    value !== "authorization" &&
    declared.has("scenario_id")
  )
    next.scenario_id = "";
  if (
    key === "profile" &&
    value !== "isolated" &&
    declared.has("execution_profile_id")
  )
    next.execution_profile_id = "";
  return next;
}

/**
 * The browser-local datetime-local value turned into the one string the server
 * is ever given. Checked on that string rather than on the typed value, because
 * Date.prototype.toISOString emits ECMA-262's expanded year (+YYYYYY / -YYYYYY)
 * once the UTC instant leaves 0000-9999, and every server reader of these four
 * fields parses with time.Parse(time.RFC3339, s), whose layout takes exactly
 * four year digits and no sign. The browser time zone decides which side of the
 * boundary a typed value lands on, so an ordinary 9999-12-31T23:59 is in range
 * east of UTC and overflows west of it. schedules next_run_at
 * (internal/app/domain_schedules.go), scopes expires_at (internal/app/policy.go)
 * and findings due_date (internal/app/finding_ops.go) answer the overflow with a
 * 400, but findings expires_at has no write-time validator at all: the
 * unreadable string is stored and then read back as an inactive risk acceptance
 * by internal/app/domain.go, leaving the finding counted as open. toISOString
 * also throws RangeError outside the ECMAScript time value range, which used to
 * surface as the untranslated "Invalid time value".
 */
function resourceDateTimeWire(value: any, label: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || !/^\d{4}-/.test(date.toISOString()))
    throw new Error(
      `${label}: 세계 표준시로 바꾸면 서버가 받을 수 있는 연도 범위를 벗어납니다. 더 가까운 일시를 입력해 주세요.`,
    );
  return date.toISOString();
}

/**
 * The request body for every common resource form. Lives here rather than in
 * resources.tsx so the strings it submits can be asserted against the server
 * validators that judge them.
 */
export function resourceSubmitBody(
  fields: readonly SubmitField[],
  values: Draft,
): Draft {
  const out: Draft = { ...values };
  for (const f of fields) {
    if (f.type === "json") {
      try {
        out[f.key] = JSON.parse(values[f.key] || "{}");
      } catch {
        throw new Error(`${f.label}: 올바른 JSON 형식을 입력해 주세요.`);
      }
    }
    if (f.type === "datetime") {
      out[f.key] = values[f.key]
        ? resourceDateTimeWire(values[f.key], f.label)
        : "";
    }
    if (
      f.required &&
      (out[f.key] === "" ||
        out[f.key] == null ||
        (Array.isArray(out[f.key]) && !out[f.key].length))
    )
      throw new Error(`${f.label} 항목을 입력해 주세요.`);
  }
  return out;
}

/** The original server revision must not be replaced by an editable form value. */
export function withEditRevision(
  body: Values,
  original?: Values | null,
): Values {
  const next = { ...body };
  delete next.expected_updated_at;
  if (original) {
    if (typeof original.updated_at !== "string" || !original.updated_at)
      throw new Error(
        "수정 기준 시각을 확인할 수 없습니다. 최신 자료를 다시 불러오세요.",
      );
    next.expected_updated_at = original.updated_at;
  }
  return next;
}

/** Share the selected resource, never unrelated URL queries or form values. */
export function resourceDetailPath(
  kind: string,
  id: string,
  activity = false,
): string {
  const workspace = [
    "services",
    "findings",
    "scans",
    "scenarios",
    "remediations",
    "schedules",
    "approvals",
  ];
  const prefix = workspace.includes(kind) ? "" : "/admin";
  const params = new URLSearchParams({ item: id });
  if (kind === "findings" && activity) params.set("detail_tab", "activity");
  return `${prefix}/${encodeURIComponent(kind)}?${params}`;
}
