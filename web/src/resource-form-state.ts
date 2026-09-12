type Values = Record<string, unknown>;
type Field = { key: string; type?: string };

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
  return next;
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
