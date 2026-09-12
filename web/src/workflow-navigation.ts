// Only list controls and declared tab-specific identifiers are carried between
// tabs. The caller retains location.state, including its list return address.
const listKeys = ["q", "sort", "dir", "page", "size"];
const namespace = (tab: string, key: string) => `_view_${tab}_${key}`;
export function switchWorkflowTab(
  current: URLSearchParams,
  previousTab: string,
  nextTab: string,
  tabs: readonly string[],
  extraKeys: Record<string, string[]> = {},
) {
  const next = new URLSearchParams(current);
  if (
    !tabs.includes(previousTab) ||
    !tabs.includes(nextTab) ||
    previousTab === nextTab
  )
    return next;
  const owned = (tab: string) => [...listKeys, ...(extraKeys[tab] || [])];
  const allKeys = [...new Set(tabs.flatMap(owned))];
  const allowedStored = new Set(
    tabs.flatMap((tab) => owned(tab).map((key) => namespace(tab, key))),
  );
  for (const key of [...next.keys()])
    if (key.startsWith("_view_") && !allowedStored.has(key)) next.delete(key);
  for (const key of owned(previousTab)) {
    const value = current.get(key);
    const stored = namespace(previousTab, key);
    if (value) next.set(stored, value);
    else next.delete(stored);
  }
  for (const key of allKeys) next.delete(key);
  for (const key of owned(nextTab)) {
    const value = next.get(namespace(nextTab, key));
    if (value) next.set(key, value);
  }
  next.set("tab", nextTab);
  return next;
}

export function normalizeSoftwareParams(current: URLSearchParams) {
  const next = new URLSearchParams(current);
  if (!next.has("f_service_id") && next.has("service"))
    next.set("f_service_id", next.get("service") || "");
  next.delete("service");
  return next;
}

export function utf8Length(value: string) {
  return new TextEncoder().encode(value).length;
}
export function sbomLabelError(value: string) {
  return utf8Length(value.trim()) > 200
    ? "문서 이름은 UTF-8 기준 200바이트까지 입력할 수 있습니다. 한글은 보통 글자당 3바이트입니다."
    : "";
}

type DraftTarget = {
  service_id: string;
  profile: string;
  scope_id?: string;
  scenario_id?: string;
};
export function copyCampaignDraft(source: {
  name: string;
  description?: string;
  targets: DraftTarget[];
}) {
  return {
    name: `${Array.from(source.name).slice(0, 190).join("")} · 새 진단`,
    description: source.description || "",
    targets: source.targets.map((target) => ({
      service_id: target.service_id,
      profile: target.profile,
      ...(target.scope_id ? { scope_id: target.scope_id } : {}),
      ...(target.profile === "authorization" && target.scenario_id
        ? { scenario_id: target.scenario_id }
        : {}),
    })),
  };
}
