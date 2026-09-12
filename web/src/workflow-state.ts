export const queueViews = [
  { value: "all", label: "모든 조치" },
  { value: "mine", label: "내가 등록한 발견 건" },
  { value: "overdue", label: "기한 초과" },
  { value: "due_soon", label: "기한 임박" },
  { value: "unassigned", label: "담당자 미지정" },
];
export function readQueueParams(params: URLSearchParams) {
  const rawPage = Number(params.get("page"));
  const rawSize = Number(params.get("size"));
  return {
    view: queueViews.some((item) => item.value === params.get("view"))
      ? params.get("view")!
      : "all",
    query: params.get("q") || "",
    group: params.get("group") || "",
    page: Number.isSafeInteger(rawPage) && rawPage > 0 ? rawPage : 1,
    size: [10, 25, 50, 100].includes(rawSize) ? rawSize : 25,
  };
}
export function queueRequest(params: URLSearchParams) {
  const state = readQueueParams(params);
  const query = new URLSearchParams({
    view: state.view,
    q: state.query,
    page: String(state.page),
    size: String(state.size),
  });
  if (state.group) query.set("group", state.group);
  return `/api/finding-queue?${query}`;
}
export function percentText(value: number | null | undefined) {
  return typeof value === "number" && Number.isFinite(value)
    ? `${(value * 100).toLocaleString("ko-KR", { maximumFractionDigits: 2 })}%`
    : "미확인";
}
export function parseSBOM(content: string): object {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(
      "JSON 형식을 확인하세요. 파일 전체가 올바른 JSON이어야 합니다.",
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error("SBOM 문서는 JSON 객체여야 합니다.");
  const doc = parsed as Record<string, unknown>;
  const supported =
    (doc.bomFormat === "CycloneDX" &&
      ["1.4", "1.5", "1.6"].includes(String(doc.specVersion))) ||
    ["SPDX-2.2", "SPDX-2.3"].includes(String(doc.spdxVersion));
  if (!supported)
    throw new Error(
      "CycloneDX 1.4–1.6 또는 SPDX 2.2·2.3 JSON 파일을 선택하세요.",
    );
  return parsed;
}
export function safeListReturn(
  value: unknown,
  path: "/software" | "/campaigns",
) {
  return typeof value === "string" &&
    (value === path || value.startsWith(`${path}?`)) &&
    !/[\\\u0000-\u001f]/.test(value)
    ? value
    : path;
}
export function campaignTargetError(
  targets: { service_id: string; profile: string; scenario_id?: string }[],
) {
  if (!targets.length || targets.length > 20)
    return "진단 대상을 1개 이상, 최대 20개까지 추가하세요.";
  const keys = new Set<string>();
  for (const target of targets) {
    if (
      !target.service_id ||
      !["http-baseline", "authorization", "import-only"].includes(
        target.profile,
      )
    )
      return "모든 대상의 서비스와 진단 프로파일을 선택하세요.";
    if (target.profile === "authorization" && !target.scenario_id)
      return "업무 권한 검증에는 권한 시나리오가 필요합니다.";
    const key = JSON.stringify([
      target.service_id,
      target.profile,
      target.scenario_id || "",
    ]);
    if (keys.has(key))
      return "같은 서비스·프로파일·시나리오를 중복해서 추가할 수 없습니다.";
    keys.add(key);
  }
  return "";
}

// Changed observations are a subset of persisting observations in the API.
// Keep both summary counts intact while showing each observation once in a table.
export function unchangedObservations<
  T extends { service_id: string; fingerprint: string },
>(persisting: T[], changed: { after: T }[]): T[] {
  const keys = new Set(
    changed.map((item) =>
      JSON.stringify([item.after.service_id, item.after.fingerprint]),
    ),
  );
  return persisting.filter(
    (item) => !keys.has(JSON.stringify([item.service_id, item.fingerprint])),
  );
}
