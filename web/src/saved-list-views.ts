export type SavedListView = { id: string; name: string; query: string };
export type ListPreferences = {
  density: "comfortable" | "compact";
  expanded: boolean;
  views: SavedListView[];
};
export const defaultListPreferences: ListPreferences = {
  density: "comfortable",
  expanded: false,
  views: [],
};

export function listPreferenceKey(userId: string, path: string) {
  return `hunter.lists.v1:${encodeURIComponent(userId)}:${encodeURIComponent(path)}`;
}

// Reading validates one saved view against this many characters and discards
// anything longer, so saving checks the same limit with the same value instead
// of reporting success for a view the next visit throws away. This is the read
// validation limit, not a browser storage limit: storage quota is measured per
// origin over everything stored, never per value.
export const savedListQueryLimit = 8192;

export function savedListQueryTooLong(query: string) {
  return query.length > savedListQueryLimit;
}

export function readListPreferences(raw: string | null): ListPreferences {
  try {
    const value = JSON.parse(raw || "null");
    if (!value || typeof value !== "object")
      return { ...defaultListPreferences, views: [] };
    const ids = new Set<string>();
    const views: SavedListView[] = [];
    if (Array.isArray(value.views))
      for (const item of value.views) {
        if (
          !item ||
          typeof item.id !== "string" ||
          item.id.length > 80 ||
          !item.id ||
          ids.has(item.id) ||
          typeof item.name !== "string" ||
          !item.name.trim() ||
          item.name.length > 60 ||
          typeof item.query !== "string" ||
          savedListQueryTooLong(item.query)
        )
          continue;
        ids.add(item.id);
        views.push({ id: item.id, name: item.name.trim(), query: item.query });
        if (views.length === 8) break;
      }
    return {
      density: value.density === "compact" ? "compact" : "comfortable",
      expanded: value.expanded === true,
      views,
    };
  } catch {
    return { ...defaultListPreferences, views: [] };
  }
}

// Saving refuses every condition reading would reject, so the success message
// never claims a view the next visit cannot restore. The order follows the form:
// the name first, then how many views fit, then how long the conditions are.
// focusName marks the errors the name field can correct, so the caller returns
// focus there instead of leaving it on the submit button.
export function savedViewSaveError(
  prefs: ListPreferences,
  title: string,
  params: URLSearchParams,
  filters: string[],
  snapshot: string,
): { message: string; focusName: boolean } | null {
  if (!title) return { message: "보기 이름을 입력해 주세요.", focusName: true };
  if (prefs.views.length >= 8)
    return {
      message:
        "보기를 최대 8개까지 저장할 수 있습니다. 사용하지 않는 보기를 삭제해 주세요.",
      focusName: false,
    };
  if (prefs.views.some((item) => item.name === title))
    return {
      message: "같은 이름의 보기가 있습니다. 다른 이름을 입력해 주세요.",
      focusName: true,
    };
  if (
    (params.get("q") || "").length > 500 ||
    filters.some((key) => (params.get(`f_${key}`) || "").length > 500)
  )
    return {
      message: "검색어나 필터 값이 너무 깁니다. 500자 이하로 줄여 주세요.",
      focusName: false,
    };
  // Each value stays under 500 characters, but URL encoding expands Korean text,
  // so the whole snapshot can still pass the limit reading validates against.
  if (savedListQueryTooLong(snapshot))
    return {
      message:
        "검색어와 필터가 너무 길어 이 보기를 저장할 수 없습니다. 조건을 줄여 주세요.",
      focusName: false,
    };
  return null;
}

// The limit stays in UTF-16 code units, so only the cut position moves: a boundary
// that falls between a surrogate pair would leave a lone surrogate that URL
// serialization replaces with U+FFFD, changing the restored search text.
function clip(value: string, limit = 500) {
  if (value.length <= limit) return value;
  const lead = value.charCodeAt(limit - 1);
  const trail = value.charCodeAt(limit);
  const split =
    lead >= 0xd800 && lead <= 0xdbff && trail >= 0xdc00 && trail <= 0xdfff;
  return value.slice(0, split ? limit - 1 : limit);
}

// Saved views may only change list controls, never navigation, selected records,
// approval actions, secret values in arbitrary query params, or authorization.
// The length limit belongs to browser storage, so a caller that builds an
// address to share passes clip: false and keeps the text the address bar holds.
export function savedListQuery(
  params: URLSearchParams,
  columns: string[],
  filters: string[],
  options: { clip?: boolean } = {},
) {
  const keep = options.clip === false ? (value: string) => value : clip;
  const next = new URLSearchParams();
  const query = params.get("q");
  if (query) next.set("q", keep(query));
  const sort = params.get("sort");
  if (sort && columns.includes(sort)) {
    next.set("sort", sort);
    next.set("dir", params.get("dir") === "desc" ? "desc" : "asc");
  }
  const size = params.get("size");
  if (size && ["10", "50", "100"].includes(size)) next.set("size", size);
  for (const key of [...filters].sort()) {
    const value = params.get(`f_${key}`);
    if (value) next.set(`f_${key}`, keep(value));
  }
  return next.toString();
}

export function applySavedListQuery(
  current: URLSearchParams,
  query: string,
  columns: string[],
  filters: string[],
) {
  const allowed = new URLSearchParams(
    savedListQuery(new URLSearchParams(query), columns, filters),
  );
  const next = new URLSearchParams(current);
  for (const key of [
    "q",
    "sort",
    "dir",
    "page",
    "size",
    ...filters.map((key) => `f_${key}`),
  ])
    next.delete(key);
  for (const [key, value] of allowed) next.set(key, value);
  return next;
}
