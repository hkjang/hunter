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
          item.query.length > 8192
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

// Saved views may only change list controls, never navigation, selected records,
// approval actions, secret values in arbitrary query params, or authorization.
export function savedListQuery(
  params: URLSearchParams,
  columns: string[],
  filters: string[],
) {
  const next = new URLSearchParams();
  const query = params.get("q");
  if (query) next.set("q", query.slice(0, 500));
  const sort = params.get("sort");
  if (sort && columns.includes(sort)) {
    next.set("sort", sort);
    next.set("dir", params.get("dir") === "desc" ? "desc" : "asc");
  }
  const size = params.get("size");
  if (size && ["10", "50", "100"].includes(size)) next.set("size", size);
  for (const key of [...filters].sort()) {
    const value = params.get(`f_${key}`);
    if (value) next.set(`f_${key}`, value.slice(0, 500));
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
