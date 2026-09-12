export type SortDirection = "asc" | "desc";
export type ListSort = { key: string; direction: SortDirection };
export type ListColumn<T> = {
  key: string;
  label: string;
  value: (row: T) => unknown;
  exportValue?: (row: T) => unknown;
  compare?: (a: T, b: T) => number;
};

const collator = new Intl.Collator("ko-KR", {
  numeric: true,
  sensitivity: "base",
});
export const pageSizes = [10, 25, 50, 100];

export function normalizeSearch(value: string) {
  return value.normalize("NFKC").toLocaleLowerCase("ko-KR").trim();
}

// Search explicit display fields only. Hidden credentials and arbitrary object
// payloads are intentionally not serialized into the search index.
export function searchText(value: unknown): string {
  if (Array.isArray(value)) return value.map(searchText).join(" ");
  if (["string", "number", "boolean"].includes(typeof value))
    return String(value);
  return "";
}

export function matchesSearch(values: unknown[], query: string): boolean {
  const haystack = normalizeSearch(values.map(searchText).join(" "));
  return normalizeSearch(query)
    .split(/\s+/u)
    .filter(Boolean)
    .every((word) => haystack.includes(word));
}

export function sortRows<T>(
  rows: readonly T[],
  columns: ListColumn<T>[],
  sort: ListSort | null,
): T[] {
  const column = columns.find((c) => c.key === sort?.key);
  if (!column || !sort) return [...rows];
  const direction = sort.direction === "asc" ? 1 : -1;
  return rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => {
      const av = column.value(a.row),
        bv = column.value(b.row);
      const emptyA =
        av == null ||
        av === "" ||
        (typeof av === "number" && !Number.isFinite(av));
      const emptyB =
        bv == null ||
        bv === "" ||
        (typeof bv === "number" && !Number.isFinite(bv));
      if (emptyA !== emptyB) return emptyA ? 1 : -1;
      if (emptyA && emptyB) return a.index - b.index;
      const result = column.compare
        ? column.compare(a.row, b.row)
        : typeof av === "number" && typeof bv === "number"
          ? av - bv
          : collator.compare(searchText(av), searchText(bv));
      return result * direction || a.index - b.index;
    })
    .map(({ row }) => row);
}

export function readListState(
  params: URLSearchParams,
  columnKeys: string[],
  filterKeys: string[],
  defaultSort: ListSort | null = null,
) {
  const rawSort = params.get("sort");
  const sort =
    rawSort && columnKeys.includes(rawSort)
      ? {
          key: rawSort,
          direction:
            params.get("dir") === "desc" ? ("desc" as const) : ("asc" as const),
        }
      : defaultSort;
  const requestedPage = Number(params.get("page"));
  const requestedSize = Number(params.get("size"));
  return {
    query: params.get("q") || "",
    sort,
    page:
      Number.isSafeInteger(requestedPage) && requestedPage > 0
        ? requestedPage
        : 1,
    pageSize: pageSizes.includes(requestedSize) ? requestedSize : 25,
    filters: Object.fromEntries(
      filterKeys.map((key) => [key, params.get(`f_${key}`) || ""]),
    ),
  };
}

export function paginateRows<T>(
  rows: readonly T[],
  requestedPage: number,
  pageSize: number,
) {
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const page = Math.max(1, Math.min(requestedPage, pageCount));
  return {
    page,
    pageCount,
    rows: rows.slice((page - 1) * pageSize, page * pageSize),
  };
}

export function patchListParams(
  current: URLSearchParams,
  changes: Record<string, string | null>,
  resetPage = false,
) {
  const next = new URLSearchParams(current);
  if (resetPage) next.delete("page");
  for (const [key, value] of Object.entries(changes)) {
    if (value === null || value === "") next.delete(key);
    else next.set(key, value);
  }
  return next;
}
