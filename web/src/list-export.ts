import type { ListColumn } from "./list-view";
import { savedListQuery } from "./saved-list-views.ts";

function displayText(value: unknown): string {
  if (Array.isArray(value))
    return value.map(displayText).filter(Boolean).join(" · ");
  return ["string", "number", "boolean"].includes(typeof value)
    ? String(value)
    : "";
}

export function csvCell(value: unknown): string {
  let text = displayText(value);
  // Spreadsheet applications may execute formulas even in quoted CSV fields.
  if (/^[\s\u0000-\u001f]*[=+\-@]/u.test(text) || /^[\t\r\n]/u.test(text))
    text = "'" + text;
  return '"' + text.replaceAll('"', '""') + '"';
}

export function listCSV<T>(
  rows: readonly T[],
  columns: ListColumn<T>[],
): string {
  return (
    "\uFEFF" +
    [
      columns.map((column) => csvCell(column.label)).join(","),
      ...rows.map((row) =>
        columns
          .map((column) => {
            const value = column.exportValue
              ? column.exportValue(row)
              : column.value(row);
            const text =
              !column.exportValue &&
              /(_at|_date)$/.test(column.key) &&
              typeof value === "number" &&
              Number.isFinite(value)
                ? new Date(value).toISOString()
                : value;
            return csvCell(text);
          })
          .join(","),
      ),
    ].join("\r\n") +
    "\r\n"
  );
}

export function downloadCSV<T>(
  rows: readonly T[],
  columns: ListColumn<T>[],
  name = "목록",
) {
  const blob = new Blob([listCSV(rows, columns)], {
    type: "text/csv;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `hunter-${name.replace(/[^\p{L}\p{N}_-]/gu, "-").slice(0, 70)}-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function listSharePath(
  pathname: string,
  params: URLSearchParams,
  columns: string[],
  filters: string[],
  page: number,
) {
  // A copied address must open the list the sender is looking at, so the search
  // and filter text keeps its full length instead of the saved-view limit.
  const query = new URLSearchParams(
    savedListQuery(params, columns, filters, { clip: false }),
  );
  if (Number.isSafeInteger(page) && page > 1) query.set("page", String(page));
  // Tab names are product navigation, never arbitrary parameters or form data.
  const tab = params.get("tab");
  if (
    tab &&
    [
      "components",
      "documents",
      "dependencies",
      "compare",
      "runs",
      "overview",
      "events",
      "tools",
      "memory",
      "findings",
    ].includes(tab)
  )
    query.set("tab", tab);
  const baseline = params.get("baseline");
  if (
    tab === "compare" &&
    /^\/(software|campaigns)\/[0-9a-f-]{36}$/i.test(pathname) &&
    baseline &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      baseline,
    )
  )
    query.set("baseline", baseline);
  return pathname + (query.size ? `?${query}` : "");
}

export async function copyText(text: string): Promise<void> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
  } catch {
    /* Use the selected-text fallback on internal HTTP sites. */
  }
  const active =
    document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
  const selection = window.getSelection();
  const ranges = selection
    ? Array.from({ length: selection.rangeCount }, (_, i) =>
        selection.getRangeAt(i).cloneRange(),
      )
    : [];
  const field = document.createElement("textarea");
  field.value = text;
  field.readOnly = true;
  field.style.cssText =
    "position:fixed;left:0;top:0;width:1px;height:1px;opacity:0;pointer-events:none";
  // Stay inside a modal's focus trap when its action requested the copy.
  (active?.closest('[role="dialog"]') || document.body).append(field);
  try {
    field.select();
    if (!document.execCommand("copy"))
      throw new Error(
        "복사하지 못했습니다. 브라우저의 클립보드 권한을 확인해 주세요.",
      );
  } finally {
    field.remove();
    active?.focus({ preventScroll: true });
    selection?.removeAllRanges();
    for (const range of ranges) selection?.addRange(range);
  }
}
