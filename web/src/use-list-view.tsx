import { useRef, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ActionIcon,
  Button,
  Group,
  NumberInput,
  Pagination,
  Select,
  Table,
  Text,
  TextInput,
} from "@mantine/core";
import {
  IconArrowDown,
  IconArrowUp,
  IconArrowsSort,
  IconRefresh,
  IconSearch,
  IconX,
} from "@tabler/icons-react";
import { label } from "./api";
import {
  matchesSearch,
  pageSizes,
  paginateRows,
  patchListParams,
  readListState,
  sortRows,
  type ListColumn,
  type ListSort,
} from "./list-view";
import "./list-view.css";
import { useListPreferences } from "./list-tools";

export function useListView<T>({
  rows,
  columns,
  searchValues,
  defaultSort = null,
  filters = {},
}: {
  rows: T[];
  columns: ListColumn<T>[];
  searchValues?: (row: T) => unknown[];
  defaultSort?: ListSort | null;
  filters?: Record<string, (row: T, value: string) => boolean>;
}) {
  const [params, setParams] = useSearchParams();
  const presentation = useListPreferences();
  // Keep consecutive changes in the same event (clear/search/filter) atomic;
  // useSearchParams callbacks do not queue updates like React state setters.
  const latest = useRef(params);
  latest.current = params;
  const state = readListState(
    params,
    columns.map((c) => c.key),
    Object.keys(filters),
    defaultSort,
  );
  function update(
    changes: Record<string, string | null>,
    resetPage = false,
    replace = false,
  ) {
    const next = patchListParams(latest.current, changes, resetPage);
    latest.current = next;
    setParams(next, { replace, preventScrollReset: true });
  }
  const matched = rows.filter((row) => {
    if (
      !Object.entries(filters).every(
        ([key, predicate]) =>
          !state.filters[key] || predicate(row, state.filters[key]),
      )
    )
      return false;
    const values = [
      ...columns.map((column) => column.value(row)),
      ...(searchValues?.(row) || []),
    ];
    const translated = values
      .flatMap((value) => (Array.isArray(value) ? value : [value]))
      .filter((value) => typeof value === "string")
      .map((value) => label(value));
    return matchesSearch([...values, ...translated], state.query);
  });
  const filteredRows = sortRows(matched, columns, state.sort);
  const paged = paginateRows(filteredRows, state.page, state.pageSize);
  return {
    ...presentation,
    columns,
    ...state,
    ...paged,
    filteredRows,
    total: rows.length,
    active:
      !!state.query ||
      Object.values(state.filters).some(Boolean) ||
      params.has("sort") ||
      params.has("page") ||
      params.has("size"),
    setQuery: (value: string) => update({ q: value }, true, true),
    setFilter: (key: string, value: string | null) => {
      if (Object.hasOwn(filters, key)) update({ [`f_${key}`]: value }, true);
    },
    setSort: (key: string) => {
      if (columns.some((column) => column.key === key))
        update(
          {
            sort: key,
            dir:
              state.sort?.key === key && state.sort.direction === "asc"
                ? "desc"
                : "asc",
          },
          true,
        );
    },
    setPage: (value: number) => {
      const page = Math.max(
        1,
        Math.min(Math.trunc(value) || 1, paged.pageCount),
      );
      update({ page: page === 1 ? null : String(page) });
    },
    setPageSize: (value: number) => {
      if (pageSizes.includes(value))
        update({ size: value === 25 ? null : String(value) }, true);
    },
    reset: () =>
      update(
        Object.fromEntries(
          [
            "q",
            "sort",
            "dir",
            "page",
            "size",
            ...Object.keys(filters).map((key) => `f_${key}`),
          ].map((key) => [key, null]),
        ),
      ),
  };
}

export type ListView<T = unknown> = ReturnType<typeof useListView<T>>;

export function ListSearch<T>({
  view,
  label: caption,
  placeholder,
}: {
  view: ListView<T>;
  label: string;
  placeholder?: string;
}) {
  return (
    <TextInput
      className="list-search"
      aria-label={caption}
      placeholder={placeholder || caption}
      value={view.query}
      onChange={(event) => view.setQuery(event.currentTarget.value)}
      leftSection={<IconSearch size={18} />}
      size="md"
      rightSection={
        view.query ? (
          <ActionIcon
            variant="subtle"
            color="gray"
            aria-label={`${caption} 지우기`}
            onClick={(event) => {
              event.currentTarget
                .closest(".list-search")
                ?.querySelector("input")
                ?.focus({ preventScroll: true });
              view.setQuery("");
            }}
          >
            <IconX size={16} />
          </ActionIcon>
        ) : undefined
      }
    />
  );
}

export function SortHeader<T>({
  view,
  column,
  children,
}: {
  view: ListView<T>;
  column: string;
  children: ReactNode;
}) {
  const direction = view.sort?.key === column ? view.sort.direction : null;
  const Icon =
    direction === "asc"
      ? IconArrowUp
      : direction === "desc"
        ? IconArrowDown
        : IconArrowsSort;
  return (
    <Table.Th
      scope="col"
      aria-sort={
        direction === "asc"
          ? "ascending"
          : direction === "desc"
            ? "descending"
            : "none"
      }
    >
      <button
        type="button"
        className={`list-sort ${direction ? "is-sorted" : ""}`}
        onClick={() => view.setSort(column)}
        title={`${typeof children === "string" ? children : "이 열"}: ${direction === "asc" ? "내림차순" : "오름차순"} 정렬`}
      >
        <span>{children}</span>
        <Icon size={16} aria-hidden="true" />
        <span className="sr-only">
          {direction === "asc" ? "내림차순" : "오름차순"} 정렬
        </span>
      </button>
    </Table.Th>
  );
}

export function ListReset<T>({ view }: { view: ListView<T> }) {
  return view.active ? (
    <Button
      className="list-reset"
      variant="subtle"
      color="gray"
      leftSection={<IconRefresh size={16} />}
      onClick={(event) => {
        event.currentTarget
          .closest(".table-controls, .data-panel")
          ?.querySelector<HTMLInputElement>(".list-search input")
          ?.focus({ preventScroll: true });
        view.reset();
      }}
    >
      조건 초기화
    </Button>
  ) : null;
}

export function ListPagination<T>({
  view,
  totalLabel = "건",
  limit,
}: {
  view: ListView<T>;
  totalLabel?: string;
  limit?: number;
}) {
  const [target, setTarget] = useState<string | number>("");
  const count = view.filteredRows.length;
  return (
    <div className="list-footer">
      <div className="list-footer-summary" role="status" aria-live="polite">
        <Text size="sm">
          <strong>
            {count.toLocaleString()}
            {totalLabel}
          </strong>{" "}
          {count !== view.total && (
            <span>
              / 조회 {view.total.toLocaleString()}
              {totalLabel}{" "}
            </span>
          )}
          · {count ? ((view.page - 1) * view.pageSize + 1).toLocaleString() : 0}
          –{Math.min(view.page * view.pageSize, count).toLocaleString()} 표시
        </Text>
        {limit && view.total >= limit ? (
          <Text size="xs" c="dimmed">
            최근 {limit.toLocaleString()}
            {totalLabel} 내 검색·정렬
          </Text>
        ) : null}
      </div>
      <Group gap="sm" className="list-footer-controls">
        <Select
          aria-label="페이지당 표시 수"
          w={112}
          value={String(view.pageSize)}
          allowDeselect={false}
          data={pageSizes.map((size) => ({
            value: String(size),
            label: `${size}개씩`,
          }))}
          onChange={(value) => view.setPageSize(Number(value))}
          comboboxProps={{ withinPortal: true }}
        />
        {view.pageCount > 1 && (
          <Pagination
            total={view.pageCount}
            value={view.page}
            onChange={view.setPage}
            siblings={0}
            boundaries={1}
            gap={4}
            getItemProps={(page) => ({
              "aria-label": `${page}페이지`,
              "aria-current": page === view.page ? "page" : undefined,
            })}
            getControlProps={(control) => ({
              "aria-label": {
                first: "첫 페이지",
                previous: "이전 페이지",
                next: "다음 페이지",
                last: "마지막 페이지",
              }[control],
            })}
          />
        )}
        {view.pageCount > 5 && (
          <form
            className="list-page-jump"
            onSubmit={(event) => {
              event.preventDefault();
              if (target !== "") view.setPage(Number(target));
              setTarget("");
            }}
          >
            <NumberInput
              aria-label="이동할 페이지"
              placeholder={`1–${view.pageCount}`}
              min={1}
              max={view.pageCount}
              allowDecimal={false}
              allowNegative={false}
              hideControls
              value={target}
              onChange={setTarget}
            />
            <Button type="submit" variant="default" disabled={target === ""}>
              이동
            </Button>
          </form>
        )}
      </Group>
    </div>
  );
}
