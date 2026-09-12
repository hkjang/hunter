import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import {
  ActionIcon,
  Badge,
  Button,
  Checkbox,
  Group,
  Popover,
  SegmentedControl,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import {
  IconAdjustmentsHorizontal,
  IconBookmark,
  IconCheck,
  IconTrash,
  IconX,
  IconDownload,
  IconLink,
} from "@tabler/icons-react";
import { useLocation, useSearchParams } from "react-router-dom";
import { label, useSession, success, showError } from "./api";
import { copyText, downloadCSV, listSharePath } from "./list-export";
import type { ListView } from "./use-list-view";
import {
  applySavedListQuery,
  listPreferenceKey,
  readListPreferences,
  savedListQuery,
  type ListPreferences,
} from "./saved-list-views";

export function useListPreferences(context?: string) {
  const { user } = useSession();
  const { pathname } = useLocation();
  const key = listPreferenceKey(
    user?.id || "",
    pathname + (context ? `#${context}` : ""),
  );
  function read() {
    try {
      return readListPreferences(localStorage.getItem(key));
    } catch {
      return readListPreferences(null);
    }
  }
  const [stored, setStored] = useState(() => ({ key, value: read() }));
  const [storageError, setStorageError] = useState("");
  const value = stored.key === key ? stored.value : read();
  useEffect(() => {
    setStored({ key, value: read() });
    setStorageError("");
    const synchronize = (event: StorageEvent) => {
      if (event.key === key || event.key === null)
        setStored({ key, value: read() });
    };
    window.addEventListener("storage", synchronize);
    return () => window.removeEventListener("storage", synchronize);
  }, [key]);
  function update(next: ListPreferences) {
    setStored({ key, value: next });
    try {
      localStorage.setItem(key, JSON.stringify(next));
      setStorageError("");
    } catch {
      setStorageError(
        "브라우저 저장소를 사용할 수 없어 이번 화면에서만 적용됩니다.",
      );
    }
  }
  return { preferences: value, setPreferences: update, storageError };
}

type FilterLabel = { label: string; value?: (value: string) => string };
export function ListTools<T>({
  view,
  filterLabels = {},
  loading = false,
  failed = false,
}: {
  view: ListView<T>;
  filterLabels?: Record<string, FilterLabel>;
  loading?: boolean;
  failed?: boolean;
}) {
  const [params, setParams] = useSearchParams();
  const location = useLocation();
  const [opened, setOpened] = useState(false),
    [name, setName] = useState(""),
    [error, setError] = useState(""),
    [message, setMessage] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const prefs = view.preferences;
  const snapshot = savedListQuery(
    params,
    view.columns.map((column) => column.key),
    Object.keys(view.filters),
  );
  const selected = prefs.views.find((item) => item.query === snapshot);
  const filterChips = Object.entries(view.filters)
    .filter(([, value]) => value)
    .map(([key, value]) => ({
      key,
      text: `${filterLabels[key]?.label || view.columns.find((column) => column.key === key)?.label || key}: ${filterLabels[key]?.value?.(value) || label(value)}`,
    }));
  const summary = view.query || filterChips.length;
  function removeCondition(button: HTMLButtonElement, remove: () => void) {
    const chips = Array.from(
      button.parentElement?.querySelectorAll<HTMLButtonElement>("button") || [],
    );
    const index = chips.indexOf(button);
    const target =
      chips[index + 1] ||
      chips[index - 1] ||
      button
        .closest(".data-panel")
        ?.querySelector<HTMLInputElement>(".list-search input");
    // Move focus before removing its element, so keyboard users stay in the
    // filter controls instead of restarting at the beginning of the document.
    target?.focus({ preventScroll: true });
    remove();
  }
  function save(event: React.FormEvent) {
    event.preventDefault();
    const title = name.trim();
    if (!title) {
      setError("보기 이름을 입력해 주세요.");
      input.current?.focus();
      return;
    }
    if (prefs.views.length >= 8) {
      setError(
        "보기를 최대 8개까지 저장할 수 있습니다. 사용하지 않는 보기를 삭제해 주세요.",
      );
      return;
    }
    if (prefs.views.some((item) => item.name === title)) {
      setError("같은 이름의 보기가 있습니다. 다른 이름을 입력해 주세요.");
      input.current?.focus();
      return;
    }
    if (
      (params.get("q") || "").length > 500 ||
      Object.values(view.filters).some((value) => value.length > 500)
    ) {
      setError("검색어나 필터 값이 너무 깁니다. 500자 이하로 줄여 주세요.");
      return;
    }
    view.setPreferences({
      ...prefs,
      views: [
        ...prefs.views,
        {
          id: `view-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
          name: title,
          query: snapshot,
        },
      ],
    });
    setName("");
    setError("");
    setMessage(`‘${title}’ 보기를 저장했습니다.`);
  }
  return (
    <div className="list-tools">
      <div className="list-tools-row">
        <div
          className="list-result-summary"
          role="status"
          aria-live="polite"
          aria-atomic="true"
        >
          {failed ? (
            "목록을 불러오지 못했습니다"
          ) : loading ? (
            "목록을 불러오는 중"
          ) : (
            <>
              <strong>
                {view.filteredRows.length.toLocaleString()}개 결과
              </strong>
              <span> / 조회 {view.total.toLocaleString()}개</span>
            </>
          )}
          {selected && (
            <Badge variant="light" color="teal">
              {selected.name}
            </Badge>
          )}
        </div>
        <Group gap="xs" className="list-view-actions">
          <Button
            variant="default"
            leftSection={<IconDownload size={17} />}
            disabled={loading || failed || !view.filteredRows.length}
            title={`현재 조회 자료 중 검색·정렬을 적용한 ${view.filteredRows.length.toLocaleString()}개 결과를 내보냅니다.`}
            onClick={() => {
              downloadCSV(view.filteredRows, view.columns, "검색결과");
              success(
                `${view.filteredRows.length.toLocaleString()}개 검색 결과를 CSV로 내보냈습니다.`,
              );
            }}
          >
            CSV 내보내기
          </Button>
          <Button
            variant="default"
            leftSection={<IconLink size={17} />}
            onClick={async () => {
              try {
                const path = listSharePath(
                  location.pathname,
                  params,
                  view.columns.map((column) => column.key),
                  Object.keys(view.filters),
                  view.page,
                );
                await copyText(new URL(path, window.location.origin).href);
                success(
                  "목록 주소를 복사했습니다. 받는 사람의 접근 권한에 따라 결과가 표시됩니다.",
                );
              } catch (error) {
                showError(error);
              }
            }}
          >
            목록 주소 복사
          </Button>
          <Popover
            opened={opened}
            onChange={setOpened}
            position="bottom-end"
            width={360}
            trapFocus
            returnFocus
            shadow="md"
          >
            <Popover.Target>
              <Button
                variant="default"
                leftSection={<IconBookmark size={17} />}
                onClick={() => {
                  setOpened(!opened);
                  setError("");
                  setMessage("");
                }}
                aria-expanded={opened}
              >
                저장한 보기
              </Button>
            </Popover.Target>
            <Popover.Dropdown className="list-settings-popover">
              <Text fw={600}>목록 보기 저장</Text>
              <Text size="sm" c="dimmed" mt={4}>
                검색·필터·정렬·표시 수를 이 브라우저에 사용자별로 저장합니다.
                불러오면 1페이지부터 표시합니다.
              </Text>
              <Stack gap={6} mt="md" className="saved-list-items">
                {prefs.views.length ? (
                  prefs.views.map((item) => (
                    <Group key={item.id} gap={4} wrap="nowrap">
                      <Button
                        variant={selected?.id === item.id ? "light" : "subtle"}
                        className="saved-list-name"
                        color="teal"
                        leftSection={
                          selected?.id === item.id ? (
                            <IconCheck size={15} />
                          ) : undefined
                        }
                        onClick={() => {
                          setParams(
                            applySavedListQuery(
                              params,
                              item.query,
                              view.columns.map((column) => column.key),
                              Object.keys(view.filters),
                            ),
                            { preventScrollReset: true, state: location.state },
                          );
                          setOpened(false);
                        }}
                      >
                        {item.name}
                      </Button>
                      <ActionIcon
                        variant="subtle"
                        color="gray"
                        aria-label={`${item.name} 보기 삭제`}
                        onClick={() => {
                          input.current?.focus({ preventScroll: true });
                          view.setPreferences({
                            ...prefs,
                            views: prefs.views.filter((v) => v.id !== item.id),
                          });
                          setMessage(`‘${item.name}’ 보기를 삭제했습니다.`);
                        }}
                      >
                        <IconTrash size={17} />
                      </ActionIcon>
                    </Group>
                  ))
                ) : (
                  <Text c="dimmed" size="sm">
                    아직 저장한 보기가 없습니다.
                  </Text>
                )}
              </Stack>
              <form onSubmit={save} className="save-list-form">
                <TextInput
                  ref={input}
                  label="보기 이름"
                  placeholder="예: 운영 서비스의 심각한 발견 건"
                  maxLength={60}
                  value={name}
                  onChange={(event) => {
                    setName(event.currentTarget.value);
                    setError("");
                  }}
                  error={error || undefined}
                />
                <Button type="submit" fullWidth mt="sm">
                  현재 조건 저장 ({prefs.views.length}/8)
                </Button>
              </form>
              {message && (
                <Text size="sm" c="teal" mt="sm" role="status">
                  {message}
                </Text>
              )}
            </Popover.Dropdown>
          </Popover>
          <Popover
            position="bottom-end"
            width={280}
            trapFocus
            returnFocus
            shadow="md"
          >
            <Popover.Target>
              <Button
                variant="default"
                leftSection={<IconAdjustmentsHorizontal size={17} />}
              >
                표 표시 설정
              </Button>
            </Popover.Target>
            <Popover.Dropdown className="list-settings-popover">
              <Text fw={600} mb="sm">
                행 간격
              </Text>
              <SegmentedControl
                fullWidth
                aria-label="행 간격"
                value={prefs.density}
                data={[
                  { value: "comfortable", label: "기본" },
                  { value: "compact", label: "촘촘하게" },
                ]}
                onChange={(density) =>
                  view.setPreferences({
                    ...prefs,
                    density: density as ListPreferences["density"],
                  })
                }
              />
              <Text c="dimmed" size="sm" mt="sm">
                글자 크기는 유지하고 행의 여백만 조절합니다.
              </Text>
              <Checkbox
                label="표 전체 펼치기"
                description="긴 목록을 페이지 스크롤로 확인합니다."
                mt="md"
                checked={prefs.expanded}
                onChange={(event) =>
                  view.setPreferences({
                    ...prefs,
                    expanded: event.currentTarget.checked,
                  })
                }
              />
            </Popover.Dropdown>
          </Popover>
        </Group>
      </div>
      {!!summary && (
        <div className="list-applied" aria-label="적용 중인 검색 조건">
          <span>적용 중</span>
          {view.query && (
            <button
              type="button"
              className="list-filter-chip"
              aria-label={`검색어 ${view.query} 해제`}
              onClick={(event) =>
                removeCondition(event.currentTarget, () => view.setQuery(""))
              }
            >
              <span>검색: {view.query}</span>
              <IconX size={14} aria-hidden="true" />
            </button>
          )}
          {filterChips.map((chip) => (
            <button
              type="button"
              key={chip.key}
              className="list-filter-chip"
              aria-label={`${chip.text} 해제`}
              onClick={(event) =>
                removeCondition(event.currentTarget, () =>
                  view.setFilter(chip.key, ""),
                )
              }
            >
              <span>{chip.text}</span>
              <IconX size={14} aria-hidden="true" />
            </button>
          ))}
        </div>
      )}
      {view.storageError && (
        <Text size="sm" c="orange" role="status" mt="sm">
          {view.storageError}
        </Text>
      )}
    </div>
  );
}

export function TableViewport<T>({
  view,
  label: caption,
  minWidth = 760,
  children,
}: {
  view: ListView<T>;
  label: string;
  minWidth?: number;
  children: ReactNode;
}) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const [scrollable, setScrollable] = useState(false);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const measure = () => {
      setScrollable(
        node.scrollHeight > node.clientHeight + 1 ||
          node.scrollWidth > node.clientWidth + 1,
      );
      const first = node.querySelector<HTMLElement>("thead th");
      node.style.setProperty(
        "--first-column-width",
        `${first?.getBoundingClientRect().width || 0}px`,
      );
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    if (node.firstElementChild) observer.observe(node.firstElementChild);
    return () => observer.disconnect();
  }, [view.rows, view.preferences.expanded, view.preferences.density]);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = 0;
  }, [
    view.page,
    view.pageSize,
    view.query,
    view.sort?.key,
    view.sort?.direction,
    JSON.stringify(view.filters),
  ]);
  return (
    <>
      <div id={id} className="table-scroll-help">
        {view.preferences.expanded
          ? "표 전체를 펼쳤습니다. 넓은 표는 좌우로 스크롤해 확인하세요."
          : scrollable
            ? "표 안에서 스크롤해 더 확인하세요. 열 제목은 고정됩니다."
            : "열 제목을 눌러 정렬할 수 있습니다."}
      </div>
      <div
        ref={ref}
        role="region"
        aria-label={`${caption} 표`}
        aria-describedby={id}
        tabIndex={scrollable ? 0 : undefined}
        className={`hunter-table-viewport density-${view.preferences.density}${view.preferences.expanded ? " is-expanded" : ""}`}
      >
        <div style={{ minWidth }}>{children}</div>
      </div>
    </>
  );
}
