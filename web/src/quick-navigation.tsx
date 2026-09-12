import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ComponentType,
} from "react";
import { ActionIcon, Button, Group, Modal, TextInput } from "@mantine/core";
import {
  IconArrowDown,
  IconArrowUp,
  IconArrowRight,
  IconCornerDownLeft,
  IconSearch,
  IconStar,
  IconStarFilled,
  IconX,
} from "@tabler/icons-react";
import {
  navigationStorageKey,
  parseNavigationHistory,
  recordMenuVisit,
  searchNavigation,
  toggleMenuFavorite,
  visibleSavedMenus,
  type NavigationEntry,
  type NavigationHistory,
} from "./navigation";
import "./navigation.css";
export type QuickNavigationEntry = NavigationEntry & {
  icon: ComponentType<{ size?: number; stroke?: number }>;
};
export function QuickNavigation({
  opened,
  onClose,
  onNavigate,
  entries,
  userId,
  currentPath,
}: {
  opened: boolean;
  onClose: () => void;
  onNavigate: (path: string) => void;
  entries: QuickNavigationEntry[];
  userId: string;
  currentPath?: string;
}) {
  const storageKey = navigationStorageKey(userId);
  const [history, setHistory] = useState<NavigationHistory>(() => {
    try {
      return parseNavigationHistory(localStorage.getItem(storageKey));
    } catch {
      return parseNavigationHistory(null);
    }
  });
  const [query, setQuery] = useState(""),
    [active, setActive] = useState(0),
    [storageAvailable, setStorageAvailable] = useState(true);
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  useEffect(() => {
    try {
      setHistory(parseNavigationHistory(localStorage.getItem(storageKey)));
      setStorageAvailable(true);
    } catch {
      setHistory(parseNavigationHistory(null));
      setStorageAvailable(false);
    }
  }, [storageKey]);
  useEffect(() => {
    if (currentPath)
      setHistory((previous) => recordMenuVisit(previous, currentPath));
  }, [currentPath]);
  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(history));
    } catch {
      setStorageAvailable(false);
    }
  }, [history, storageKey]);
  useEffect(() => {
    if (opened) {
      setQuery("");
      setActive(0);
      requestAnimationFrame(() => input.current?.focus());
    }
  }, [opened]);
  const sections = useMemo(() => {
    if (query.trim())
      return [{ title: "검색 결과", items: searchNavigation(entries, query) }];
    const favorites = visibleSavedMenus(entries, history.favorites);
    const recent = visibleSavedMenus(entries, history.recent).filter(
      (entry) => !history.favorites.includes(entry.path),
    );
    const saved = new Set([...favorites, ...recent].map((entry) => entry.path));
    const rest = entries.filter((entry) => !saved.has(entry.path));
    return [
      { title: "즐겨찾기", items: favorites },
      { title: "최근 방문", items: recent },
      ...Array.from(new Set(rest.map((entry) => entry.group || "메뉴"))).map(
        (group) => ({
          title: group,
          items: rest.filter((entry) => (entry.group || "메뉴") === group),
        }),
      ),
    ].filter((section) => section.items.length);
  }, [entries, query, history]);
  const results = sections.flatMap((section) => section.items);
  const selected = Math.min(active, Math.max(0, results.length - 1));
  useEffect(() => {
    if (opened)
      document
        .getElementById(`${listId}-${selected}`)
        ?.scrollIntoView({ block: "nearest" });
  }, [selected, opened, listId]);
  function move(path: string) {
    if (!entries.some((entry) => entry.path === path)) return;
    setHistory((previous) => recordMenuVisit(previous, path));
    onClose();
    onNavigate(path);
  }
  function toggle(path: string) {
    setHistory((previous) => toggleMenuFavorite(previous, path));
  }
  function key(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.nativeEvent.isComposing) return;
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (results.length)
        setActive(
          (selected + (event.key === "ArrowDown" ? 1 : -1) + results.length) %
            results.length,
        );
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (results[selected]) move(results[selected].path);
    } else if (event.key === "Escape") {
      event.preventDefault();
      onClose();
    }
  }
  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="빠른 이동"
      size="lg"
      className="hunter-quick-navigation"
      closeButtonProps={{ "aria-label": "빠른 이동 닫기" }}
    >
      <div className="navigation-search">
        <TextInput
          ref={input}
          data-autofocus
          aria-label="메뉴 검색"
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={opened}
          aria-controls={listId}
          aria-activedescendant={
            results.length ? `${listId}-${selected}` : undefined
          }
          aria-describedby={`${listId}-help`}
          value={query}
          onChange={(event) => {
            setQuery(event.currentTarget.value);
            setActive(0);
          }}
          onKeyDown={key}
          placeholder="메뉴 이름, 영어 별칭 또는 초성 검색"
          leftSection={<IconSearch size={20} />}
          rightSection={
            query ? (
              <ActionIcon
                variant="subtle"
                aria-label="검색어 지우기"
                onClick={() => {
                  setQuery("");
                  setActive(0);
                  input.current?.focus();
                }}
              >
                <IconX size={17} />
              </ActionIcon>
            ) : undefined
          }
        />
        <p id={`${listId}-help`}>
          예: 서비스, scan, ㅂㅇㅎㅎ ·{" "}
          <span>별표로 자주 쓰는 메뉴를 저장하세요.</span>
        </p>
      </div>
      <div
        className="navigation-results"
        id={listId}
        role="listbox"
        aria-label="이동할 메뉴"
        aria-busy="false"
      >
        {results.length ? (
          sections.map((section) => (
            <div role="group" aria-label={section.title} key={section.title}>
              <div className="navigation-section-title">{section.title}</div>
              {section.items.map((entry) => {
                const index = results.indexOf(entry);
                const favorite = history.favorites.includes(entry.path);
                return (
                  <div
                    className={`navigation-option-row ${selected === index ? "selected" : ""}`}
                    key={entry.path}
                  >
                    <button
                      id={`${listId}-${index}`}
                      role="option"
                      aria-selected={selected === index}
                      tabIndex={-1}
                      className="navigation-option"
                      onMouseMove={() => setActive(index)}
                      onClick={() => move(entry.path)}
                    >
                      <span className="navigation-item-icon">
                        <entry.icon size={20} stroke={1.7} />
                      </span>
                      <span className="navigation-item-copy">
                        <strong>{entry.label}</strong>
                        <small>
                          {entry.group || "메뉴"}
                          {entry.path === currentPath ? " · 현재 메뉴" : ""}
                        </small>
                      </span>
                      <IconArrowRight
                        className="navigation-open-icon"
                        size={17}
                      />
                    </button>
                    <ActionIcon
                      className="navigation-favorite"
                      variant="subtle"
                      color={favorite ? "yellow" : "gray"}
                      aria-label={`${entry.label} 즐겨찾기 ${favorite ? "해제" : "추가"}`}
                      aria-pressed={favorite}
                      onClick={() => toggle(entry.path)}
                    >
                      {favorite ? (
                        <IconStarFilled size={18} />
                      ) : (
                        <IconStar size={18} />
                      )}
                    </ActionIcon>
                  </div>
                );
              })}
            </div>
          ))
        ) : (
          <div className="navigation-empty">
            <IconSearch size={30} />
            <strong>일치하는 메뉴가 없습니다</strong>
            <p>
              다른 이름이나 영어 별칭으로 검색해 보세요.
              <br />
              현재 권한으로 사용할 수 있는 메뉴만 표시합니다.
            </p>
            <Button
              variant="light"
              onClick={() => {
                setQuery("");
                input.current?.focus();
              }}
            >
              전체 메뉴 보기
            </Button>
          </div>
        )}
      </div>
      <div className="navigation-footer">
        <Group gap="sm">
          <span>
            <kbd>
              <IconArrowUp size={12} />
              <IconArrowDown size={12} />
            </kbd>{" "}
            선택
          </span>
          <span>
            <kbd>
              <IconCornerDownLeft size={12} />
            </kbd>{" "}
            이동
          </span>
          <span>
            <kbd>Esc</kbd> 닫기
          </span>
        </Group>
        <span role="status" aria-live="polite">
          {query
            ? `${results.length}개 메뉴`
            : storageAvailable
              ? "이 브라우저에 사용자별 저장"
              : "현재 창에서만 저장됩니다"}
        </span>
      </div>
    </Modal>
  );
}
