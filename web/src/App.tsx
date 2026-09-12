import { useEffect, useRef, useState } from "react";
import { useFocusTrap, useMediaQuery } from "@mantine/hooks";
import {
  Link,
  Navigate,
  NavLink,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  ActionIcon,
  Alert,
  Avatar,
  Badge,
  Button,
  Group,
  Menu,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  UnstyledButton,
} from "@mantine/core";
import {
  IconActivity,
  IconAdjustments,
  IconArrowRight,
  IconBook2,
  IconBell,
  IconChevronDown,
  IconChevronRight,
  IconCircleCheck,
  IconClipboardCheck,
  IconCloudOff,
  IconDashboard,
  IconDatabaseSearch,
  IconFileAnalytics,
  IconGitBranch,
  IconKey,
  IconLayersIntersect,
  IconLink,
  IconListCheck,
  IconLogout,
  IconMenu2,
  IconPlugConnected,
  IconRadar,
  IconSearch,
  IconSettings,
  IconShieldCheck,
  IconShieldLock,
  IconSparkles,
  IconTargetArrow,
  IconTerminal2,
  IconTrophy,
  IconUser,
  IconUsers,
  IconX,
} from "@tabler/icons-react";
import {
  api,
  type Row,
  type User,
  SessionContext,
  useSession,
  label,
  useCan,
} from "./api";
import { LoadState } from "./components";
import { QuickNavigation } from "./quick-navigation";
import { focusMainContent, useRouteFocus } from "./accessibility";
import "./accessibility.css";
import {
  clearLoginReturn,
  readLoginReturn,
  safeReturnPath,
  saveLoginReturn,
} from "./navigation";
import {
  Dashboard,
  GraphPage,
  ReportsPage,
  ContributionsPage,
  CopilotPage,
} from "./pages";
import { NotificationsPage } from "./notifications";
import { AutomationPage } from "./automation";
import { PersonalInboxPage } from "./personal-inbox";
import { ResourcePage } from "./resources";
import { TriagePage } from "./triage";
import { SoftwarePage, SoftwareDetailPage } from "./software";
import { CampaignsPage, CampaignDetailPage } from "./campaigns";
import { IntelligencePage, OperationsPage } from "./operations";
import { AgentsPage, AgentRunPage } from "./agents";
import { agentReadScopes, canReadAgents } from "./agent-permissions";
import {
  SettingsPage,
  ProfilePage,
  KeysPage,
  UsersPage,
  AuditPage,
} from "./settings";
export const navGroups = [
  {
    title: "워크스페이스",
    items: [
      { path: "/dashboard", label: "보안 현황", icon: IconDashboard },
      { path: "/triage", label: "조치함", icon: IconClipboardCheck },
      { path: "/services", label: "서비스 자산", icon: IconLayersIntersect },
      { path: "/software", label: "소프트웨어 구성", icon: IconDatabaseSearch },
      { path: "/findings", label: "발견 건", icon: IconShieldCheck },
      { path: "/remediations", label: "개선 요청", icon: IconLink },
      { path: "/scans", label: "진단 실행", icon: IconRadar },
      { path: "/campaigns", label: "진단 캠페인", icon: IconTargetArrow },
      { path: "/agents", label: "에이전트 진단", icon: IconSparkles },
      { path: "/schedules", label: "진단 예약", icon: IconActivity },
      { path: "/graph", label: "영향 관계도", icon: IconGitBranch },
      { path: "/scenarios", label: "권한 검증", icon: IconListCheck },
      { path: "/reports", label: "보고서", icon: IconFileAnalytics },
      { path: "/contributions", label: "보안 기여", icon: IconTrophy },
      { path: "/copilot", label: "AI 분석 도우미", icon: IconSparkles },
      { path: "/approvals", label: "검토 · 승인", icon: IconClipboardCheck },
    ],
  },
  {
    title: "서비스 관리",
    admin: true,
    items: [
      {
        path: "/admin/integrations",
        label: "연동 관리",
        icon: IconPlugConnected,
      },
      {
        path: "/admin/discovery",
        label: "자산 발견",
        icon: IconDatabaseSearch,
      },
      { path: "/admin/policies", label: "실행 정책", icon: IconShieldLock },
      { path: "/admin/scopes", label: "진단 허용 범위", icon: IconTargetArrow },
      { path: "/admin/auth-profiles", label: "진단 인증", icon: IconKey },
      {
        path: "/admin/workers",
        label: "워커 · 실행 이벤트",
        icon: IconActivity,
      },
      {
        path: "/admin/intelligence",
        label: "위협 정보 반입",
        icon: IconShieldCheck,
      },
      { path: "/admin/notifications", label: "알림센터", icon: IconBell },
      {
        path: "/admin/automation",
        label: "자동화 관리",
        icon: IconAdjustments,
      },
      { path: "/admin/operations", label: "운영 점검", icon: IconActivity },
      { path: "/admin/users", label: "사용자 · 권한", icon: IconUsers },
      { path: "/admin/audit", label: "감사 기록", icon: IconBook2 },
      { path: "/admin/settings", label: "서비스 설정", icon: IconSettings },
    ],
  },
];
const routeScopes: Record<string, string | readonly string[]> = {
  "/triage": ["findings:read", "services:read"],
  "/software": "services:read",
  "/campaigns": ["scans:read", "services:read"],
  "/dashboard": "findings:read",
  "/services": "services:read",
  "/findings": "findings:read",
  "/scans": "scans:read",
  "/agents": "agents:read",
  "/schedules": "scans:read",
  "/scenarios": "services:read",
  "/graph": "services:read",
  "/reports": "findings:read",
  "/contributions": "findings:read",
  "/remediations": "findings:read",
  "/copilot": "ai:use",
  "/approvals": "scans:approve",
  "/admin/integrations": "integrations:manage",
  "/admin/discovery": "integrations:manage",
  "/admin/audit": "audit:read",
  "/admin/notifications": "admin:manage",
  "/admin/automation": "admin:manage",
  "/personal/inbox": "services:read",
};
const personalItems = [
  { path: "/personal/inbox", label: "내 업무 알림", icon: IconBell },
  { path: "/personal/profile", label: "내 프로필", icon: IconUser },
  { path: "/personal/keys", label: "개인 API 키", icon: IconKey },
];
export default function App() {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null),
    [ready, setReady] = useState(false),
    [config, setConfig] = useState<Row>({ version: "1.7.0" });
  const refreshConfig = () =>
    api<Row>("/api/settings/public")
      .then(setConfig)
      .catch(() => {});
  useEffect(() => {
    let active = true;
    async function initialize() {
      // Route availability depends on both authentication and public settings.
      const [auth] = await Promise.allSettled([
        api<{ user: User }>("/api/auth/me"),
        refreshConfig(),
      ]);
      if (!active) return;
      if (auth.status === "fulfilled") {
        setUser(auth.value.user);
        const from = readLoginReturn(true);
        if (from) {
          clearLoginReturn();
          navigate(from, { replace: true });
        }
      }
      setReady(true);
    }
    void initialize();
    const unauth = () => setUser(null);
    window.addEventListener("hunter:unauthorized", unauth);
    return () => {
      active = false;
      window.removeEventListener("hunter:unauthorized", unauth);
    };
  }, []);
  if (!ready)
    return (
      <div className="app-loading">
        <img src="/favicon.svg" width={54} height={54} alt="Hunter" />
        <LoadState loading error="" />
      </div>
    );
  return (
    <SessionContext.Provider value={{ user, setUser, config, refreshConfig }}>
      <Routes>
        <Route
          path="/login"
          element={user ? <AuthenticatedLoginRedirect /> : <Login />}
        />
        <Route path="/*" element={user ? <Shell /> : <LoginRedirect />} />
      </Routes>
    </SessionContext.Provider>
  );
}
function AuthenticatedLoginRedirect() {
  const location = useLocation();
  const { user } = useSession();
  const home = ["/dashboard", "/services", "/findings"].includes(
    user?.preferences?.home_page,
  )
    ? user!.preferences!.home_page
    : "/dashboard";
  const target =
    safeReturnPath(location.state?.from) || readLoginReturn() || home;
  return <Navigate to={target} replace />;
}
function LoginRedirect() {
  const location = useLocation();
  const from = location.pathname + location.search;
  useEffect(() => {
    saveLoginReturn(from);
  }, [from]);
  return <Navigate to="/login" replace state={{ from }} />;
}
function Login() {
  const { setUser, refreshConfig } = useSession();
  const [name, setName] = useState(""),
    [password, setPassword] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [authConfig, setAuthConfig] = useState<Row>({});
  const location = useLocation(),
    navigate = useNavigate();
  useEffect(() => {
    api("/api/auth/config")
      .then(setAuthConfig)
      .catch((e) => setError(e.message));
    const oidcError = new URLSearchParams(location.search).get("error");
    if (oidcError)
      setError(
        "SSO 로그인에 실패했습니다. 인증 설정을 확인하거나 로컬 계정으로 로그인해 주세요.",
      );
  }, [location.search]);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await api<{ user: User }>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: name, password }),
      });
      const profile = await api<Row>("/api/profile").catch(() => ({}) as Row);
      const home = ["/dashboard", "/services", "/findings"].includes(
        profile.preferences?.home_page,
      )
        ? profile.preferences.home_page
        : "/dashboard";
      const from = safeReturnPath(location.state?.from) || readLoginReturn();
      saveLoginReturn(from || home);
      await refreshConfig();
      setUser({ ...result.user, preferences: profile.preferences });
      navigate(from || home, { replace: true });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="login-page">
      <section className="login-story">
        <Link to="/" className="brand">
          <img src="/favicon.svg" alt="" />
          <span>
            hunter<span className="brand-dot">.</span>
          </span>
        </Link>
        <div className="login-story-body">
          <Badge variant="outline" color="lime" radius="xl" size="lg">
            CONTINUOUS SECURITY VALIDATION
          </Badge>
          <h1>
            발견에서 해결까지.
            <br />
            보안의 다음 행동을
            <br />
            <span>명확하게.</span>
          </h1>
          <p>
            흩어진 보안 정보를 하나의 흐름으로.
            <br />
            사내 서비스의 위험을 발견하고, 검증하고,
            <br />
            함께 해결하는 보안 워크스페이스입니다.
          </p>
          <div className="radar-art" aria-hidden="true">
            <div className="radar-ring r1" />
            <div className="radar-ring r2" />
            <div className="radar-ring r3" />
            <div className="radar-line" />
            <div className="radar-center">
              <IconShieldCheck size={44} stroke={1.25} />
            </div>
            <span className="radar-point p1" />
            <span className="radar-point p2" />
            <span className="radar-point p3" />
            <div className="radar-caption">
              <span className="pulse-dot" />
              지속적인 보안 검증
            </div>
          </div>
        </div>
        <div className="login-story-footer">
          <IconCloudOff size={17} /> 폐쇄망을 위한 독립적인 보안 플랫폼
        </div>
      </section>
      <section className="login-panel">
        <div className="login-mobile-brand">
          <img src="/favicon.svg" alt="Hunter" width={40} /> hunter.
        </div>
        <div className="login-form">
          <span className="eyebrow">WELCOME TO HUNTER</span>
          <h2>워크스페이스 로그인</h2>
          <p>계정으로 로그인하고 보안 현황을 확인하세요.</p>
          {error && (
            <Alert color="red" mb="lg" title="로그인 안내">
              {error}
            </Alert>
          )}
          <form onSubmit={submit}>
            <Stack gap="lg">
              <TextInput
                label="사용자 아이디"
                placeholder="아이디를 입력하세요"
                autoComplete="username"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <PasswordInput
                label="비밀번호"
                placeholder="비밀번호를 입력하세요"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <Button
                type="submit"
                fullWidth
                size="lg"
                mt="sm"
                loading={busy}
                rightSection={<IconArrowRight size={19} />}
              >
                로그인
              </Button>
            </Stack>
          </form>
          {authConfig.oidc_enabled && (
            <>
              <div className="login-divider">또는 사내 계정으로 계속</div>
              <Button
                component="a"
                href="/api/auth/oidc/login"
                onClick={() =>
                  saveLoginReturn(
                    safeReturnPath(location.state?.from) || readLoginReturn(),
                    true,
                  )
                }
                variant="default"
                fullWidth
                size="lg"
                leftSection={<IconShieldLock size={20} />}
              >
                Keycloak SSO 로그인
              </Button>
            </>
          )}
          <div className="login-note">
            <IconShieldLock size={18} />
            <span>
              승인된 사용자만 접근할 수 있습니다.
              <br />
              계정 문의는 서비스 관리자에게 연락해 주세요.
            </span>
          </div>
        </div>
        <footer className="login-footer">
          <span>© {new Date().getFullYear()} hunter</span>
          <span>
            서비스 버전 <b>v{authConfig.version || "1.7.0"}</b>
          </span>
        </footer>
      </section>
    </div>
  );
}
function Shell() {
  const { user, setUser, config } = useSession();
  const location = useLocation(),
    navigate = useNavigate();
  const [mobile, setMobile] = useState(false),
    [searchOpen, setSearchOpen] = useState(false);
  const narrow = useMediaQuery("(max-width: 991px)", false, {
    getInitialValueInEffect: false,
  });
  const mobileMenuOpen = narrow && mobile;
  const menuTrigger = useRef<HTMLButtonElement>(null);
  const quickReturnToMenu = useRef<string | null>(null);
  const main = useRef<HTMLElement>(null);
  const sidebarFocusTrap = useFocusTrap(mobileMenuOpen && !searchOpen);
  useRouteFocus(location.pathname, main);
  function closeMobileMenu() {
    setMobile(false);
    requestAnimationFrame(() => menuTrigger.current?.focus());
  }
  function closeQuickNavigation() {
    setSearchOpen(false);
  }
  function afterQuickNavigationClose() {
    if (narrow && quickReturnToMenu.current === location.pathname)
      menuTrigger.current?.focus();
    quickReturnToMenu.current = null;
  }
  const [collapsed, setCollapsed] = useState(false);
  useEffect(() => {
    clearLoginReturn();
  }, []);
  const can = useCan();
  const allowed = (path: string) =>
    (path !== "/approvals" || !!config.approval_enabled) &&
    (path !== "/agents" || canReadAgents(can)) &&
    ((!routeScopes[path] && !path.startsWith("/admin")) ||
      [routeScopes[path] || "admin:manage"]
        .flat()
        .every((scope) => can(scope)));
  const groups = navGroups
    .map((g) => ({ ...g, items: g.items.filter((i) => allowed(i.path)) }))
    .filter((g) => g.items.length > 0);
  const entries = [
    ...groups.flatMap((g) =>
      g.items.map((item) => ({ ...item, group: g.title })),
    ),
    ...personalItems
      .filter((item) => allowed(item.path))
      .map((item) => ({ ...item, group: "개인화" })),
  ];
  const current = entries.find(
    (i) =>
      i.path === location.pathname ||
      location.pathname.startsWith(`${i.path}/`),
  );
  useEffect(() => {
    setMobile(false);
    document.title = `${current?.label || "Hunter"} · hunter`;
    const frame = requestAnimationFrame(() => {
      const nav = document.querySelector<HTMLElement>(".sidebar-nav");
      const active = nav?.querySelector<HTMLElement>(".nav-item.active");
      if (!nav || !active) return;
      const n = nav.getBoundingClientRect(),
        a = active.getBoundingClientRect();
      if (a.bottom > n.bottom) nav.scrollTop += a.bottom - n.bottom + 12;
      else if (a.top < n.top) nav.scrollTop -= n.top - a.top + 12;
    });
    return () => cancelAnimationFrame(frame);
  }, [location.pathname, current?.label]);
  useEffect(() => {
    function key(e: KeyboardEvent) {
      if (
        (e.ctrlKey || e.metaKey) &&
        !e.altKey &&
        e.key.toLowerCase() === "k" &&
        !e.isComposing
      ) {
        e.preventDefault();
        if (searchOpen) closeQuickNavigation();
        else {
          quickReturnToMenu.current = mobileMenuOpen ? location.pathname : null;
          setMobile(false);
          setSearchOpen(true);
        }
      }
    }
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [mobileMenuOpen, searchOpen, location.pathname]);
  async function logout() {
    clearLoginReturn();
    await api("/api/auth/logout", { method: "POST" }).catch(() => {});
    setUser(null);
    navigate("/login");
  }
  return (
    <div className="app-shell">
      <a
        className="skip-to-content"
        href="#main-content"
        inert={mobileMenuOpen || undefined}
        onClick={(event) => {
          event.preventDefault();
          focusMainContent(main.current);
        }}
      >
        본문 바로가기
      </a>
      {mobileMenuOpen && (
        <div
          className="mobile-overlay"
          onClick={closeMobileMenu}
          aria-hidden="true"
        />
      )}
      <aside
        id="workspace-navigation"
        className={`sidebar ${mobileMenuOpen ? "sidebar-open" : ""}`}
        ref={sidebarFocusTrap}
        inert={narrow && !mobileMenuOpen ? true : undefined}
        aria-hidden={narrow && !mobileMenuOpen ? true : undefined}
        role={mobileMenuOpen ? "dialog" : undefined}
        aria-modal={mobileMenuOpen ? true : undefined}
        aria-label={mobileMenuOpen ? "워크스페이스 메뉴" : undefined}
        onKeyDown={(event) => {
          if (
            mobileMenuOpen &&
            event.key === "Escape" &&
            !event.defaultPrevented &&
            !(event.target as HTMLElement).closest('[role="menu"]')
          ) {
            event.preventDefault();
            closeMobileMenu();
          }
        }}
      >
        <div className="sidebar-brand">
          <Link to="/dashboard" className="brand">
            <img src="/favicon.svg" alt="" />
            <span>
              hunter<span className="brand-dot">.</span>
            </span>
          </Link>
          <ActionIcon
            hiddenFrom="md"
            variant="subtle"
            color="gray"
            className="shell-menu-control"
            data-autofocus={mobileMenuOpen || undefined}
            aria-label="메뉴 닫기"
            onClick={closeMobileMenu}
          >
            <IconX size={20} />
          </ActionIcon>
        </div>
        <div className="workspace-tag">
          <div className="workspace-icon">
            <IconShieldCheck size={19} />
          </div>
          <div>
            <strong>{config.service_name || "Hunter 워크스페이스"}</strong>
            <span>지속적인 보안 검증</span>
          </div>
          <Badge variant="light" color="teal" size="xs">
            내부망
          </Badge>
        </div>
        <nav className="sidebar-nav" aria-label="주 메뉴">
          {groups.map((group) => (
            <div className="nav-group" key={group.title}>
              {group.admin ? (
                <button
                  className="nav-group-title"
                  onClick={() => setCollapsed(!collapsed)}
                  aria-expanded={!collapsed}
                >
                  {group.title}
                  <IconChevronDown
                    size={14}
                    style={{
                      transform: collapsed ? "rotate(-90deg)" : undefined,
                    }}
                  />
                </button>
              ) : (
                <div className="nav-group-title">{group.title}</div>
              )}
              {!(group.admin && collapsed) &&
                group.items
                  .filter(
                    (i) => i.path != "/approvals" || config.approval_enabled,
                  )
                  .map((item) => (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      className={({ isActive }) =>
                        `nav-item ${isActive ? "active" : ""}`
                      }
                    >
                      <item.icon size={20} stroke={1.65} />
                      <span>{item.label}</span>
                      {item.path === "/copilot" && (
                        <span className="ai-chip">AI</span>
                      )}
                      {item.path === location.pathname && (
                        <span className="active-dot" />
                      )}
                    </NavLink>
                  ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-status">
            <span className="status-led" />
            오프라인 운영 준비<span>v{config.version || "1.7.0"}</span>
          </div>
          <Menu width={255} position="top-start" shadow="md" offset={12}>
            <Menu.Target>
              <UnstyledButton
                className="profile-trigger"
                aria-label="프로필 및 개인화 메뉴"
              >
                <Avatar color="teal" radius="xl">
                  {(user?.name || user?.username || "H").slice(0, 1)}
                </Avatar>
                <div>
                  <strong>{user?.name || user?.username}</strong>
                  <span>{label(user?.role)}</span>
                </div>
                <IconChevronDown size={17} />
              </UnstyledButton>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Label>개인화</Menu.Label>
              {allowed("/personal/inbox") && (
                <Menu.Item
                  component={Link}
                  to="/personal/inbox"
                  leftSection={<IconBell size={17} />}
                >
                  내 업무 알림
                </Menu.Item>
              )}
              <Menu.Item
                component={Link}
                to="/personal/profile"
                leftSection={<IconUser size={17} />}
              >
                내 프로필
              </Menu.Item>
              <Menu.Item
                component={Link}
                to="/personal/keys"
                leftSection={<IconKey size={17} />}
              >
                개인 API 키 관리
              </Menu.Item>
              <Menu.Divider />
              <Menu.Label>
                hunter · 서비스 버전 v{config.version || "1.7.0"}
              </Menu.Label>
              <Menu.Item
                color="red"
                leftSection={<IconLogout size={17} />}
                onClick={logout}
              >
                로그아웃
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </div>
      </aside>
      <div className="main-shell" inert={mobileMenuOpen || undefined}>
        <header className="topbar">
          <Group gap="sm">
            <ActionIcon
              hiddenFrom="md"
              variant="subtle"
              color="gray"
              ref={menuTrigger}
              className="shell-menu-control"
              aria-label="메뉴 열기"
              aria-expanded={mobileMenuOpen}
              aria-controls="workspace-navigation"
              aria-haspopup="dialog"
              onClick={() => setMobile(true)}
            >
              <IconMenu2 />
            </ActionIcon>
            <span className="topbar-workspace">
              {location.pathname.startsWith("/admin")
                ? "서비스 관리"
                : location.pathname.startsWith("/personal")
                  ? "개인화"
                  : "워크스페이스"}
            </span>
            <IconChevronRight size={15} color="#a8b1b4" />
            <strong>{current?.label || "보안 현황"}</strong>
          </Group>
          <Group gap="md">
            <button
              className="quick-search hunter-navigation-trigger"
              aria-label="빠른 이동 열기"
              aria-haspopup="dialog"
              onClick={() => setSearchOpen(true)}
            >
              <IconSearch size={17} />
              <span>빠른 이동</span>
              <kbd>
                {/Mac|iPhone|iPad/.test(navigator.platform) ? "⌘ K" : "Ctrl K"}
              </kbd>
            </button>
            <div className="topbar-date">
              {new Date().toLocaleDateString("ko-KR", {
                year: "numeric",
                month: "long",
                day: "numeric",
              })}
            </div>
            <Avatar
              size={34}
              color="teal"
              radius="xl"
              className="topbar-avatar"
            >
              {(user?.name || "H")[0]}
            </Avatar>
          </Group>
        </header>
        <main
          className="main-content"
          id="main-content"
          ref={main}
          tabIndex={-1}
          aria-label={`${current?.label || "Hunter"} 본문`}
        >
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route
              path="/triage"
              element={
                <Access required={routeScopes["/triage"]}>
                  <TriagePage />
                </Access>
              }
            />
            <Route
              path="/software"
              element={
                <Access required={routeScopes["/software"]}>
                  <SoftwarePage />
                </Access>
              }
            />
            <Route
              path="/software/:id"
              element={
                <Access required={routeScopes["/software"]}>
                  <SoftwareDetailPage />
                </Access>
              }
            />
            <Route
              path="/campaigns"
              element={
                <Access required={routeScopes["/campaigns"]}>
                  <CampaignsPage />
                </Access>
              }
            />
            <Route
              path="/campaigns/:id"
              element={
                <Access required={routeScopes["/campaigns"]}>
                  <CampaignDetailPage />
                </Access>
              }
            />
            <Route
              path="/admin/intelligence"
              element={
                <Access required="admin:manage">
                  <IntelligencePage />
                </Access>
              }
            />
            <Route
              path="/admin/operations"
              element={
                <Access required="admin:manage">
                  <OperationsPage />
                </Access>
              }
            />
            <Route
              path="/dashboard"
              element={
                <Access required={routeScopes["/dashboard"]}>
                  <Dashboard />
                </Access>
              }
            />
            <Route
              path="/graph"
              element={
                <Access required={routeScopes["/graph"]}>
                  <GraphPage />
                </Access>
              }
            />
            <Route
              path="/reports"
              element={
                <Access required={routeScopes["/reports"]}>
                  <ReportsPage />
                </Access>
              }
            />
            <Route
              path="/contributions"
              element={
                <Access required={routeScopes["/contributions"]}>
                  <ContributionsPage />
                </Access>
              }
            />
            <Route
              path="/copilot"
              element={
                <Access required={routeScopes["/copilot"]}>
                  <CopilotPage />
                </Access>
              }
            />
            <Route
              path="/agents"
              element={
                <Access required={agentReadScopes}>
                  <AgentsPage />
                </Access>
              }
            />
            <Route
              path="/agents/:id"
              element={
                <Access required={agentReadScopes}>
                  <AgentRunPage />
                </Access>
              }
            />
            <Route
              path="/approvals"
              element={
                config.approval_enabled ? (
                  <Access required="scans:approve">
                    <ResourcePage kind="approvals" />
                  </Access>
                ) : (
                  <Navigate to="/dashboard" replace />
                )
              }
            />
            {[
              "services",
              "findings",
              "scans",
              "scenarios",
              "remediations",
              "schedules",
            ].map((p) => (
              <Route
                path={`/${p}`}
                key={p}
                element={
                  <Access required={routeScopes[`/${p}`]}>
                    <ResourcePage key={p} kind={p} />
                  </Access>
                }
              />
            ))}
            {[
              "integrations",
              "discovery",
              "policies",
              "scopes",
              "auth-profiles",
              "workers",
            ].map((p) => (
              <Route
                path={`/admin/${p}`}
                key={p}
                element={
                  <Access
                    required={routeScopes[`/admin/${p}`] || "admin:manage"}
                  >
                    <ResourcePage key={p} kind={p} />
                  </Access>
                }
              />
            ))}
            <Route
              path="/admin/notifications"
              element={
                <Access required="admin:manage">
                  <NotificationsPage />
                </Access>
              }
            />
            <Route
              path="/admin/settings"
              element={
                <Access required="admin:manage">
                  <SettingsPage />
                </Access>
              }
            />
            <Route
              path="/admin/users"
              element={
                <Access required="admin:manage">
                  <UsersPage />
                </Access>
              }
            />
            <Route
              path="/admin/audit"
              element={
                <Access required="audit:read">
                  <AuditPage />
                </Access>
              }
            />
            <Route
              path="/admin/automation"
              element={
                <Access required="admin:manage">
                  <AutomationPage />
                </Access>
              }
            />
            <Route
              path="/personal/inbox"
              element={
                <Access required="services:read">
                  <PersonalInboxPage />
                </Access>
              }
            />
            <Route path="/personal/profile" element={<ProfilePage />} />
            <Route path="/personal/keys" element={<KeysPage />} />
            <Route
              path="*"
              element={
                <Stack align="center" p={60}>
                  <IconSearch size={50} />
                  <h1>페이지를 찾을 수 없습니다</h1>
                  <Text c="dimmed">
                    주소를 확인하거나 보안 현황으로 돌아가세요.
                  </Text>
                  <Button component={Link} to="/dashboard">
                    보안 현황으로
                  </Button>
                </Stack>
              }
            />
          </Routes>
        </main>
        <footer className="app-footer">
          <span>hunter · 지속적인 보안 검증 플랫폼</span>
          <span>
            <IconCircleCheck size={14} /> 사내 환경을 위한 안전한 연결
          </span>
        </footer>
      </div>
      <QuickNavigation
        key={user?.id}
        opened={searchOpen}
        onClose={closeQuickNavigation}
        onExitTransitionEnd={afterQuickNavigationClose}
        onNavigate={navigate}
        entries={entries}
        userId={user?.id || ""}
        currentPath={current?.path}
      />
    </div>
  );
}
function Access({
  children,
  required,
}: {
  children: React.ReactNode;
  required: string | readonly string[];
}) {
  const can = useCan();
  return (
    Array.isArray(required) ? required.every(can) : can(required as string)
  ) ? (
    children
  ) : (
    <Alert color="orange" title="접근 권한이 필요합니다">
      이 페이지에 접근할 권한이 없습니다. 서비스 관리자에게 역할 권한을
      문의하세요.
      {Array.isArray(required) && (
        <Text size="sm" mt="sm">
          에이전트 기록에는 서비스·발견 건·진단 결과가 포함됩니다. 에이전트,
          서비스, 발견 건, 진단 조회 권한이 모두 필요합니다.
        </Text>
      )}
    </Alert>
  );
}
