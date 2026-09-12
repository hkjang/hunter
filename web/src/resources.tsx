import { FindingActivity } from "./triage";
import { BulkFindingActions, useFindingSelection } from "./finding-bulk";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams, useLocation } from "react-router-dom";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Checkbox,
  Code,
  Divider,
  Drawer,
  Group,
  JsonInput,
  Menu,
  Modal,
  NumberInput,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  TagsInput,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import {
  IconArrowRight,
  IconCheck,
  IconChevronLeft,
  IconChevronRight,
  IconCode,
  IconCopy,
  IconLink,
  IconDots,
  IconDownload,
  IconEdit,
  IconFileImport,
  IconFilter,
  IconPlayerPlay,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconShieldCheck,
  IconSquare,
  IconTrash,
  IconX,
} from "@tabler/icons-react";
import {
  api,
  APIError,
  colors,
  dateText,
  fullDate,
  label,
  labels,
  type Row,
  showError,
  success,
  useCan,
  useData,
  useSession,
} from "./api";
import { Empty, LoadState, PageHeader, Status } from "./components";
import { ListTools, TableViewport } from "./list-tools";
import {
  FormFeedback,
  SaveStatus,
  useUnsavedChanges,
  type FormIssue,
} from "./form-feedback";
import { changed, requiredIssues, invalidFields } from "./form-state";
import { copyText } from "./list-export";
import {
  changeResourceField,
  withEditRevision,
  resourceDetailPath,
} from "./resource-form-state";
import {
  useListView,
  ListSearch,
  SortHeader,
  ListPagination,
  ListReset,
} from "./use-list-view";
export type Field = {
  key: string;
  label: string;
  type?:
    | "text"
    | "textarea"
    | "number"
    | "select"
    | "tags"
    | "json"
    | "switch"
    | "password"
    | "datetime"
    | "service"
    | "scope"
    | "scenario"
    | "user"
    | "auth"
    | "finding"
    | "integration";
  options?: string[];
  required?: boolean;
  description?: string;
  placeholder?: string;
  default?: any;
  min?: number;
  max?: number;
  admin?: boolean;
};
type Config = {
  title: string;
  description: string;
  singular: string;
  icon?: any;
  fields: Field[];
  columns: string[];
  readOnly?: boolean;
  editOnly?: boolean;
  noDelete?: boolean;
  scope: string;
};
const service: Field = {
  key: "service_id",
  label: "대상 서비스",
  type: "service",
  required: true,
};
const statusOptions = [
  "candidate",
  "confirmed",
  "in_progress",
  "retest",
  "inconclusive",
  "false_positive",
  "accepted",
];
const configs: Record<string, Config> = {
  services: {
    title: "서비스 자산",
    description:
      "사내 서비스와 담당자를 연결하고, 진단할 공격 표면을 관리합니다.",
    singular: "서비스",
    scope: "services:write",
    columns: ["name", "environment", "team", "criticality", "approved"],
    fields: [
      {
        key: "name",
        label: "서비스 이름",
        required: true,
        placeholder: "예: 사내 업무 포털",
      },
      {
        key: "url",
        label: "대표 URL",
        placeholder: "https://service.internal",
      },
      {
        key: "environment",
        label: "환경",
        type: "select",
        options: ["staging", "development", "production"],
        default: "staging",
      },
      { key: "network", label: "망 구분", default: "업무망" },
      { key: "team", label: "담당 조직", required: true },
      { key: "owner", label: "서비스 담당자", required: true },
      {
        key: "owner_id",
        label: "접근 권한 담당자 계정",
        type: "user",
        admin: true,
        description:
          "이 계정은 개인 워크스페이스에서 해당 서비스에 접근할 수 있습니다.",
      },
      {
        key: "criticality",
        label: "업무 중요도",
        type: "select",
        options: ["tier1", "tier2", "tier3", "tier4"],
        default: "tier3",
      },
      {
        key: "repository",
        label: "소스 저장소",
        placeholder: "https://gitlab.internal/group/project",
      },
      {
        key: "image",
        label: "컨테이너 이미지",
        placeholder: "harbor.internal/project/service:v1.0.0",
      },
      { key: "description", label: "서비스 설명", type: "textarea" },
      {
        key: "targets",
        label: "추가 공격 표면",
        type: "json",
        default: [],
        description:
          'type, value 필드의 배열. 예: [{"type":"api","value":"https://service.internal/api"}]',
      },
      {
        key: "approved",
        label: "진단 대상 승인",
        type: "switch",
        default: false,
        admin: true,
        description:
          "승인된 서비스도 별도의 유효한 진단 허용 범위가 있어야 통신할 수 있습니다.",
      },
    ],
  },
  findings: {
    title: "발견 건",
    description:
      "탐지 근거부터 개선, 재검증까지 모든 보안 이슈를 한곳에서 추적합니다.",
    singular: "발견 건",
    scope: "findings:write",
    columns: ["title", "severity", "status", "service_id", "assignee"],
    fields: [
      { key: "title", label: "제목", required: true },
      service,
      {
        key: "severity",
        label: "기술적 심각도",
        type: "select",
        options: ["critical", "high", "medium", "low", "info"],
        default: "medium",
      },
      {
        key: "status",
        label: "처리 상태",
        type: "select",
        options: statusOptions,
        default: "candidate",
      },
      {
        key: "source",
        label: "발견 출처",
        default: "manual",
        description: "직원 신고: manual, 자동 진단: 엔진 이름",
      },
      { key: "assignee", label: "조치 담당자" },
      {
        key: "description",
        label: "발견 내용 · 영향",
        type: "textarea",
        required: true,
      },
      {
        key: "evidence",
        label: "판정 근거 · 재현 절차",
        type: "textarea",
        description: "비밀번호, 토큰, 개인정보 등 민감정보는 포함하지 마세요.",
      },
      { key: "remediation", label: "개선 방법", type: "textarea" },
      { key: "cve", label: "CVE 식별자" },
      { key: "component", label: "영향 구성요소" },
      { key: "due_date", label: "조치 기한", type: "datetime" },
      {
        key: "decision_reason",
        label: "오탐 · 위험 수용 판단 사유",
        type: "textarea",
        description: "위험 수용 시 사유와 만료 일시가 필요합니다.",
      },
      { key: "expires_at", label: "위험 수용 만료 일시", type: "datetime" },
      {
        key: "contribution_points",
        label: "기여 점수",
        type: "number",
        default: 0,
        min: 0,
        admin: true,
        description: "검토한 유효 기여에 한해 관리자가 설정합니다.",
      },
    ],
  },
  scans: {
    title: "진단 실행",
    description:
      "허용된 범위에서 진단을 실행하고, 결과와 실행 이력을 확인합니다.",
    singular: "진단",
    scope: "scans:write",
    columns: ["service_id", "profile", "status", "created_at", "finished_at"],
    noDelete: true,
    fields: [
      service,
      {
        key: "profile",
        label: "진단 프로파일",
        type: "select",
        options: ["http-baseline", "authorization", "import-only"],
        default: "http-baseline",
      },
      {
        key: "scope_id",
        label: "승인된 진단 허용 범위",
        type: "scope",
        description:
          "통신하는 진단에는 승인되고 만료되지 않은 범위가 필요합니다.",
      },
      {
        key: "finding_id",
        label: "재검증할 발견 건 ID (선택)",
        description: "HTTP 보안 헤더 발견 건의 재검증 시 입력합니다.",
      },
      {
        key: "scenario_id",
        label: "업무 권한 검증 시나리오",
        type: "scenario",
        description: "업무 권한 검증 프로파일을 선택한 경우 필수입니다.",
      },
    ],
  },
  policies: {
    title: "실행 정책",
    description:
      "요청량, 허용 메서드, 차단 경로 등 모든 진단의 안전 기준을 정의합니다.",
    singular: "정책",
    scope: "admin:manage",
    columns: ["name", "max_rps", "max_requests", "timeout_seconds", "enabled"],
    fields: [
      { key: "name", label: "정책 이름", required: true },
      { key: "description", label: "설명", type: "textarea" },
      { key: "enabled", label: "정책 활성화", type: "switch", default: true },
      {
        key: "production_active_scan",
        label: "운영 환경 능동 진단 허용",
        type: "switch",
        default: false,
        description:
          "기본 비활성화. 실제 엔진 실행은 서버의 지원 범위와 안전 통제를 따릅니다.",
      },
      {
        key: "max_rps",
        label: "초당 최대 요청 수",
        type: "number",
        default: 1,
        min: 0.1,
        max: 100,
      },
      {
        key: "max_concurrency",
        label: "동시 실행 상한",
        type: "number",
        default: 1,
        min: 1,
        max: 20,
      },
      {
        key: "max_requests",
        label: "최대 요청 수",
        type: "number",
        default: 20,
        min: 1,
        max: 1000,
      },
      {
        key: "timeout_seconds",
        label: "실행 제한 시간 (초)",
        type: "number",
        default: 30,
        min: 1,
        max: 600,
      },
      {
        key: "allowed_methods",
        label: "허용 HTTP 메서드",
        type: "tags",
        default: ["GET", "HEAD"],
      },
      {
        key: "blocked_paths",
        label: "차단 경로 접두사",
        type: "tags",
        default: ["/delete", "/payment", "/logout", "/send"],
        description: "Enter를 눌러 경로를 추가합니다.",
      },
    ],
  },
  schedules: {
    title: "진단 예약",
    description:
      "서비스별 주기적 진단을 예약합니다. 매 실행마다 현재 승인 범위와 정책을 적용합니다.",
    singular: "진단 예약",
    scope: "scans:write",
    columns: [
      "name",
      "service_id",
      "profile",
      "interval_minutes",
      "next_run_at",
      "enabled",
    ],
    fields: [
      { key: "name", label: "예약 이름", required: true },
      service,
      {
        key: "profile",
        label: "진단 프로파일",
        type: "select",
        options: ["http-baseline", "authorization", "import-only"],
        default: "http-baseline",
      },
      { key: "scope_id", label: "진단 허용 범위", type: "scope" },
      { key: "scenario_id", label: "검증 시나리오", type: "scenario" },
      {
        key: "interval_minutes",
        label: "실행 간격 (분)",
        type: "number",
        default: 1440,
        min: 5,
        max: 10080,
        required: true,
      },
      {
        key: "next_run_at",
        label: "첫 실행 일시",
        type: "datetime",
        required: true,
      },
      { key: "enabled", label: "예약 활성화", type: "switch", default: true },
    ],
  },
  scopes: {
    title: "진단 허용 범위",
    description:
      "승인된 호스트, 경로, 유효 기간을 명시하여 진단 대상의 경계를 지킵니다.",
    singular: "허용 범위",
    scope: "admin:manage",
    columns: ["name", "service_id", "allowed_hosts", "expires_at", "approved"],
    fields: [
      { key: "name", label: "범위 이름", required: true },
      service,
      {
        key: "allowed_hosts",
        label: "허용 호스트",
        type: "tags",
        required: true,
        description:
          "호스트와 포트를 정확히 입력합니다. 예: portal.internal:8443 (기본 포트는 호스트명만 입력)",
      },
      {
        key: "allowed_paths",
        label: "허용 경로 접두사",
        type: "tags",
        default: ["/"],
        required: true,
      },
      {
        key: "expires_at",
        label: "승인 만료 일시",
        type: "datetime",
        required: true,
      },
      {
        key: "approved",
        label: "명시적 진단 범위 승인",
        type: "switch",
        default: false,
        description:
          "네트워크 진단은 이 안전 승인이 있어야 실행됩니다. 팀장 승인 설정과 별개입니다.",
      },
      {
        key: "max_rps",
        label: "초당 최대 요청 수",
        type: "number",
        default: 1,
        min: 0.1,
        max: 100,
      },
      {
        key: "max_requests",
        label: "최대 요청 수",
        type: "number",
        default: 20,
        min: 1,
        max: 1000,
      },
      {
        key: "timeout_seconds",
        label: "실행 제한 시간 (초)",
        type: "number",
        default: 30,
        min: 1,
        max: 600,
      },
    ],
  },
  integrations: {
    title: "연동 관리",
    description:
      "API, 데이터베이스, 웹훅과 기존 진단 엔진을 유연하게 연결합니다.",
    singular: "연동",
    scope: "integrations:manage",
    columns: ["name", "type", "endpoint", "enabled", "updated_at"],
    fields: [
      { key: "name", label: "연동 이름", required: true },
      {
        key: "type",
        label: "연동 방식",
        type: "select",
        options: ["rest", "postgres", "webhook", "scanner-import"],
        default: "rest",
      },
      {
        key: "endpoint",
        label: "API 주소 또는 DB 호스트 설명",
        description:
          "DB 연결 시 비밀번호를 포함한 DSN은 아래 비밀정보 필드에 입력하세요.",
        placeholder: "https://itam.internal/api/services",
      },
      {
        key: "secret",
        label: "인증 토큰 · PostgreSQL DSN",
        type: "password",
        description: "암호화하여 저장합니다. 비워 두면 기존 값이 유지됩니다.",
      },
      { key: "enabled", label: "연동 활성화", type: "switch", default: true },
      {
        key: "config",
        label: "연동 세부 설정 (JSON)",
        type: "json",
        default: {},
        description:
          "필드 매핑, 데이터 경로, DB 조회 등 연동별 설정. 아래 도움말을 참고하세요.",
      },
    ],
  },
  discovery: {
    title: "자산 발견",
    description:
      "외부 시스템에서 수집한 신규 자산을 확인하고 서비스 등록 후보를 관리합니다.",
    singular: "자산 후보",
    scope: "integrations:manage",
    columns: ["name", "url", "source", "status", "created_at"],
    fields: [
      { key: "name", label: "자산 이름", required: true },
      { key: "url", label: "발견 URL", required: true },
      { key: "source", label: "발견 출처", default: "manual" },
      { key: "team", label: "담당 조직" },
      {
        key: "status",
        label: "검토 상태",
        type: "select",
        options: ["candidate", "accepted", "rejected"],
        default: "candidate",
      },
      { key: "description", label: "설명", type: "textarea" },
    ],
  },
  "auth-profiles": {
    title: "진단 인증 프로파일",
    description:
      "플랫폼 로그인과 분리된 대상 서비스의 테스트 인증을 암호화해 관리합니다.",
    singular: "인증 프로파일",
    scope: "admin:manage",
    columns: ["name", "service_id", "type", "updated_at"],
    fields: [
      { key: "name", label: "프로파일 이름", required: true },
      service,
      {
        key: "type",
        label: "인증 방식",
        type: "select",
        options: ["bearer", "basic", "headers"],
        default: "bearer",
      },
      { key: "username", label: "Basic 테스트 사용자 이름" },
      {
        key: "token",
        label: "Bearer 토큰",
        type: "password",
        description: "Bearer 방식일 때 입력. 빈 값은 기존 값을 유지합니다.",
      },
      {
        key: "password",
        label: "Basic 비밀번호",
        type: "password",
        description: "Basic 방식일 때 입력. 빈 값은 기존 값을 유지합니다.",
      },
      {
        key: "headers",
        label: "사용자 정의 헤더 (JSON 문자열)",
        type: "password",
        description:
          'headers 방식일 때 {"X-Test-Token":"..."} 형식으로 입력하세요. 암호화하여 저장됩니다.',
      },
    ],
  },
  workers: {
    title: "워커 · 실행 이벤트",
    description:
      "실행 워커의 망 배치와 활성 상태, 변경 기반 진단 이벤트를 관리합니다.",
    singular: "워커",
    scope: "admin:manage",
    editOnly: true,
    noDelete: true,
    columns: ["name", "status", "network", "enabled", "last_seen_at"],
    fields: [
      { key: "name", label: "워커 이름", required: true },
      {
        key: "network",
        label: "담당 망",
        required: true,
        description:
          "서비스의 망 구분과 정확히 일치해야 실행합니다. 예: 업무망. 와일드카드는 지원하지 않습니다.",
      },
      {
        key: "enabled",
        label: "진단 실행 허용",
        type: "switch",
        default: false,
        description: "외부 워커는 최초 등록 후 관리자가 활성화해야 합니다.",
      },
    ],
  },
  scenarios: {
    title: "업무 권한 검증",
    description:
      "정상 접근과 권한 위반 접근을 비교하는 합성 데이터 시나리오를 정의합니다.",
    singular: "시나리오",
    scope: "services:write",
    columns: ["name", "service_id", "description", "updated_at"],
    fields: [
      { key: "name", label: "시나리오 이름", required: true },
      service,
      { key: "description", label: "기대 동작 · 업무 권한", type: "textarea" },
      {
        key: "path",
        label: "검증할 비공개 테스트 자원 경로",
        required: true,
        placeholder: "/api/requests/test-user-a-request",
      },
      {
        key: "marker",
        label: "대상 합성 데이터 식별 문자열",
        required: true,
        description: "정상 사용자 응답에 반드시 포함될 고유 문자열입니다.",
      },
      {
        key: "authorized_profile_id",
        label: "정상 접근 사용자 인증",
        type: "auth",
        required: true,
      },
      {
        key: "unauthorized_profile_id",
        label: "비교 사용자 인증",
        type: "auth",
        required: true,
      },
      {
        key: "unauthorized_control_path",
        label: "비교 사용자 본인 데이터 경로",
        required: true,
        description:
          "비교 사용자의 세션이 정상인지 먼저 확인할 GET 경로입니다.",
      },
      {
        key: "unauthorized_control_marker",
        label: "비교 사용자 본인 데이터 식별 문자열",
        required: true,
        description:
          "인증 실패를 보안 차단 성공으로 오인하지 않도록 정상 응답을 먼저 확인합니다.",
      },
    ],
  },
  remediations: {
    title: "개선 요청",
    description:
      "발견 건의 개선안을 정리하고 사내 ITSM 또는 개발 플랫폼으로 전달합니다.",
    singular: "개선 요청",
    scope: "findings:write",
    columns: ["name", "finding_id", "status", "updated_at"],
    fields: [
      { key: "name", label: "개선 요청 이름", required: true },
      {
        key: "finding_id",
        label: "연결할 발견 건",
        type: "finding",
        required: true,
      },
      {
        key: "integration_id",
        label: "전송할 연동",
        type: "integration",
        description: "direction=outbound로 설정한 REST 연동을 선택하세요.",
      },
      {
        key: "description",
        label: "개선 내용",
        type: "textarea",
        required: true,
      },
      { key: "patch", label: "코드 · 설정 변경안", type: "textarea" },
      { key: "url", label: "외부 티켓 · PR 주소" },
      {
        key: "status",
        label: "상태",
        type: "select",
        options: ["draft"],
        default: "draft",
      },
    ],
  },
  approvals: {
    title: "검토 · 승인",
    description:
      "관리자가 활성화한 팀장 검토 절차에 따라 진단 요청을 승인하거나 반려합니다.",
    singular: "승인 요청",
    scope: "scans:approve",
    readOnly: true,
    columns: ["service_id", "profile", "status", "created_at"],
    fields: [],
  },
};
export const fieldLabels: Record<string, string> = {
  interval_minutes: "간격 (분)",
  next_run_at: "다음 실행",
  name: "이름",
  title: "제목",
  environment: "환경",
  team: "담당 조직",
  criticality: "중요도",
  approved: "진단 승인",
  service_id: "대상 서비스",
  severity: "심각도",
  status: "상태",
  assignee: "담당자",
  profile: "진단 프로파일",
  created_at: "등록 일시",
  updated_at: "변경 일시",
  finished_at: "종료 일시",
  started_at: "시작 일시",
  max_rps: "최대 RPS",
  max_requests: "최대 요청",
  timeout_seconds: "제한 시간",
  enabled: "사용",
  allowed_hosts: "허용 호스트",
  allowed_paths: "허용 경로",
  expires_at: "만료 일시",
  type: "방식",
  endpoint: "연결 주소",
  url: "주소",
  source: "출처",
  network: "망 구분",
  last_seen_at: "최근 응답",
  description: "설명",
  owner_id: "등록자 ID",
  evidence: "증거 · 재현",
  remediation: "개선 가이드",
  logs: "실행 로그",
  result: "진단 결과",
  username: "아이디",
  role: "역할",
  action: "작업",
  target: "대상",
  detail: "상세",
  reason: "사유",
  finding_id: "연결 발견 건",
  integration_id: "연동",
  patch: "변경안",
  decision_reason: "판단 사유",
  fingerprint: "중복 식별자",
  component: "구성요소",
  contribution_points: "기여 점수",
  scope_id: "진단 범위",
  scenario_id: "시나리오",
  steps: "검증 단계",
  config: "세부 설정",
  cve: "CVE",
  targets: "공격 표면",
  repository: "소스 저장소",
  image: "이미지",
  owner: "담당자",
  due_date: "조치 기한",
  decided_by: "검토자",
  requester_id: "요청자",
  error: "오류",
  observations: "관찰 기록",
};
export function initialValues(fields: Field[], row?: Row | null) {
  const out: Row = {};
  fields.forEach((f) => {
    let v =
      row?.[f.key] ??
      f.default ??
      (f.type === "switch"
        ? false
        : f.type === "tags"
          ? []
          : f.type === "json"
            ? {}
            : "");
    if (f.type === "json") v = JSON.stringify(v, null, 2);
    if (f.type === "password") v = "";
    if (f.type === "datetime" && v) {
      const d = new Date(v);
      if (!isNaN(d.getTime()))
        v = new Date(d.getTime() - d.getTimezoneOffset() * 60000)
          .toISOString()
          .slice(0, 16);
    }
    out[f.key] = v;
  });
  return out;
}
export function FieldForm({
  fields,
  values,
  setValues,
  services = [],
  scopes = [],
  scenarios = [],
  choices = {},
  errors = {},
  idPrefix,
}: {
  fields: Field[];
  values: Row;
  setValues: (v: Row) => void;
  services?: Row[];
  scopes?: Row[];
  scenarios?: Row[];
  choices?: Record<string, Row[]>;
  errors?: Record<string, string>;
  idPrefix?: string;
}) {
  const { user } = useSession();
  const change = (key: string, v: any) =>
    setValues(changeResourceField(values, key, v, fields));
  return (
    <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg">
      {fields
        .filter((f) => !f.admin || user?.role === "admin")
        .map((f) => {
          const common = {
            label: f.label,
            description: f.description,
            required: f.required,
            error: errors[f.key],
            id: idPrefix ? `${idPrefix}-${f.key}` : undefined,
          };
          let input;
          switch (f.type) {
            case "switch":
              input = (
                <Switch
                  label={f.label}
                  description={f.description}
                  checked={!!values[f.key]}
                  onChange={(e) => change(f.key, e.currentTarget.checked)}
                  size="md"
                  mt="xs"
                />
              );
              break;
            case "select":
            case "service":
            case "scope":
            case "scenario":
            case "user":
            case "auth":
            case "finding":
            case "integration": {
              if (f.type === "integration" && !choices.integration?.length) {
                input = (
                  <TextInput
                    {...common}
                    value={values[f.key] || ""}
                    onChange={(e) => change(f.key, e.target.value)}
                    placeholder="관리자가 제공한 연동 ID (선택)"
                  />
                );
                break;
              }
              const options = choices[f.type || ""]
                ? (choices[f.type || ""] || [])
                    .filter(
                      (s) =>
                        f.type !== "auth" ||
                        !values.service_id ||
                        s.service_id === values.service_id,
                    )
                    .map((s) => ({
                      value: s.id,
                      label: s.name || s.title || s.username || s.id,
                    }))
                : f.type === "service"
                  ? services.map((s) => ({
                      value: s.id,
                      label: s.name || s.id,
                    }))
                  : f.type === "scope"
                    ? scopes
                        .filter(
                          (s) =>
                            !values.service_id ||
                            s.service_id === values.service_id,
                        )
                        .map((s) => ({
                          value: s.id,
                          label: `${s.name} ${s.approved ? "" : "(미승인)"}`,
                        }))
                    : f.type === "scenario"
                      ? scenarios
                          .filter(
                            (s) =>
                              !values.service_id ||
                              s.service_id === values.service_id,
                          )
                          .map((s) => ({ value: s.id, label: s.name || s.id }))
                      : (f.options || []).map((o) => ({
                          value: o,
                          label: label(o),
                        }));
              input = (
                <Select
                  {...common}
                  searchable
                  clearable={!f.required}
                  placeholder="선택하세요"
                  data={options}
                  value={values[f.key] || null}
                  onChange={(v) => change(f.key, v || "")}
                  nothingFoundMessage="선택할 항목이 없습니다"
                />
              );
              break;
            }
            case "number":
              input = (
                <NumberInput
                  {...common}
                  value={values[f.key]}
                  min={f.min ?? 0}
                  max={f.max}
                  onChange={(v) => change(f.key, v)}
                />
              );
              break;
            case "tags":
              input = (
                <TagsInput
                  {...common}
                  value={values[f.key] || []}
                  onChange={(v) => change(f.key, v)}
                  placeholder="입력 후 Enter"
                  clearable
                />
              );
              break;
            case "json":
              input = (
                <JsonInput
                  {...common}
                  value={values[f.key]}
                  onChange={(v) => change(f.key, v)}
                  formatOnBlur
                  autosize
                  minRows={5}
                  maxRows={18}
                  validationError="올바른 JSON 형식으로 입력하세요"
                />
              );
              break;
            case "textarea":
              input = (
                <Textarea
                  {...common}
                  value={values[f.key]}
                  onChange={(e) => change(f.key, e.target.value)}
                  minRows={3}
                  autosize
                />
              );
              break;
            default:
              input = (
                <TextInput
                  {...common}
                  placeholder={f.placeholder}
                  type={
                    f.type === "password"
                      ? "password"
                      : f.type === "datetime"
                        ? "datetime-local"
                        : "text"
                  }
                  value={values[f.key] ?? ""}
                  onChange={(e) => change(f.key, e.target.value)}
                  autoComplete={f.type === "password" ? "new-password" : "off"}
                />
              );
          }
          return (
            <div
              key={f.key}
              className={
                ["textarea", "json", "switch", "tags"].includes(f.type || "")
                  ? "field-wide"
                  : ""
              }
            >
              {input}
            </div>
          );
        })}
    </SimpleGrid>
  );
}
function formBody(fields: Field[], values: Row) {
  const out = { ...values };
  for (const f of fields) {
    if (f.type === "json") {
      try {
        out[f.key] = JSON.parse(values[f.key] || "{}");
      } catch {
        throw new Error(`${f.label}: 올바른 JSON 형식을 입력해 주세요.`);
      }
    }
    if (f.type === "datetime") {
      out[f.key] = values[f.key] ? new Date(values[f.key]).toISOString() : "";
    }
    if (
      f.required &&
      (out[f.key] === "" ||
        out[f.key] == null ||
        (Array.isArray(out[f.key]) && !out[f.key].length))
    )
      throw new Error(`${f.label} 항목을 입력해 주세요.`);
  }
  return out;
}
export function ResourcePage({ kind }: { kind: string }) {
  const cfg = configs[kind];
  const can = useCan();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const { data, loading, error, reload } = useData<Row[]>(`/api/${kind}`);
  const servicesData = useData<Row[]>(
    kind === "services" || !can("services:read") ? null : "/api/services",
  );
  const scopesData = useData<Row[]>(
    ["scans", "schedules"].includes(kind) && can("services:read")
      ? "/api/scopes"
      : null,
  );
  const scenariosData = useData<Row[]>(
    ["scans", "schedules"].includes(kind) && can("services:read")
      ? "/api/scenarios"
      : null,
  );
  const { user } = useSession();
  const usersData = useData<Row[]>(
    kind === "services" && user?.role === "admin" ? "/api/users" : null,
  );
  const authData = useData<Row[]>(
    kind === "scenarios" ? "/api/auth-profiles" : null,
  );
  const findingData = useData<Row[]>(
    kind === "remediations" ? "/api/findings" : null,
  );
  const integrationData = useData<Row[]>(
    kind === "remediations" &&
      (user?.role === "admin" || user?.scopes?.includes("integrations:manage"))
      ? "/api/integrations"
      : null,
  );
  const writable = can(cfg.scope);
  const selection = useFindingSelection(`${kind}:${params.toString()}`);
  const bulkEnabled = kind === "findings" && writable;
  const [opened, setOpened] = useState(false),
    [edit, setEdit] = useState<Row | null>(null),
    [values, setValues] = useState<Row>({}),
    [busy, setBusy] = useState(false),
    [remove, setRemove] = useState<Row | null>(null),
    [importOpen, setImportOpen] = useState(false),
    [importService, setImportService] = useState<string | null>(null),
    [importFormat, setImportFormat] = useState<string | null>("generic"),
    [importJSON, setImportJSON] = useState(""),
    [importScan, setImportScan] = useState(""),
    [decision, setDecision] = useState<{ row: Row; value: string } | null>(
      null,
    ),
    [reason, setReason] = useState(""),
    [eventOpen, setEventOpen] = useState(false),
    [eventData, setEventData] = useState<Row>({
      event_type: "deploy",
      profile: "http-baseline",
    });
  const [dispatch, setDispatch] = useState<Row | null>(null);
  const [formError, setFormError] = useState("");
  const [saveAttempt, setSaveAttempt] = useState(0);
  useEffect(() => {
    if (opened) setFormError("");
  }, [opened]);
  const location = useLocation();
  const selectedId = params.get("item") || params.get("scan") || "";
  const detailRequest = useData<Row>(
    selectedId ? `/api/${kind}/${encodeURIComponent(selectedId)}` : null,
  );
  const detail =
    !detailRequest.loading &&
    !detailRequest.error &&
    detailRequest.data?.id === selectedId
      ? detailRequest.data
      : null;
  const baseline = useRef<Row>({});
  const formRef = useRef<HTMLFormElement>(null);
  const [formIssues, setFormIssues] = useState<FormIssue[]>([]);
  const [confirmClose, setConfirmClose] = useState(false),
    [conflict, setConflict] = useState(false),
    [latest, setLatest] = useState<Row | null>(null),
    [latestBusy, setLatestBusy] = useState(false);
  const [activityDirty, setActivityDirty] = useState(false),
    [activityVisited, setActivityVisited] = useState(false),
    [pendingDetailAction, setPendingDetailAction] = useState<
      (() => void) | null
    >(null);
  const formDirty = opened && changed(baseline.current, values);
  useUnsavedChanges(formDirty || (opened && busy) || activityDirty);
  useEffect(() => {
    setActivityDirty(false);
    setActivityVisited(false);
  }, [selectedId]);
  useEffect(() => {
    if (params.get("detail_tab") === "activity") setActivityVisited(true);
  }, [selectedId, params.get("detail_tab")]);
  function clearForm() {
    setOpened(false);
    setConfirmClose(false);
    setConflict(false);
    setLatest(null);
    setFormError("");
    setFormIssues([]);
    setValues({});
    setEdit(null);
    baseline.current = {};
  }
  function requestCloseForm() {
    if (busy || latestBusy) return;
    if (formDirty) setConfirmClose(true);
    else clearForm();
  }
  function detailTransition(action: () => void) {
    if (activityDirty) setPendingDetailAction(() => action);
    else action();
  }
  async function copyDetail(value: string, caption: string) {
    try {
      await copyText(value);
      success(`${caption}를 복사했습니다.`);
    } catch (error) {
      showError(error);
    }
  }
  async function reviewLatest() {
    if (!edit || latestBusy) return;
    setLatestBusy(true);
    try {
      setLatest(await api<Row>(`/api/${kind}/${encodeURIComponent(edit.id)}`));
    } catch (error) {
      setFormError(
        error instanceof Error
          ? error.message
          : "최신 자료를 불러오지 못했습니다.",
      );
    } finally {
      setLatestBusy(false);
    }
  }
  function replaceWithLatest() {
    if (!latest) return;
    const next = initialValues(cfg.fields, latest);
    setEdit(latest);
    baseline.current = next;
    setValues(next);
    setLatest(null);
    setConflict(false);
    setFormError("");
    setFormIssues([]);
  }
  const [history, setHistory] = useState<{
    name: string;
    rows: Row[];
    loading: boolean;
    error: string;
  } | null>(null);
  function showDetail(row: Row, replace = false) {
    detailTransition(() => {
      const next = new URLSearchParams(params);
      next.set("item", row.id);
      next.delete("scan");
      setParams(next, {
        replace,
        preventScrollReset: true,
        state: location.state,
      });
    });
  }
  function closeDetailNow() {
    const next = new URLSearchParams(params);
    next.delete("item");
    next.delete("scan");
    next.delete("detail_tab");
    setParams(next, {
      replace: true,
      preventScrollReset: true,
      state: location.state,
    });
  }
  function closeDetail() {
    detailTransition(closeDetailNow);
  }
  const serviceMap = useMemo(
    () =>
      Object.fromEntries(
        (servicesData.data || (data && kind === "services" && data) || []).map(
          (s: Row) => [s.id, s.name],
        ),
      ),
    [servicesData.data, data, kind],
  );
  const severityOrder = ["info", "low", "medium", "high", "critical"];
  const list = useListView<Row>({
    rows: data || [],
    columns: cfg.columns.map((key) => ({
      key,
      label: fieldLabels[key] || key,
      value: (row: Row) => {
        if (key === "service_id") return serviceMap[row[key]] || row[key];
        if (key === "finding_id")
          return (
            findingData.data?.find((finding) => finding.id === row[key])
              ?.title || row[key]
          );
        if (key === "approved") return row[key] ? "승인됨" : "미승인";
        if (key === "enabled") return row[key] ? "활성" : "비활성";
        if (key.endsWith("_at")) return row[key] ? Date.parse(row[key]) : null;
        if (typeof row[key] === "string") return label(row[key]);
        return row[key];
      },
      ...(key === "severity"
        ? {
            compare: (a: Row, b: Row) =>
              severityOrder.indexOf(a.severity) -
              severityOrder.indexOf(b.severity),
          }
        : {}),
    })),
    searchValues: (row) => [
      row.id,
      row.url,
      row.cve,
      row.source,
      row.profile,
      row.assignee,
      ...cfg.columns.map((key) =>
        key.endsWith("_at")
          ? [row[key], dateText(row[key])]
          : typeof row[key] === "object"
            ? null
            : row[key],
      ),
    ],
    filters: Object.fromEntries(
      ["status", "severity", "environment", "type", "service_id", "team"].map(
        (key) => [key, (row: Row, value: string) => row[key] === value],
      ),
    ),
  });
  const hasFilters = !!list.query || Object.values(list.filters).some(Boolean);
  const detailIndex = detail
    ? list.filteredRows.findIndex((row) => row.id === detail.id)
    : -1;
  const filterFields = [
    "status",
    "severity",
    "environment",
    "type",
    "service_id",
    "team",
  ].filter(
    (key) =>
      cfg.columns.includes(key) &&
      (data?.some((row) => row[key]) || list.filters[key]),
  );
  const filterOptions = (key: string) =>
    Array.from(
      new Set([
        ...(data || [])
          .map((row) => row[key])
          .filter((value) => typeof value === "string" && value),
        ...(list.filters[key] ? [list.filters[key]] : []),
      ]),
    )
      .map((value) => ({
        value,
        label: key === "service_id" ? serviceMap[value] || value : label(value),
      }))
      .sort((a, b) => a.label.localeCompare(b.label, "ko", { numeric: true }));
  useEffect(() => {
    const finding = params.get("finding");
    if (kind === "remediations" && finding) {
      setEdit(null);
      const next = {
        ...initialValues(cfg.fields),
        finding_id: finding,
        name: "발견 건 개선 요청",
      };
      baseline.current = next;
      setValues(next);
      setFormError("");
      setFormIssues([]);
      setConflict(false);
      setOpened(true);
    }
  }, [kind, params.get("finding"), cfg.fields]);
  function create() {
    setEdit(null);
    const next = initialValues(cfg.fields);
    baseline.current = next;
    setValues(next);
    setFormError("");
    setFormIssues([]);
    setConflict(false);
    setOpened(true);
  }
  function editRow(row: Row) {
    detailTransition(() => {
      setEdit(row);
      const next = initialValues(cfg.fields, row);
      baseline.current = next;
      setValues(next);
      setFormError("");
      setFormIssues([]);
      setConflict(false);
      closeDetailNow();
      setOpened(true);
    });
  }
  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setFormError("");
    setFormIssues([]);
    setSaveAttempt((value) => value + 1);
    const required = requiredIssues(
      cfg.fields
        .filter(
          (field) => field.required && (!field.admin || user?.role === "admin"),
        )
        .map((field) => ({
          fieldId: `resource-${kind}-${field.key}`,
          label: field.label,
          value: values[field.key],
        })),
    );
    if (
      ["scans", "schedules"].includes(kind) &&
      values.profile === "authorization" &&
      !values.scenario_id
    )
      required.push({
        fieldId: `resource-${kind}-scenario_id`,
        message: "업무 권한 검증 시나리오를 선택하세요.",
      });
    const issues = [
      ...new Map(
        [
          ...required,
          ...(formRef.current ? invalidFields(formRef.current) : []),
        ].map((issue) => [issue.fieldId || issue.message, issue]),
      ).values(),
    ];
    setFormIssues(issues);
    if (issues.length) return;
    setBusy(true);
    try {
      const body = withEditRevision(formBody(cfg.fields, values), edit);
      await api(`/api/${kind}${edit ? `/${edit.id}` : ""}`, {
        method: edit ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      success(
        `${cfg.singular}${edit ? " 정보를 수정" : "을(를) 등록"}했습니다`,
      );
      clearForm();
      await reload();
    } catch (e) {
      setConflict(!!edit && e instanceof APIError && e.status === 409);
      setFormError(
        e instanceof Error
          ? e.message
          : "저장하지 못했습니다. 잠시 후 다시 시도해 주세요.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function action(row: Row, path: string, body: Row = {}) {
    setBusy(true);
    try {
      const result = await api(`/api/${kind}/${row.id}/${path}`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      success(
        typeof result?.message === "string"
          ? result.message
          : "요청을 처리했습니다",
      );
      await reload();
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  async function deleteRow() {
    if (!remove) return;
    setBusy(true);
    try {
      await api(`/api/${kind}/${remove.id}`, { method: "DELETE" });
      success("항목을 삭제했습니다");
      setRemove(null);
      closeDetail();
      await reload();
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  async function doImport() {
    setBusy(true);
    try {
      if (!importService) throw new Error("대상 서비스를 선택해 주세요.");
      let results;
      try {
        results = JSON.parse(importJSON);
      } catch {
        throw new Error("진단 결과가 올바른 JSON인지 확인해 주세요.");
      }
      const result = await api("/api/imports", {
        method: "POST",
        body: JSON.stringify({
          format: importFormat,
          scan_id: importScan || undefined,
          service_id: importService,
          results,
        }),
      });
      success(`진단 결과를 가져왔습니다. ${JSON.stringify(result)}`);
      setImportOpen(false);
      setImportJSON("");
      await reload();
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  async function approve() {
    if (!decision) return;
    setBusy(true);
    try {
      await api(
        `/api/scans/${decision.row.scan_id || decision.row.id}/approve`,
        {
          method: "POST",
          body: JSON.stringify({ decision: decision.value, reason }),
        },
      );
      success("검토 결과를 반영했습니다");
      setDecision(null);
      setReason("");
      await reload();
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }
  function cell(row: Row, key: string) {
    const v = row[key];
    if (
      [
        "status",
        "severity",
        "environment",
        "profile",
        "criticality",
        "type",
      ].includes(key)
    )
      return <Status value={v} />;
    if (["enabled", "approved"].includes(key))
      return (
        <Badge
          variant="light"
          color={v ? "teal" : "gray"}
          size="lg"
          radius="sm"
        >
          {key === "approved"
            ? v
              ? "승인됨"
              : "미승인"
            : v
              ? "활성"
              : "비활성"}
        </Badge>
      );
    if (key === "finding_id")
      return (
        <span>
          {findingData.data?.find((f) => f.id === v)?.title || v || "—"}
        </span>
      );
    if (key === "service_id")
      return <span className="table-service">{serviceMap[v] || v || "—"}</span>;
    if (key.endsWith("_at"))
      return <span className="table-date">{dateText(v)}</span>;
    if (Array.isArray(v))
      return (
        <Group gap={4}>
          {v.slice(0, 2).map((x, i) => (
            <Badge key={i} color="gray" variant="light">
              {typeof x === "object" ? JSON.stringify(x) : x}
            </Badge>
          ))}
          {v.length > 2 && <span>+{v.length - 2}</span>}
        </Group>
      );
    if (["name", "title"].includes(key))
      return (
        <div className="table-main">
          <span
            className={`table-object-icon ${kind === "findings" ? "finding-object" : ""}`}
          >
            <IconShieldCheck size={17} />
          </span>
          <div>
            <strong>{v || "이름 없음"}</strong>
            {(row.url || row.cve || row.source) && (
              <small>{row.url || row.cve || row.source}</small>
            )}
          </div>
        </div>
      );
    return (
      <span className="table-truncate">
        {v === undefined || v === "" ? "—" : String(v)}
      </span>
    );
  }
  return (
    <>
      <PageHeader
        title={cfg.title}
        description={cfg.description}
        eyebrow={
          kind === "approvals"
            ? "REVIEW & APPROVAL"
            : kind === "services"
              ? "ASSET INVENTORY"
              : kind === "findings"
                ? "FINDINGS & REMEDIATION"
                : kind === "scans"
                  ? "CONTINUOUS VALIDATION"
                  : kind === "scenarios"
                    ? "AUTHORIZATION TESTING"
                    : "ADMINISTRATION"
        }
        action={
          <Group gap="sm">
            {kind === "policies" && writable && (
              <Button
                variant="default"
                component="a"
                href="/api/policies/export"
                leftSection={<IconDownload size={18} />}
              >
                정책 JSON 다운로드
              </Button>
            )}
            {kind === "findings" && writable && (
              <Button
                variant="default"
                leftSection={<IconFileImport size={18} />}
                onClick={() => setImportOpen(true)}
              >
                진단 결과 가져오기
              </Button>
            )}
            {kind === "workers" && writable && (
              <Button
                leftSection={<IconPlus size={18} />}
                onClick={() => setEventOpen(true)}
              >
                변경 이벤트 등록
              </Button>
            )}
            {!cfg.readOnly && !cfg.editOnly && writable && (
              <Button
                leftSection={
                  kind === "scans" ? (
                    <IconPlayerPlay size={18} />
                  ) : (
                    <IconPlus size={18} />
                  )
                }
                onClick={create}
              >
                {kind === "scans" ? "진단 실행" : `${cfg.singular} 등록`}
              </Button>
            )}
          </Group>
        }
      />
      {kind === "services" && (
        <div className="info-strip">
          <IconLayersMini />
          <div>
            <strong>서비스에서 시작하는 보안 관리</strong>
            <span>
              서비스를 등록한 뒤 진단 대상 승인과 허용 범위를 설정하면 안전하게
              진단할 수 있습니다.
            </span>
          </div>
        </div>
      )}
      {kind === "scenarios" && (
        <Alert color="teal" mb="xl" title="업무 정책이 검증의 기준입니다">
          본인 데이터의 정상 접근 단계와 타인 데이터의 차단 단계를 함께
          정의하세요. 인증 실패는 권한 통제 성공으로 처리하지 않습니다. 합성
          데이터와 테스트 계정을 사용합니다.
        </Alert>
      )}
      {kind === "integrations" && (
        <SimpleGrid cols={{ base: 2, lg: 4 }} mb="xl">
          {[
            { t: "REST API", s: "ITAM · ITSM · 서비스 카탈로그" },
            { t: "데이터베이스", s: "PostgreSQL 읽기 전용 수집" },
            { t: "이벤트 웹훅", s: "배포 · 소스 변경 기반 재진단" },
            { t: "진단 엔진", s: "Trivy · Nuclei · ZAP · SARIF" },
          ].map((i) => (
            <Paper key={i.t} className="integration-type">
              <IconCode size={22} />
              <strong>{i.t}</strong>
              <span>{i.s}</span>
            </Paper>
          ))}
        </SimpleGrid>
      )}
      <Paper className="data-panel">
        <div className="table-toolbar">
          <Group gap="xs">
            <h2>
              {kind === "approvals" ? "검토 요청 목록" : `${cfg.singular} 목록`}
            </h2>
            <Badge color="gray" variant="light" radius="sm">
              {data?.length || 0}
            </Badge>
          </Group>
          <Group gap="sm" className="table-controls">
            <ListSearch
              view={list}
              label={`${cfg.singular} 검색`}
              placeholder="이름, 서비스, 상태 검색"
            />
            <ListReset view={list} />
            <Tooltip label="새로고침">
              <ActionIcon
                aria-label="목록 새로고침"
                variant="default"
                size={36}
                onClick={reload}
              >
                <IconRefresh size={17} />
              </ActionIcon>
            </Tooltip>
          </Group>
        </div>
        {filterFields.length > 0 && (
          <div className="list-filter-bar">
            {filterFields.map((key) => (
              <Select
                key={key}
                label={fieldLabels[key] || key}
                aria-label={`${fieldLabels[key] || key} 필터`}
                placeholder="전체"
                clearable
                searchable
                nothingFoundMessage="일치하는 항목이 없습니다"
                data={filterOptions(key)}
                value={list.filters[key] || null}
                onChange={(value) => list.setFilter(key, value)}
                leftSection={<IconFilter size={15} />}
              />
            ))}
          </div>
        )}
        <ListTools
          view={list}
          loading={loading}
          failed={!!error}
          filterLabels={Object.fromEntries(
            Object.keys(list.filters).map((key) => [
              key,
              {
                label: fieldLabels[key] || key,
                value: (value: string) =>
                  key === "service_id"
                    ? serviceMap[value] || value
                    : label(value),
              },
            ]),
          )}
        />
        {bulkEnabled && (
          <BulkFindingActions
            items={selection.rows}
            onDone={reload}
            onClear={selection.clear}
          />
        )}
        <LoadState loading={loading} error={error} reload={reload} />
        {!loading &&
          !error &&
          (list.filteredRows.length ? (
            <TableViewport view={list} label={cfg.singular} minWidth={760}>
              <Table
                verticalSpacing="md"
                horizontalSpacing="lg"
                highlightOnHover
                className="resource-table"
              >
                <Table.Thead>
                  <Table.Tr>
                    {bulkEnabled && (
                      <Table.Th w={52}>
                        <Checkbox
                          aria-label="현재 페이지 발견 건 모두 선택"
                          checked={
                            list.rows.length > 0 &&
                            list.rows.every((row) => selection.selected(row.id))
                          }
                          indeterminate={
                            list.rows.some((row) =>
                              selection.selected(row.id),
                            ) &&
                            !list.rows.every((row) =>
                              selection.selected(row.id),
                            )
                          }
                          onChange={(event) =>
                            selection.page(
                              list.rows,
                              event.currentTarget.checked,
                            )
                          }
                        />
                      </Table.Th>
                    )}
                    {cfg.columns.map((c) => (
                      <SortHeader key={c} view={list} column={c}>
                        {fieldLabels[c] || c}
                      </SortHeader>
                    ))}
                    <Table.Th w={55}>
                      <span className="sr-only">작업</span>
                    </Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {list.rows.map((row) => (
                    <Table.Tr
                      key={row.id}
                      onClick={() => showDetail(row)}
                      style={{ cursor: "pointer" }}
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && e.target === e.currentTarget)
                          showDetail(row);
                      }}
                    >
                      {bulkEnabled && (
                        <Table.Td onClick={(event) => event.stopPropagation()}>
                          <Checkbox
                            aria-label={`${row.title || row.id} 선택`}
                            checked={selection.selected(row.id)}
                            onChange={(event) =>
                              selection.toggle(row, event.currentTarget.checked)
                            }
                          />
                        </Table.Td>
                      )}
                      {cfg.columns.map((c) => (
                        <Table.Td key={c}>{cell(row, c)}</Table.Td>
                      ))}
                      <Table.Td onClick={(e) => e.stopPropagation()}>
                        <Menu shadow="md" width={180} position="bottom-end">
                          <Menu.Target>
                            <ActionIcon
                              aria-label={`${row.name || row.title || cfg.singular} 작업`}
                              variant="subtle"
                              color="gray"
                            >
                              <IconDots size={18} />
                            </ActionIcon>
                          </Menu.Target>
                          <Menu.Dropdown>
                            <Menu.Item
                              onClick={() => showDetail(row)}
                              leftSection={<IconSearch size={16} />}
                            >
                              상세 보기
                            </Menu.Item>
                            {writable && !cfg.readOnly && kind !== "scans" && (
                              <Menu.Item
                                leftSection={<IconEdit size={16} />}
                                onClick={() => editRow(row)}
                              >
                                수정
                              </Menu.Item>
                            )}
                            {kind === "scans" &&
                              writable &&
                              [
                                "running",
                                "queued",
                                "pending_approval",
                              ].includes(row.status) && (
                                <Menu.Item
                                  color="orange"
                                  leftSection={<IconSquare size={16} />}
                                  onClick={() => action(row, "cancel")}
                                >
                                  진단 취소
                                </Menu.Item>
                              )}
                            {kind === "policies" && writable && (
                              <Menu.Item
                                leftSection={<IconCode size={16} />}
                                onClick={async () => {
                                  setHistory({
                                    name: row.name,
                                    rows: [],
                                    loading: true,
                                    error: "",
                                  });
                                  try {
                                    const rows = await api<Row[]>(
                                      `/api/policies/${row.id}/history`,
                                    );
                                    setHistory({
                                      name: row.name,
                                      rows,
                                      loading: false,
                                      error: "",
                                    });
                                  } catch (e) {
                                    setHistory({
                                      name: row.name,
                                      rows: [],
                                      loading: false,
                                      error: (e as Error).message,
                                    });
                                  }
                                }}
                              >
                                정책 변경 이력
                              </Menu.Item>
                            )}
                            {kind === "findings" && writable && (
                              <Menu.Item
                                leftSection={<IconEdit size={16} />}
                                onClick={() =>
                                  navigate(
                                    `/remediations?finding=${encodeURIComponent(row.id)}`,
                                  )
                                }
                              >
                                개선안 작성
                              </Menu.Item>
                            )}
                            {kind === "discovery" && writable && (
                              <Menu.Item
                                leftSection={<IconPlus size={16} />}
                                onClick={() => action(row, "register")}
                              >
                                서비스로 등록
                              </Menu.Item>
                            )}
                            {kind === "remediations" && writable && (
                              <Menu.Item
                                leftSection={<IconArrowRight size={16} />}
                                onClick={() => setDispatch(row)}
                              >
                                외부 개선 요청 전송
                              </Menu.Item>
                            )}
                            {kind === "findings" &&
                              can("scans:write") &&
                              row.source === "http-baseline" && (
                                <Menu.Item
                                  leftSection={<IconRefresh size={16} />}
                                  onClick={async () => {
                                    try {
                                      await api("/api/scans", {
                                        method: "POST",
                                        body: JSON.stringify({
                                          service_id: row.service_id,
                                          profile: "http-baseline",
                                          finding_id: row.id,
                                        }),
                                      });
                                      success("재검증을 요청했습니다");
                                      await reload();
                                    } catch (e) {
                                      showError(e);
                                    }
                                  }}
                                >
                                  실제 재검증 요청
                                </Menu.Item>
                              )}
                            {kind === "integrations" && writable && (
                              <>
                                <Menu.Item
                                  leftSection={<IconCheck size={16} />}
                                  onClick={() => action(row, "test")}
                                >
                                  연결 테스트
                                </Menu.Item>
                                <Menu.Item
                                  leftSection={<IconRefresh size={16} />}
                                  onClick={() => action(row, "sync")}
                                >
                                  자산 동기화
                                </Menu.Item>
                              </>
                            )}
                            {kind === "approvals" &&
                              writable &&
                              ["pending_approval", "pending"].includes(
                                row.status,
                              ) && (
                                <>
                                  <Menu.Item
                                    color="teal"
                                    onClick={() =>
                                      setDecision({ row, value: "approved" })
                                    }
                                  >
                                    승인
                                  </Menu.Item>
                                  <Menu.Item
                                    color="red"
                                    onClick={() =>
                                      setDecision({ row, value: "rejected" })
                                    }
                                  >
                                    반려
                                  </Menu.Item>
                                </>
                              )}
                            {writable && !cfg.readOnly && !cfg.noDelete && (
                              <>
                                <Menu.Divider />
                                <Menu.Item
                                  color="red"
                                  leftSection={<IconTrash size={16} />}
                                  onClick={() => setRemove(row)}
                                >
                                  삭제
                                </Menu.Item>
                              </>
                            )}
                          </Menu.Dropdown>
                        </Menu>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </TableViewport>
          ) : (
            <Empty
              title={
                hasFilters
                  ? "검색 결과가 없습니다"
                  : `등록된 ${cfg.singular}이(가) 없습니다`
              }
              description={
                hasFilters
                  ? "검색어나 필터를 변경해 다시 확인하세요."
                  : cfg.description
              }
              action={
                !hasFilters && !cfg.readOnly && !cfg.editOnly && writable ? (
                  <Button
                    variant="light"
                    leftSection={<IconPlus size={17} />}
                    onClick={create}
                  >
                    첫 {cfg.singular} 등록
                  </Button>
                ) : undefined
              }
            />
          ))}
        {!loading && !error && <ListPagination view={list} limit={5000} />}
      </Paper>
      {kind === "integrations" && (
        <Paper className="content-card" mt="xl">
          <h2>유연한 연동을 위한 설정 안내</h2>
          <Text c="dimmed" size="sm" mb="md">
            연동 비밀정보는 암호화되어 저장됩니다. 수집한 자산은 발견 후보로
            등록되며 자동으로 진단 승인되지 않습니다.
          </Text>
          <Tabs defaultValue="rest">
            <Tabs.List>
              <Tabs.Tab value="rest">REST API</Tabs.Tab>
              <Tabs.Tab value="postgres">PostgreSQL</Tabs.Tab>
              <Tabs.Tab value="webhook">웹훅 · API</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="rest" pt="md">
              <Code block>
                {JSON.stringify(
                  {
                    items_path: "data.services",
                    mapping: {
                      name: "service_name",
                      url: "endpoint",
                      team: "owner_team",
                    },
                  },
                  null,
                  2,
                )}
              </Code>
            </Tabs.Panel>
            <Tabs.Panel value="postgres" pt="md">
              <Text size="sm" mb="sm">
                읽기 전용 계정을 사용하고 SELECT 결과를 서비스 후보로
                가져옵니다.
              </Text>
              <Code block>
                {JSON.stringify(
                  {
                    query:
                      "SELECT name, url, team FROM service_catalog LIMIT 500",
                    mapping: { name: "name", url: "url", team: "team" },
                  },
                  null,
                  2,
                )}
              </Code>
            </Tabs.Panel>
            <Tabs.Panel value="webhook" pt="md">
              <Text size="sm">
                개인 API 키의 권한으로 POST
                /api/integrations/&#123;id&#125;/webhook을 호출하세요. API
                명세는{" "}
                <a href="/api/openapi.json" target="_blank" rel="noreferrer">
                  OpenAPI 문서
                </a>
                에서 확인할 수 있습니다.
              </Text>
            </Tabs.Panel>
          </Tabs>
        </Paper>
      )}
      {kind === "workers" && (
        <>
          <Alert color="teal" mt="xl" title="워커에 담당 망을 지정하세요">
            워커의 담당 망이 서비스의 망 구분과 정확히 일치해야 실행합니다. 내장
            워커 builtin도 업무망 등 사용할 망을 지정하세요. 외부 워커는 최초
            등록 시 비활성 상태이며 관리자가 명시적으로 활성화합니다.
          </Alert>
          <EventsPanel />
        </>
      )}
      <Modal
        opened={opened}
        onClose={requestCloseForm}
        closeOnClickOutside={!busy && !latestBusy}
        closeOnEscape={!busy && !latestBusy}
        withCloseButton={!busy && !latestBusy}
        title={
          <strong>
            {cfg.singular} {edit ? "수정" : "등록"}
          </strong>
        }
        size="xl"
      >
        <form ref={formRef} noValidate onSubmit={save}>
          <FormFeedback
            error={formError}
            issues={formIssues}
            focusKey={saveAttempt}
          />
          {conflict && (
            <Alert
              color="orange"
              mb="lg"
              title="다른 변경 사항을 먼저 확인하세요"
            >
              <Text size="sm">
                입력 내용은 유지했습니다. 최신 자료를 확인한 후 다시 작성할 수
                있습니다. 변경 내용을 자동으로 덮어쓰지 않습니다.
              </Text>
              <Button
                mt="sm"
                variant="light"
                loading={latestBusy}
                onClick={reviewLatest}
              >
                최신 자료 확인
              </Button>
            </Alert>
          )}
          {(edit || formDirty || busy) && (
            <SaveStatus dirty={formDirty} saving={busy} />
          )}
          <fieldset className="form-fields" disabled={busy || latestBusy}>
            {kind === "scans" && (
              <Alert color="teal" mb="lg">
                HTTP 진단은 승인된 URL에 제한된 GET/HEAD 요청을 보내 실제 보안
                헤더를 점검합니다. 운영계의 임의 능동 공격, 외부 주소로의
                리다이렉트는 허용하지 않습니다.
              </Alert>
            )}
            <FieldForm
              idPrefix={`resource-${kind}`}
              errors={Object.fromEntries(
                formIssues
                  .filter((issue) =>
                    issue.fieldId?.startsWith(`resource-${kind}-`),
                  )
                  .map((issue) => [
                    issue.fieldId!.slice(`resource-${kind}-`.length),
                    issue.message,
                  ]),
              )}
              fields={cfg.fields}
              values={values}
              setValues={setValues}
              services={servicesData.data || []}
              scopes={scopesData.data || []}
              scenarios={scenariosData.data || []}
              choices={{
                user: usersData.data || [],
                auth: authData.data || [],
                finding: findingData.data || [],
                integration: integrationData.data || [],
              }}
            />
            <Group justify="flex-end" mt="xl">
              <Button
                variant="default"
                onClick={requestCloseForm}
                disabled={busy || latestBusy}
              >
                취소
              </Button>
              <Button type="submit" loading={busy}>
                {kind === "scans"
                  ? "진단 요청"
                  : edit
                    ? "변경 사항 저장"
                    : "등록"}
              </Button>
            </Group>
          </fieldset>
        </form>
      </Modal>
      <Drawer
        opened={!!selectedId}
        onClose={closeDetail}
        title={`${cfg.singular} 상세`}
        position="right"
        size="lg"
      >
        <LoadState
          loading={detailRequest.loading}
          error={detailRequest.error}
          reload={detailRequest.reload}
        />
        {detailRequest.error && (
          <Button mt="md" variant="default" onClick={closeDetail}>
            목록으로 돌아가기
          </Button>
        )}
        {detail && (
          <Stack>
            {detailIndex >= 0 && (
              <Group justify="space-between" className="detail-navigation">
                <Text size="sm" c="dimmed">
                  현재 목록 {detailIndex + 1} / {list.filteredRows.length}
                </Text>
                <Group gap="xs">
                  <Button
                    variant="default"
                    leftSection={<IconChevronLeft size={16} />}
                    disabled={detailIndex === 0}
                    onClick={() =>
                      showDetail(list.filteredRows[detailIndex - 1], true)
                    }
                  >
                    이전 항목
                  </Button>
                  <Button
                    variant="default"
                    rightSection={<IconChevronRight size={16} />}
                    disabled={detailIndex === list.filteredRows.length - 1}
                    onClick={() =>
                      showDetail(list.filteredRows[detailIndex + 1], true)
                    }
                  >
                    다음 항목
                  </Button>
                </Group>
              </Group>
            )}
            <Group justify="space-between">
              <h2 style={{ margin: 0 }}>
                {detail.name ||
                  detail.title ||
                  serviceMap[detail.service_id] ||
                  cfg.singular}
              </h2>
              {detail.status && <Status value={detail.status} />}
            </Group>
            <Group gap="sm">
              <Button
                variant="default"
                leftSection={<IconCopy size={16} />}
                onClick={() => copyDetail(String(detail.id), "식별자")}
              >
                ID 복사
              </Button>
              <Button
                variant="default"
                leftSection={<IconLink size={16} />}
                onClick={() =>
                  copyDetail(
                    `${window.location.origin}${resourceDetailPath(kind, String(detail.id), params.get("detail_tab") === "activity")}`,
                    "상세 링크",
                  )
                }
              >
                상세 링크 복사
              </Button>
            </Group>
            {writable && !cfg.readOnly && kind !== "scans" && (
              <Button
                variant="light"
                leftSection={<IconEdit size={17} />}
                onClick={() => editRow(detail)}
              >
                정보 수정
              </Button>
            )}
            <Tabs
              value={
                kind === "findings" && params.get("detail_tab") === "activity"
                  ? "activity"
                  : "overview"
              }
              onChange={(value) => {
                const next = new URLSearchParams(params);
                if (value === "activity") next.set("detail_tab", "activity");
                else next.delete("detail_tab");
                setParams(next, {
                  preventScrollReset: true,
                  state: location.state,
                });
              }}
              keepMounted
            >
              {kind === "findings" && (
                <Tabs.List mb="md">
                  <Tabs.Tab value="overview">발견 정보</Tabs.Tab>
                  <Tabs.Tab value="activity">활동 · 댓글</Tabs.Tab>
                </Tabs.List>
              )}
              <Tabs.Panel value="overview">
                {Object.entries(detail)
                  .filter(
                    ([k]) =>
                      ![
                        "secret",
                        "password",
                        "token",
                        "api_key",
                        "id",
                      ].includes(k) && !k.endsWith("_encrypted"),
                  )
                  .map(([key, value]) => (
                    <div className="detail-field" key={key}>
                      <Text size="sm" c="dimmed" fw={500} mb={5}>
                        {fieldLabels[key] || key}
                      </Text>
                      {typeof value === "object" ? (
                        <Code block>{JSON.stringify(value, null, 2)}</Code>
                      ) : (
                        <Text
                          style={{
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-word",
                          }}
                        >
                          {key === "service_id"
                            ? serviceMap[value as string] || String(value)
                            : key.endsWith("_at")
                              ? dateText(value)
                              : label(value)}
                        </Text>
                      )}
                    </div>
                  ))}
                <Text size="xs" c="dimmed">
                  식별자 {detail.id}
                </Text>
              </Tabs.Panel>
              {kind === "findings" && (
                <Tabs.Panel value="activity">
                  {(activityVisited ||
                    params.get("detail_tab") === "activity") && (
                    <FindingActivity
                      key={detail.id}
                      findingId={detail.id}
                      onDirtyChange={setActivityDirty}
                    />
                  )}
                </Tabs.Panel>
              )}
            </Tabs>
          </Stack>
        )}
      </Drawer>
      <Modal
        opened={confirmClose}
        onClose={() => setConfirmClose(false)}
        title="작성 중인 내용을 닫을까요?"
        size="sm"
      >
        <Text>
          저장하지 않은 입력이 있습니다. 계속 작성하거나 입력을 버리고 닫을 수
          있습니다.
        </Text>
        <Group justify="flex-end" mt="lg">
          <Button variant="default" onClick={() => setConfirmClose(false)}>
            계속 작성
          </Button>
          <Button color="red" onClick={clearForm}>
            입력 버리고 닫기
          </Button>
        </Group>
      </Modal>
      <Modal
        opened={!!latest}
        onClose={() => setLatest(null)}
        title="최신 자료 확인"
        size="md"
      >
        <Stack>
          <Text fw={600}>{latest?.name || latest?.title || cfg.singular}</Text>
          <Text size="sm">최근 변경: {dateText(latest?.updated_at)}</Text>
          {latest?.status && <Status value={latest.status} />}
          <Alert color="orange">
            최신 자료로 다시 작성하면 현재 입력한 내용을 대체합니다. 취소하면
            현재 입력을 유지합니다.
          </Alert>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setLatest(null)}>
              입력 유지
            </Button>
            <Button onClick={replaceWithLatest}>최신 자료로 다시 작성</Button>
          </Group>
        </Stack>
      </Modal>
      <Modal
        opened={!!pendingDetailAction}
        onClose={() => setPendingDetailAction(null)}
        title="작성 중인 댓글이 있습니다"
        size="sm"
      >
        <Text>
          아직 등록하지 않은 댓글이 있습니다. 계속 작성하거나 댓글을 버리고
          이동하세요.
        </Text>
        <Group justify="flex-end" mt="lg">
          <Button
            variant="default"
            onClick={() => setPendingDetailAction(null)}
          >
            계속 작성
          </Button>
          <Button
            color="red"
            onClick={() => {
              const action = pendingDetailAction;
              setPendingDetailAction(null);
              setActivityDirty(false);
              action?.();
            }}
          >
            댓글 버리고 이동
          </Button>
        </Group>
      </Modal>
      <Modal
        opened={!!remove}
        onClose={() => setRemove(null)}
        title="항목 삭제"
        size="sm"
      >
        <Text>
          ‘{remove?.name || remove?.title || cfg.singular}’ 항목을
          삭제하시겠습니까?
        </Text>
        <Text c="dimmed" size="sm" mt="sm">
          삭제한 항목은 이 화면에서 복구할 수 없습니다.
        </Text>
        <Group justify="flex-end" mt="xl">
          <Button variant="default" onClick={() => setRemove(null)}>
            취소
          </Button>
          <Button color="red" loading={busy} onClick={deleteRow}>
            삭제
          </Button>
        </Group>
      </Modal>
      <Modal
        opened={importOpen}
        onClose={() => setImportOpen(false)}
        title="진단 결과 가져오기"
        size="lg"
      >
        <Stack>
          <Select
            label="대상 서비스"
            required
            data={(servicesData.data || []).map((s) => ({
              value: s.id,
              label: s.name,
            }))}
            value={importService}
            onChange={setImportService}
            searchable
          />
          <Select
            label="진단 결과 형식"
            data={["generic", "trivy", "nuclei", "zap", "sarif", "gitleaks"]}
            value={importFormat}
            onChange={setImportFormat}
          />
          <TextInput
            label="결과 수입 대기 진단 ID (선택)"
            description="import-only 진단과 연결하려면 진단 상세의 식별자를 입력하세요."
            value={importScan}
            onChange={(e) => setImportScan(e.target.value)}
          />
          <Text size="sm" c="dimmed">
            파일은 브라우저에서 읽은 후 결과를 API로 전송합니다. 동일한 발견
            건은 중복 판정으로 연결합니다.
          </Text>
          <input
            type="file"
            accept=".json,.jsonl,application/json"
            aria-label="진단 결과 JSON 파일"
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (f) {
                if (f.size > 8 * 1024 * 1024) {
                  showError(new Error("8MB 이하 파일을 선택해 주세요."));
                  return;
                }
                const text = await f.text();
                try {
                  setImportJSON(JSON.stringify(JSON.parse(text), null, 2));
                } catch {
                  try {
                    setImportJSON(
                      JSON.stringify(
                        text
                          .split("\n")
                          .filter(Boolean)
                          .map((l) => JSON.parse(l)),
                        null,
                        2,
                      ),
                    );
                  } catch {
                    setImportJSON(text);
                  }
                }
              }
            }}
          />
          <JsonInput
            label="진단 결과 JSON"
            value={importJSON}
            onChange={setImportJSON}
            autosize
            minRows={8}
            maxRows={20}
            formatOnBlur
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setImportOpen(false)}>
              취소
            </Button>
            <Button loading={busy} onClick={doImport}>
              가져오기
            </Button>
          </Group>
        </Stack>
      </Modal>
      <Modal
        opened={!!decision}
        onClose={() => setDecision(null)}
        title={`진단 요청 ${decision?.value === "approved" ? "승인" : "반려"}`}
      >
        <Textarea
          label="검토 사유"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          minRows={3}
        />
        <Group justify="flex-end" mt="lg">
          <Button variant="default" onClick={() => setDecision(null)}>
            취소
          </Button>
          <Button
            color={decision?.value === "approved" ? "teal" : "red"}
            loading={busy}
            onClick={approve}
          >
            검토 결과 저장
          </Button>
        </Group>
      </Modal>
      <Modal
        opened={!!history}
        onClose={() => setHistory(null)}
        title={`${history?.name || "정책"} 변경 이력`}
        size="xl"
      >
        <LoadState loading={!!history?.loading} error={history?.error || ""} />
        {!history?.loading &&
          !history?.error &&
          (history?.rows.length ? (
            <Stack>
              {history.rows.map((h, i) => (
                <Paper p="lg" withBorder key={h.version || i}>
                  <Group justify="space-between" mb="md">
                    <Badge color="teal" variant="light">
                      버전 {h.version}
                    </Badge>
                    <Text size="sm" c="dimmed">
                      {dateText(h.created_at)}
                    </Text>
                  </Group>
                  <Code block>{JSON.stringify(h.data, null, 2)}</Code>
                  <Text size="xs" c="dimmed" mt="sm">
                    변경자: {h.changed_by}
                  </Text>
                </Paper>
              ))}
            </Stack>
          ) : (
            <Empty
              title="기록된 변경 이력이 없습니다"
              description="정책을 저장하면 버전별 변경 내용이 기록됩니다."
            />
          ))}
      </Modal>
      <Modal
        opened={!!dispatch}
        onClose={() => setDispatch(null)}
        title="외부 개선 요청 전송"
      >
        <Text>
          ‘{dispatch?.name}’ 개선 내용을 연결된 외부 시스템에 전송합니다.
        </Text>
        <Alert mt="lg" color="teal">
          연동의 설정된 주소로 티켓 또는 변경 요청을 생성합니다. 코드 병합은
          자동으로 수행하지 않습니다.
        </Alert>
        <Group justify="flex-end" mt="xl">
          <Button variant="default" onClick={() => setDispatch(null)}>
            취소
          </Button>
          <Button
            loading={busy}
            onClick={async () => {
              if (!dispatch) return;
              await action(dispatch, "dispatch");
              setDispatch(null);
            }}
          >
            전송
          </Button>
        </Group>
      </Modal>
      <Modal
        opened={eventOpen}
        onClose={() => setEventOpen(false)}
        title="변경 이벤트 등록"
      >
        <Stack>
          <Select
            label="서비스"
            data={(servicesData.data || []).map((s) => ({
              value: s.id,
              label: s.name,
            }))}
            value={eventData.service_id || null}
            onChange={(v) => setEventData({ ...eventData, service_id: v })}
          />
          <Select
            label="이벤트"
            data={[
              { value: "deploy", label: "배포" },
              { value: "push", label: "소스 변경" },
              { value: "image", label: "이미지 배포" },
              { value: "iam_change", label: "권한 정책 변경" },
            ]}
            value={eventData.event_type}
            onChange={(v) => setEventData({ ...eventData, event_type: v })}
          />
          <TextInput
            label="변경 참조 (커밋, 이미지 버전 등)"
            value={eventData.reference || ""}
            onChange={(e) =>
              setEventData({ ...eventData, reference: e.target.value })
            }
          />
          <Alert color="teal">
            승인된 서비스와 유효한 허용 범위에 기존 실행 정책을 적용합니다.
          </Alert>
          <Button
            loading={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api("/api/events", {
                  method: "POST",
                  body: JSON.stringify(eventData),
                });
                success("이벤트를 등록했습니다");
                setEventOpen(false);
                await reload();
                window.dispatchEvent(new Event("hunter:events"));
              } catch (e) {
                showError(e);
              } finally {
                setBusy(false);
              }
            }}
          >
            이벤트 등록
          </Button>
        </Stack>
      </Modal>
    </>
  );
}
function IconLayersMini() {
  return (
    <span className="info-strip-icon">
      <IconShieldCheck size={23} />
    </span>
  );
}
function EventsPanel() {
  const { data, loading, error, reload } = useData<Row[]>("/api/events");
  useEffect(() => {
    const refresh = () => {
      void reload();
    };
    window.addEventListener("hunter:events", refresh);
    return () => window.removeEventListener("hunter:events", refresh);
  }, [reload]);
  return (
    <Paper className="content-card" mt="xl">
      <Group justify="space-between" mb="lg">
        <h2>변경 이벤트 이력</h2>
        <ActionIcon
          aria-label="이벤트 새로고침"
          variant="default"
          onClick={reload}
        >
          <IconRefresh size={17} />
        </ActionIcon>
      </Group>
      <LoadState loading={loading} error={error} reload={reload} />
      {!loading &&
        !error &&
        (data?.length ? (
          <Table.ScrollContainer minWidth={600}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>이벤트</Table.Th>
                  <Table.Th>참조</Table.Th>
                  <Table.Th>상태</Table.Th>
                  <Table.Th>발생 일시</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.map((r) => (
                  <Table.Tr key={r.id}>
                    <Table.Td>{r.event_type || r.type}</Table.Td>
                    <Table.Td>{r.reference || "—"}</Table.Td>
                    <Table.Td>
                      <Status value={r.status || "completed"} />
                    </Table.Td>
                    <Table.Td>{dateText(r.created_at)}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        ) : (
          <Empty
            title="수집된 변경 이벤트가 없습니다"
            description="배포 또는 소스 변경 웹훅을 연동하면 이벤트가 기록됩니다."
          />
        ))}
    </Paper>
  );
}
