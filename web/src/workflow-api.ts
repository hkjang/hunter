import { api, type Row } from "./api";

export type FindingRef = {
  id: string;
  title: string;
  severity: string;
  status: string;
};
export type QueueItem = FindingRef & {
  service_id: string;
  service_name: string;
  team?: string;
  owner_id?: string;
  assignee?: string;
  cve?: string;
  component?: string;
  group_id?: string;
  priority: { score: number; level: string; reasons: string[] };
  sla: {
    due_date: string | null;
    source: "manual" | "policy" | "none";
    state: "overdue" | "due_soon" | "on_track" | "not_set" | "invalid";
    remaining_days: number | null;
  };
  intelligence: {
    kev: boolean | null;
    epss: number | null;
    percentile: number | null;
    source_date: string | null;
    stale: boolean | null;
    kev_source_date?: string;
    epss_source_date?: string;
  };
};
export type FindingQueue = {
  items: QueueItem[];
  total: number;
  page: number;
  page_size: number;
  as_of: string;
  summary: Record<string, number>;
  groups: {
    id: string;
    cve: string;
    component: string;
    finding_count: number;
    service_count: number;
    max_score: number;
  }[];
};
export type ActivityItem = {
  id: string;
  kind: "comment" | "audit" | "observation" | "verification";
  author_id?: string;
  author_name?: string;
  created_at: string;
  body?: string;
  action?: string;
  summary: string;
  details?: Row;
};
export type ActivityPage = {
  items: ActivityItem[];
  total: number;
  page: number;
  page_size: number;
};
export type IntelDataset = {
  format: "kev" | "epss";
  configured: boolean;
  source_date: string | null;
  imported_at: string | null;
  sha256: string | null;
  entry_count: number;
  stale: boolean | null;
};
export type IntelligenceState = {
  datasets: IntelDataset[];
  max_content_bytes: number;
  max_entries: number;
  mode: string;
  stale_after_days: number;
};
export type IntelImportResult = {
  format: string;
  source_date: string;
  sha256: string;
  entry_count: number;
  replaced: boolean;
  message: string;
};
export type SoftwareComponent = {
  id: string;
  bom_ref: string;
  identity: string;
  name: string;
  group?: string;
  type?: string;
  version?: string;
  purl?: string;
  licenses: string[];
  license_review: boolean;
  dependency_count: number;
  findings_count?: number;
  findings?: FindingRef[];
  services?: { id: string; name: string; sbom_id: string }[];
};
export type SBOMDocument = {
  id: string;
  service_id: string;
  service_name: string;
  label: string;
  format: string;
  spec_version: string;
  sha256: string;
  created_at: string;
  component_count: number;
  dependency_count: number;
  stale: boolean;
  warnings?: string[];
  duplicate?: boolean;
};
export type SBOMDetail = SBOMDocument & {
  components: SoftwareComponent[];
  dependencies: { ref: string; dependsOn?: string[]; depends_on?: string[] }[];
};
export type SBOMComparison = {
  baseline: SBOMDocument;
  current: SBOMDocument;
  added: SoftwareComponent[];
  removed: SoftwareComponent[];
  changed: { before: SoftwareComponent; after: SoftwareComponent }[];
};
export type CampaignTarget = {
  service_id: string;
  profile: string;
  scope_id?: string;
  scenario_id?: string;
};
export type CampaignScan = CampaignTarget & {
  id: string;
  service_name: string;
  status: string;
  created_at: string;
};
export type Campaign = {
  id: string;
  name: string;
  description: string;
  targets: CampaignTarget[];
  scans: CampaignScan[];
  status: string;
  created_at: string;
  started_at?: string;
  summary: {
    total: number;
    completed: number;
    pending: number;
    running: number;
    failed: number;
  };
};
export type Observation = {
  finding_id: string;
  fingerprint: string;
  service_id: string;
  scan_id: string;
  title: string;
  severity: string;
  source?: string;
  rule_id?: string;
  cve?: string;
  component?: string;
  location?: string;
};
export type CampaignComparison = {
  baseline: Campaign;
  current: Campaign;
  comparable: boolean;
  reasons: string[];
  added: Observation[];
  persisting: Observation[];
  not_seen: Observation[];
  changed: { before: Observation; after: Observation }[];
};
export type OperationsState = {
  as_of: string;
  checks: {
    id: string;
    title: string;
    status: "ok" | "warning" | "error";
    detail: string;
  }[];
  counts: {
    services: number;
    findings: number;
    queued_jobs: number;
    running_jobs: number;
    stale_workers: number;
    sboms: number;
  };
  emergency: boolean | Row;
  version: string;
};
const post = <T>(path: string, body: unknown) =>
  api<T>(path, { method: "POST", body: JSON.stringify(body) });
export const workflowAPI = {
  comment: (id: string, body: string) =>
    post<ActivityItem>(`/api/findings/${encodeURIComponent(id)}/activity`, {
      body,
    }),
  importIntel: (format: string, content: string, source_date: string) =>
    post<IntelImportResult>("/api/intelligence/import", {
      format,
      content,
      source_date,
    }),
  importSBOM: (service_id: string, label: string, document: object) =>
    post<SBOMDocument>("/api/sboms/import", { service_id, label, document }),
  deleteSBOM: (id: string) =>
    api(`/api/sboms/${encodeURIComponent(id)}`, { method: "DELETE" }),
  createCampaign: (body: {
    name: string;
    description: string;
    targets: CampaignTarget[];
  }) => post<Campaign>("/api/campaigns", body),
  startCampaign: (id: string) =>
    post<Campaign>(`/api/campaigns/${encodeURIComponent(id)}/start`, {}),
};
