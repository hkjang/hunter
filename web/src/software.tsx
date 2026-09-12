import { useState } from "react";
import {
  Link,
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import {
  Alert,
  Badge,
  Button,
  Drawer,
  FileInput,
  Group,
  Modal,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Tabs,
  Text,
  TextInput,
} from "@mantine/core";
import {
  IconArrowLeft,
  IconGitCompare,
  IconTrash,
  IconUpload,
} from "@tabler/icons-react";
import { dateText, type Row, useCan, useData, success } from "./api";
import { LoadState, PageHeader, Status } from "./components";
import { FormFeedback } from "./form-feedback";
import {
  Metric,
  WorkflowTable,
  type WorkflowColumn,
} from "./workflow-components";
import {
  workflowAPI,
  type SoftwareComponent,
  type SBOMDocument,
  type SBOMDetail,
  type SBOMComparison,
} from "./workflow-api";
import { parseSBOM, safeListReturn } from "./workflow-state";

function ComponentInfo({ item }: { item: SoftwareComponent }) {
  const can = useCan();
  return (
    <Stack>
      <Text fw={700} size="xl">
        {item.name}
      </Text>
      <dl className="workflow-kv">
        <dt>버전</dt>
        <dd>{item.version || "미지정"}</dd>
        <dt>그룹</dt>
        <dd>{item.group || "—"}</dd>
        <dt>PURL</dt>
        <dd>{item.purl || "식별자 없음"}</dd>
        <dt>문서 내 참조</dt>
        <dd>{item.bom_ref || "—"}</dd>
        <dt>라이선스</dt>
        <dd>{item.licenses?.join(", ") || "정보 없음"}</dd>
      </dl>
      {item.license_review && (
        <Alert color="orange" title="라이선스 검토 대상">
          라이선스가 없거나 별도 확인이 필요한 표현식·사용자 정의 식별자이거나,
          관리자의 검토 목록과 일치합니다. 법적 적합성 판정을 의미하지 않습니다.
        </Alert>
      )}
      <Text fw={600}>영향 서비스</Text>
      {item.services?.length ? (
        item.services.map((service) => (
          <Button
            key={`${service.id}-${service.sbom_id}`}
            component={Link}
            to={`/software/${service.sbom_id}`}
            variant="light"
            justify="flex-start"
          >
            {service.name}
          </Button>
        ))
      ) : (
        <Text c="dimmed">이 문서가 연결된 서비스 범위에서 확인합니다.</Text>
      )}
      {can("findings:read") && (
        <>
          <Text fw={600}>연결된 발견 건</Text>
          {item.findings?.length ? (
            item.findings.map((finding) => (
              <Paper withBorder p="md" key={finding.id}>
                <Link
                  className="workflow-link"
                  to={`/findings?item=${encodeURIComponent(finding.id)}`}
                >
                  {finding.title}
                </Link>
                <Group mt="xs">
                  <Status value={finding.severity} />
                  <Status value={finding.status} />
                </Group>
              </Paper>
            ))
          ) : (
            <Text c="dimmed">
              연결된 발견 건이 없습니다. 취약점이 없음을 보장하는 결과는
              아닙니다.
            </Text>
          )}
        </>
      )}
    </Stack>
  );
}
function componentColumns(
  open: (item: SoftwareComponent) => void,
  findings: boolean,
): WorkflowColumn<SoftwareComponent>[] {
  return [
    {
      key: "name",
      label: "구성요소",
      value: (item) =>
        [item.name, item.group, item.purl].filter(Boolean).join(" "),
      render: (item) => (
        <>
          <Button
            variant="transparent"
            p={0}
            h="auto"
            onClick={() => open(item)}
            styles={{ label: { whiteSpace: "normal", textAlign: "left" } }}
          >
            {item.name}
          </Button>
          <Text size="sm" c="dimmed">
            {item.group || item.type || "그룹 미지정"}
          </Text>
          <Text size="xs" c="dimmed" maw={420}>
            {item.purl || "PURL 미지정"}
          </Text>
        </>
      ),
    },
    {
      key: "version",
      label: "버전",
      value: (item) => item.version || "미지정",
    },
    {
      key: "licenses",
      label: "라이선스",
      value: (item) => item.licenses,
      render: (item) => (
        <Stack gap={5}>
          {item.licenses?.length ? (
            <Text size="sm">{item.licenses.join(", ")}</Text>
          ) : (
            <Text size="sm" c="dimmed">
              정보 없음
            </Text>
          )}
          {item.license_review && (
            <Badge color="orange" variant="light">
              검토 대상
            </Badge>
          )}
        </Stack>
      ),
    },
    {
      key: "dependency_count",
      label: "의존 관계",
      value: (item) => item.dependency_count ?? 0,
    },
    ...(findings
      ? [
          {
            key: "findings_count",
            label: "발견 건",
            value: (item: SoftwareComponent) => item.findings_count ?? 0,
          },
        ]
      : []),
  ];
}
function ComponentList({
  rows,
  loading = false,
  error = "",
  reload,
}: {
  rows: SoftwareComponent[];
  loading?: boolean;
  error?: string;
  reload?: () => void;
}) {
  const can = useCan();
  const [params, setParams] = useSearchParams();
  const location = useLocation();
  const selected = rows.find(
    (item) => `${item.id}:${item.bom_ref}` === params.get("component"),
  );
  function select(item: SoftwareComponent | null) {
    const next = new URLSearchParams(params);
    if (item) next.set("component", `${item.id}:${item.bom_ref}`);
    else next.delete("component");
    setParams(next, { preventScrollReset: true, state: location.state });
  }
  return (
    <>
      <WorkflowTable
        rows={rows}
        columns={componentColumns(select, can("findings:read"))}
        name="구성요소"
        rowKey={(item) => `${item.id}:${item.bom_ref}`}
        loading={loading}
        error={error}
        reload={reload}
        empty="SBOM 파일을 반입하면 이름, 버전, 라이선스와 의존 관계를 검색할 수 있습니다."
      />
      <Drawer
        opened={!!selected}
        onClose={() => select(null)}
        title="구성요소 상세"
        position="right"
        size="lg"
      >
        {selected && <ComponentInfo item={selected} />}
      </Drawer>
    </>
  );
}
export function SoftwarePage() {
  const can = useCan(),
    location = useLocation(),
    navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "components" ? "components" : "documents";
  const serviceId = params.get("service") || "";
  const documents = useData<{ items: SBOMDocument[]; total: number }>(
    `/api/sboms?service_id=${encodeURIComponent(serviceId)}`,
  );
  const components = useData<{
    items: SoftwareComponent[];
    total: number;
    as_of: string;
  }>(
    tab === "components"
      ? `/api/components?service_id=${encodeURIComponent(serviceId)}`
      : null,
  );
  const services = useData<Row[]>("/api/services");
  const [opened, setOpened] = useState(false),
    [service, setService] = useState(""),
    [label, setLabel] = useState(""),
    [file, setFile] = useState<File | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  function change(key: string, value: string | null) {
    const next = new URLSearchParams(params);
    next.delete("page");
    next.delete("component");
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { state: location.state });
  }
  async function upload(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (!service || !file) {
      setError("서비스와 SBOM JSON 파일을 선택하세요.");
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      setError("파일은 8MiB 이하로 선택하세요.");
      return;
    }
    setBusy(true);
    try {
      const doc = await workflowAPI.importSBOM(
        service,
        label.trim(),
        parseSBOM(await file.text()),
      );
      success(
        doc.duplicate
          ? "동일한 파일이 이미 등록되어 기존 문서를 열었습니다."
          : "SBOM 문서를 반입했습니다.",
      );
      setOpened(false);
      navigate(`/software/${doc.id}`, {
        state: { from: location.pathname + location.search },
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const columns: WorkflowColumn<SBOMDocument>[] = [
    {
      key: "label",
      label: "문서 · 서비스",
      value: (item) => [item.label, item.service_name].join(" "),
      render: (item) => (
        <>
          <Link
            className="workflow-link"
            to={`/software/${item.id}`}
            state={{ from: location.pathname + location.search }}
          >
            {item.label || `${item.format} 문서`}
          </Link>
          <Text size="sm" c="dimmed">
            {item.service_name}
          </Text>
        </>
      ),
    },
    {
      key: "format",
      label: "형식",
      value: (item) => `${item.format} ${item.spec_version}`,
    },
    {
      key: "component_count",
      label: "구성요소",
      value: (item) => item.component_count,
    },
    {
      key: "dependency_count",
      label: "의존 관계",
      value: (item) => item.dependency_count,
    },
    {
      key: "created_at",
      label: "반입 시각",
      value: (item) => Date.parse(item.created_at),
      render: (item) => (
        <>
          {dateText(item.created_at)}
          {item.stale && (
            <Badge display="block" mt="xs" variant="light" color="orange">
              갱신 검토
            </Badge>
          )}
        </>
      ),
    },
  ];
  return (
    <>
      <PageHeader
        title="소프트웨어 구성"
        description="서비스의 SBOM과 버전을 보관하고, 공통 구성요소·라이선스·연결된 발견 건을 확인합니다."
        action={
          can("services:write") && (
            <Button
              leftSection={<IconUpload size={18} />}
              onClick={() => {
                setError("");
                setOpened(true);
              }}
            >
              SBOM 반입
            </Button>
          )
        }
      />
      <Alert
        variant="light"
        color="teal"
        mb="lg"
        title="오프라인 소프트웨어 인벤토리"
      >
        CycloneDX 1.4–1.6 및 SPDX 2.2·2.3 JSON의 구성요소·라이선스·의존 관계를
        지원합니다. 반입은 문서 정보 정규화이며, 취약점 데이터 다운로드나 진단을
        자동 실행하지 않습니다.
      </Alert>
      <Select
        label="서비스"
        placeholder="모든 허용 서비스"
        clearable
        searchable
        data={(services.data || []).map((item) => ({
          value: item.id,
          label: item.name,
        }))}
        value={serviceId || null}
        onChange={(value) => change("service", value)}
        maw={420}
      />
      <Tabs
        value={tab}
        onChange={(value) => change("tab", value)}
        className="workflow-tabs"
      >
        <Tabs.List>
          <Tabs.Tab value="documents">SBOM 문서</Tabs.Tab>
          <Tabs.Tab value="components">구성요소 검색</Tabs.Tab>
        </Tabs.List>
      </Tabs>
      {tab === "components" && (
        <Text size="sm" c="dimmed" mb="md">
          구성요소 검색은 서비스별 가장 최근에 반입한 SBOM을 기준으로 합니다.
          이전 버전은 SBOM 문서에서 확인하세요.
        </Text>
      )}
      {tab === "components" ? (
        <ComponentList
          rows={components.data?.items || []}
          loading={components.loading}
          error={components.error}
          reload={components.reload}
        />
      ) : (
        <WorkflowTable
          rows={documents.data?.items || []}
          columns={columns}
          name="SBOM 문서"
          rowKey={(item) => item.id}
          loading={documents.loading}
          error={documents.error}
          reload={documents.reload}
          defaultSort={{ key: "created_at", direction: "desc" }}
          empty="서비스를 등록한 뒤 해당 서비스의 SBOM JSON 파일을 반입하세요."
        />
      )}
      <Modal
        opened={opened}
        onClose={() => {
          if (!busy) setOpened(false);
        }}
        title="SBOM 파일 반입"
        size="lg"
      >
        <form onSubmit={upload}>
          <Stack>
            <FormFeedback error={error} />
            <Select
              required
              label="대상 서비스"
              placeholder="서비스 선택"
              searchable
              value={service || null}
              onChange={(value) => setService(value || "")}
              data={(services.data || []).map((item) => ({
                value: item.id,
                label: item.name,
              }))}
              disabled={busy}
            />
            <TextInput
              label="문서 이름 · 배포 버전"
              placeholder="예: 결제 서비스 2.4.0"
              value={label}
              onChange={(event) => setLabel(event.currentTarget.value)}
              maxLength={200}
              disabled={busy}
            />
            <FileInput
              required
              label="SBOM JSON 파일"
              placeholder="파일 선택"
              accept=".json,application/json"
              value={file}
              onChange={setFile}
              disabled={busy}
              description="최대 8MiB. 서버에서 형식과 참조 관계를 검증합니다."
            />
            <Group justify="flex-end">
              <Button
                variant="default"
                onClick={() => setOpened(false)}
                disabled={busy}
              >
                취소
              </Button>
              <Button type="submit" loading={busy}>
                검증하고 반입
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </>
  );
}
function SBOMCompare({
  current,
  documents,
}: {
  current: SBOMDetail;
  documents: SBOMDocument[];
}) {
  const [params, setParams] = useSearchParams();
  const baseline = params.get("baseline") || "";
  const location = useLocation();
  const result = useData<SBOMComparison>(
    baseline
      ? `/api/sboms/${current.id}/compare?baseline=${encodeURIComponent(baseline)}`
      : null,
  );
  return (
    <Stack>
      <Select
        label="기준 SBOM"
        placeholder="같은 서비스의 이전 문서 선택"
        value={baseline || null}
        clearable
        searchable
        data={documents
          .filter(
            (item) =>
              item.id !== current.id && item.service_id === current.service_id,
          )
          .map((item) => ({
            value: item.id,
            label: `${item.label || item.format} · ${dateText(item.created_at)}`,
          }))}
        onChange={(value) => {
          const next = new URLSearchParams(params);
          value ? next.set("baseline", value) : next.delete("baseline");
          setParams(next, { state: location.state });
        }}
      />
      <Text size="sm" c="dimmed">
        기준 문서에서 현재 문서로 바뀐 구성 정보를 비교합니다. 제거된 구성요소가
        연결된 발견 건의 해결을 의미하지 않습니다.
      </Text>
      {baseline && (
        <>
          <LoadState
            loading={result.loading}
            error={result.error}
            reload={result.reload}
          />
          {result.data && !result.loading && !result.error && (
            <>
              <SimpleGrid cols={{ base: 3 }}>
                <Metric label="추가" value={result.data.added.length} />
                <Metric label="제거" value={result.data.removed.length} />
                <Metric label="변경" value={result.data.changed.length} />
              </SimpleGrid>
              <WorkflowTable
                name="구성 변경"
                rowKey={(item) => item.key}
                rows={[
                  ...result.data.added.map((item, i) => ({
                    key: `add-${i}`,
                    kind: "추가",
                    name: item.name,
                    before: "—",
                    after: item.version || "미지정",
                  })),
                  ...result.data.removed.map((item, i) => ({
                    key: `remove-${i}`,
                    kind: "제거",
                    name: item.name,
                    before: item.version || "미지정",
                    after: "—",
                  })),
                  ...result.data.changed.map((item, i) => ({
                    key: `change-${i}`,
                    kind: "변경",
                    name: item.after.name,
                    before: `${item.before.version || "미지정"} · ${(item.before.licenses || []).join(", ") || "라이선스 정보 없음"}`,
                    after: `${item.after.version || "미지정"} · ${(item.after.licenses || []).join(", ") || "라이선스 정보 없음"}`,
                  })),
                ]}
                columns={[
                  {
                    key: "name",
                    label: "구성요소",
                    value: (item) => item.name,
                  },
                  { key: "kind", label: "변경", value: (item) => item.kind },
                  {
                    key: "before",
                    label: "기준 구성",
                    value: (item) => item.before,
                  },
                  {
                    key: "after",
                    label: "현재 구성",
                    value: (item) => item.after,
                  },
                ]}
                empty="두 문서 사이에 비교 가능한 구성 변경이 없습니다."
              />
            </>
          )}
        </>
      )}
    </Stack>
  );
}
export function SoftwareDetailPage() {
  const { id = "" } = useParams();
  return <SoftwareDetail key={id} id={id} />;
}
function SoftwareDetail({ id }: { id: string }) {
  const result = useData<SBOMDetail>(`/api/sboms/${encodeURIComponent(id)}`);
  const docs = useData<{ items: SBOMDocument[]; total: number }>(
    result.data
      ? `/api/sboms?service_id=${encodeURIComponent(result.data.service_id)}`
      : null,
  );
  const can = useCan(),
    location = useLocation(),
    navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = ["components", "dependencies", "compare", "metadata"].includes(
    params.get("tab") || "",
  )
    ? params.get("tab")!
    : "components";
  const [remove, setRemove] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const doc = result.data;
  const componentNames = new Map(
    (doc?.components || []).map((item) => [item.bom_ref, item.name]),
  );
  async function removeDocument() {
    setBusy(true);
    setError("");
    try {
      await workflowAPI.deleteSBOM(id);
      success("SBOM 문서를 삭제했습니다.");
      navigate(safeListReturn(location.state?.from, "/software"));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Button
        component={Link}
        to={safeListReturn(location.state?.from, "/software")}
        variant="subtle"
        mb="md"
        leftSection={<IconArrowLeft size={17} />}
      >
        소프트웨어 구성으로
      </Button>
      <PageHeader
        title={doc?.label || "SBOM 상세"}
        description={
          doc
            ? `${doc.service_name} · ${doc.format} ${doc.spec_version} · ${dateText(doc.created_at)} 반입`
            : "반입한 문서의 구성 정보를 확인합니다."
        }
        action={
          can("services:write") &&
          doc && (
            <Button
              color="red"
              variant="light"
              leftSection={<IconTrash size={16} />}
              onClick={() => setRemove(true)}
            >
              문서 삭제
            </Button>
          )
        }
      />
      <LoadState
        loading={result.loading}
        error={result.error}
        reload={result.reload}
      />
      {doc && !result.loading && !result.error && (
        <>
          <>
            {doc.warnings?.length ? (
              <Alert color="orange" title="반입 시 확인 사항" mb="lg">
                <Stack gap="xs">
                  {doc.warnings.map((warning, i) => (
                    <Text key={i}>{warning}</Text>
                  ))}
                </Stack>
              </Alert>
            ) : null}
          </>
          <SimpleGrid cols={{ base: 2, md: 3 }}>
            <Metric label="구성요소" value={doc.component_count} />
            <Metric label="의존 관계" value={doc.dependency_count} />
            <Metric
              label="문서 상태"
              value={doc.stale ? "갱신 검토" : "보관 중"}
              detail="관리자 기준으로 문서 경과일을 확인합니다."
            />
          </SimpleGrid>
          <Tabs
            value={tab}
            className="workflow-tabs"
            onChange={(value) => {
              const next = new URLSearchParams(params);
              next.set("tab", value || "components");
              next.delete("page");
              next.delete("component");
              setParams(next, { state: location.state });
            }}
          >
            <Tabs.List>
              <Tabs.Tab value="components">구성요소</Tabs.Tab>
              <Tabs.Tab value="dependencies">의존 관계</Tabs.Tab>
              <Tabs.Tab
                value="compare"
                leftSection={<IconGitCompare size={16} />}
              >
                버전 비교
              </Tabs.Tab>
              <Tabs.Tab value="metadata">문서 정보</Tabs.Tab>
            </Tabs.List>
          </Tabs>
          {tab === "components" && (
            <ComponentList rows={doc.components || []} />
          )}
          {tab === "dependencies" && (
            <WorkflowTable
              name="의존 관계"
              rows={(doc.dependencies || []).flatMap((item) =>
                (item.dependsOn || item.depends_on || []).map((target) => ({
                  key: `${item.ref}-${target}`,
                  from: componentNames.get(item.ref) || item.ref,
                  to: componentNames.get(target) || target,
                })),
              )}
              rowKey={(item) => item.key}
              columns={[
                {
                  key: "from",
                  label: "상위 구성요소",
                  value: (item) => item.from,
                },
                { key: "to", label: "의존 대상", value: (item) => item.to },
              ]}
              empty="문서에 정규화 가능한 의존 관계가 없습니다."
            />
          )}
          {tab === "compare" && (
            <SBOMCompare current={doc} documents={docs.data?.items || []} />
          )}
          {tab === "metadata" && (
            <Paper className="workflow-panel">
              <dl className="workflow-kv">
                <dt>형식</dt>
                <dd>
                  {doc.format} {doc.spec_version}
                </dd>
                <dt>서비스</dt>
                <dd>{doc.service_name}</dd>
                <dt>반입 시각</dt>
                <dd>{dateText(doc.created_at)}</dd>
                <dt>SHA-256</dt>
                <dd>{doc.sha256}</dd>
                <dt>문서 식별자</dt>
                <dd>{doc.id}</dd>
              </dl>
            </Paper>
          )}
        </>
      )}
      <Modal
        opened={remove}
        onClose={() => {
          if (!busy) setRemove(false);
        }}
        title="SBOM 문서 삭제"
      >
        <Stack>
          <FormFeedback error={error} />
          <Text>
            ‘{doc?.label || "이 문서"}’와 연결된 구성 정보를 삭제합니다. 기존
            발견 건은 개별 이력으로 유지됩니다.
          </Text>
          <Group justify="flex-end">
            <Button
              variant="default"
              onClick={() => setRemove(false)}
              disabled={busy}
            >
              취소
            </Button>
            <Button color="red" loading={busy} onClick={removeDocument}>
              문서 삭제
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
