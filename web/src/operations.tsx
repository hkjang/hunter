import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Alert,
  Badge,
  Button,
  FileInput,
  Group,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { IconCheck, IconRefresh, IconUpload } from "@tabler/icons-react";
import { dateText, fullDate, useData } from "./api";
import { LoadState, PageHeader } from "./components";
import { FormFeedback } from "./form-feedback";
import { Metric } from "./workflow-components";
import {
  workflowAPI,
  type IntelligenceState,
  type IntelImportResult,
  type OperationsState,
} from "./workflow-api";

export function IntelligencePage() {
  const result = useData<IntelligenceState>("/api/intelligence");
  const [format, setFormat] = useState("kev"),
    [sourceDate, setSourceDate] = useState(""),
    [file, setFile] = useState<File | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [saved, setSaved] = useState<IntelImportResult | null>(null);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setSaved(null);
    if (!file || !sourceDate) {
      setError("반입 파일과 자료의 기준일을 입력하세요.");
      return;
    }
    const limit = result.data?.max_content_bytes || 33554432;
    if (file.size > limit) {
      setError(`파일은 ${Math.floor(limit / 1048576)}MiB 이하로 선택하세요.`);
      return;
    }
    setBusy(true);
    try {
      const value = await workflowAPI.importIntel(
        format,
        await file.text(),
        sourceDate,
      );
      setSaved(value);
      setFile(null);
      await result.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        eyebrow="ADMINISTRATION"
        title="위협 정보 반입"
        description="승인된 KEV·EPSS 파일을 반입하고, 자료의 기준일과 무결성 정보를 확인합니다."
        action={
          <Button
            variant="default"
            onClick={result.reload}
            leftSection={<IconRefresh size={17} />}
          >
            새로고침
          </Button>
        }
      />
      <Alert title="외부 연결 없이 파일로 갱신합니다" color="teal" mb="xl">
        이 화면은 CISA KEV 목록과 FIRST EPSS 자료를 다운로드하지 않습니다.
        조직의 반입 절차를 거친 원본 파일을 선택하세요. 같은 형식의 자료는 새
        데이터셋으로 교체됩니다.
      </Alert>
      <LoadState
        loading={result.loading}
        error={result.error}
        reload={result.reload}
      />
      {result.data && !result.loading && !result.error && (
        <>
          <SimpleGrid cols={{ base: 1, md: 2 }} mb="xl">
            {result.data.datasets.map((dataset) => (
              <Paper key={dataset.format} className="workflow-panel">
                <Group justify="space-between">
                  <Text fw={700} size="lg">
                    {dataset.format === "kev"
                      ? "KEV · 실제 악용 목록"
                      : "EPSS · 악용 가능성 점수"}
                  </Text>
                  <Badge
                    color={
                      !dataset.configured
                        ? "gray"
                        : dataset.stale
                          ? "orange"
                          : "teal"
                    }
                    variant="light"
                  >
                    {!dataset.configured
                      ? "미반입"
                      : dataset.stale
                        ? "갱신 필요"
                        : "반입됨"}
                  </Badge>
                </Group>
                <dl className="workflow-kv">
                  <dt>항목 수</dt>
                  <dd>{dataset.entry_count.toLocaleString()}개</dd>
                  <dt>자료 기준일</dt>
                  <dd>{fullDate(dataset.source_date)}</dd>
                  <dt>반입 시각</dt>
                  <dd>{dateText(dataset.imported_at)}</dd>
                  <dt>SHA-256</dt>
                  <dd>{dataset.sha256 || "—"}</dd>
                </dl>
              </Paper>
            ))}
          </SimpleGrid>
          <Paper className="workflow-panel">
            <form onSubmit={submit}>
              <Stack>
                <Text fw={700} size="lg">
                  자료 반입
                </Text>
                <FormFeedback error={error} />
                {saved && (
                  <Alert
                    color="teal"
                    icon={<IconCheck size={18} />}
                    title="반입 완료"
                  >
                    <Text>
                      {saved.entry_count.toLocaleString()}개 항목 · 기준일{" "}
                      {saved.source_date}
                    </Text>
                    <Text size="sm" mt="xs">
                      {saved.message}
                    </Text>
                  </Alert>
                )}
                <SimpleGrid cols={{ base: 1, sm: 2 }}>
                  <Select
                    label="자료 형식"
                    allowDeselect={false}
                    value={format}
                    onChange={(value) => {
                      setFormat(value || "kev");
                      setFile(null);
                    }}
                    data={[
                      { value: "kev", label: "CISA KEV JSON" },
                      { value: "epss", label: "FIRST EPSS CSV" },
                    ]}
                    disabled={busy}
                  />
                  <TextInput
                    required
                    type="date"
                    label="자료 기준일"
                    description="파일에 표시된 자료의 기준일을 입력하세요."
                    value={sourceDate}
                    onChange={(event) =>
                      setSourceDate(event.currentTarget.value)
                    }
                    disabled={busy}
                  />
                </SimpleGrid>
                <FileInput
                  required
                  label="반입 파일"
                  accept={
                    format === "kev"
                      ? ".json,application/json"
                      : ".csv,text/csv,text/plain"
                  }
                  placeholder={
                    format === "kev"
                      ? "KEV JSON 파일 선택"
                      : "압축을 해제한 EPSS CSV 파일 선택"
                  }
                  value={file}
                  onChange={setFile}
                  disabled={busy}
                  description={`최대 ${Math.floor(result.data.max_content_bytes / 1048576)}MiB · ${result.data.max_entries.toLocaleString()}개 항목. 압축 파일은 먼저 해제하세요.`}
                />
                <Text size="sm" c="dimmed">
                  자료가 없으면 위협 정보는 미확인으로 표시됩니다. 현재 갱신
                  판단 기준은 {result.data.stale_after_days}일이며 조치 우선순위
                  설정에서 변경할 수 있습니다.
                </Text>
                <Group justify="space-between">
                  <Button
                    component={Link}
                    to="/admin/settings?tab=risk"
                    variant="subtle"
                  >
                    우선순위 설정
                  </Button>
                  <Button
                    type="submit"
                    loading={busy}
                    leftSection={<IconUpload size={17} />}
                  >
                    검증하고 교체
                  </Button>
                </Group>
              </Stack>
            </form>
          </Paper>
        </>
      )}
    </>
  );
}
export function OperationsPage() {
  const result = useData<OperationsState>("/api/operations");
  const data = result.data;
  return (
    <>
      <PageHeader
        eyebrow="ADMINISTRATION"
        title="운영 점검"
        description="저장된 서비스 상태와 실행 대기열, 워커·보안 설정을 한곳에서 확인합니다."
        action={
          <Button
            variant="default"
            onClick={result.reload}
            leftSection={<IconRefresh size={17} />}
          >
            새로고침
          </Button>
        }
      />
      <Alert color="teal" mb="xl" title="내부 상태 기준 점검">
        외부 사이트나 진단 대상에 점검 요청을 보내지 않습니다. 아래 결과는 조회
        시점의 설정과 데이터베이스 상태를 기준으로 합니다.
      </Alert>
      <LoadState
        loading={result.loading}
        error={result.error}
        reload={result.reload}
      />
      {data && !result.loading && !result.error && (
        <>
          <SimpleGrid cols={{ base: 2, md: 4 }} mb="xl">
            <Metric label="대기 작업" value={data.counts.queued_jobs} />
            <Metric label="실행 중" value={data.counts.running_jobs} />
            <Metric label="응답 지연 워커" value={data.counts.stale_workers} />
            <Metric label="SBOM 문서" value={data.counts.sboms} />
          </SimpleGrid>
          <Paper className="workflow-panel">
            <Group justify="space-between" mb="md">
              <Text fw={700} size="lg">
                점검 결과
              </Text>
              <Text size="sm" c="dimmed">
                hunter v{data.version} · {dateText(data.as_of)}
              </Text>
            </Group>
            <Stack>
              {data.checks.map((check) => (
                <Alert
                  key={check.id}
                  color={
                    { ok: "teal", warning: "orange", error: "red" }[
                      check.status
                    ]
                  }
                  title={
                    <Group gap="sm">
                      <span>{check.title}</span>
                      <Badge
                        variant="light"
                        color={
                          { ok: "teal", warning: "orange", error: "red" }[
                            check.status
                          ]
                        }
                      >
                        {
                          {
                            ok: "정상",
                            warning: "확인 필요",
                            error: "조치 필요",
                          }[check.status]
                        }
                      </Badge>
                    </Group>
                  }
                >
                  <Text className="workflow-pre">{check.detail}</Text>
                </Alert>
              ))}
            </Stack>
            <Group mt="xl">
              <Button variant="light" component={Link} to="/admin/workers">
                워커 관리
              </Button>
              <Button variant="light" component={Link} to="/admin/settings">
                서비스 설정
              </Button>
              <Button variant="light" component={Link} to="/admin/intelligence">
                위협 정보 반입
              </Button>
            </Group>
          </Paper>
        </>
      )}
    </>
  );
}
