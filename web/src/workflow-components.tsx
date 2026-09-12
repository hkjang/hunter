import type { ReactNode } from "react";
import { Button, Group, Paper, Table, Text } from "@mantine/core";
import { IconRefresh } from "@tabler/icons-react";
import { Empty, LoadState } from "./components";
import {
  useListView,
  ListSearch,
  ListPagination,
  SortHeader,
  ListReset,
} from "./use-list-view";
import { ListTools, TableViewport } from "./list-tools";
import type { ListColumn, ListSort } from "./list-view";
import "./workflows.css";
export type WorkflowColumn<T> = ListColumn<T> & {
  render?: (row: T) => ReactNode;
};
export function WorkflowTable<T>({
  rows,
  columns,
  name,
  rowKey,
  loading = false,
  error = "",
  reload,
  empty,
  defaultSort = null,
  extra,
  filters = {},
  filterLabels = {},
  preferenceContext,
}: {
  rows: T[];
  columns: WorkflowColumn<T>[];
  name: string;
  rowKey: (row: T) => string;
  loading?: boolean;
  error?: string;
  reload?: () => void;
  empty?: string;
  defaultSort?: ListSort | null;
  extra?: ReactNode;
  filters?: Record<string, (row: T, value: string) => boolean>;
  filterLabels?: Record<
    string,
    { label: string; value?: (value: string) => string }
  >;
  preferenceContext?: string;
}) {
  const view = useListView({
    rows,
    columns,
    defaultSort,
    filters,
    preferenceContext,
  });
  return (
    <Paper className="data-panel workflow-table">
      <div className="table-toolbar">
        <Group gap="sm" flex={1}>
          <ListSearch view={view} label={`${name} 검색`} />
          <ListReset view={view} />
          {extra}
        </Group>
        {reload && (
          <Button
            variant="default"
            aria-label={`${name} 새로고침`}
            onClick={reload}
            leftSection={<IconRefresh size={16} />}
          >
            새로고침
          </Button>
        )}
      </div>
      <ListTools
        view={view}
        loading={loading}
        failed={!!error}
        filterLabels={filterLabels}
      />
      <LoadState loading={loading} error={error} reload={reload} />
      {!loading && !error && (
        <>
          {view.rows.length ? (
            <TableViewport view={view} label={name}>
              <Table
                verticalSpacing="md"
                horizontalSpacing="lg"
                highlightOnHover
              >
                <Table.Thead>
                  <Table.Tr>
                    {columns.map((column) => (
                      <SortHeader
                        key={column.key}
                        view={view}
                        column={column.key}
                      >
                        {column.label}
                      </SortHeader>
                    ))}
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {view.rows.map((row) => (
                    <Table.Tr key={rowKey(row)}>
                      {columns.map((column) => (
                        <Table.Td key={column.key}>
                          {column.render
                            ? column.render(row)
                            : String(column.value(row) ?? "—")}
                        </Table.Td>
                      ))}
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </TableViewport>
          ) : (
            <Empty
              title={
                view.active
                  ? "조건에 맞는 항목이 없습니다"
                  : `${name} 항목이 없습니다`
              }
              description={
                view.active
                  ? "검색 조건을 바꾸거나 초기화해 주세요."
                  : empty || "관련 자료를 등록하면 이곳에서 확인할 수 있습니다."
              }
            />
          )}
          <ListPagination view={view} />
        </>
      )}
    </Paper>
  );
}
export function Metric({
  label,
  value,
  detail,
}: {
  label: string;
  value: ReactNode;
  detail?: string;
}) {
  return (
    <Paper withBorder p="lg" className="workflow-metric">
      <Text c="dimmed" size="sm">
        {label}
      </Text>
      <Text fw={700} size="xl" mt={8}>
        {value}
      </Text>
      {detail && (
        <Text size="sm" c="dimmed" mt={6}>
          {detail}
        </Text>
      )}
    </Paper>
  );
}
