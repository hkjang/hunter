import type { ReactNode } from "react";
import {
  Alert,
  Badge,
  Button,
  Center,
  Group,
  Loader,
  Paper,
  Stack,
  Text,
  Title,
} from "@mantine/core";
import {
  IconArrowUpRight,
  IconDatabaseOff,
  IconRefresh,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { colors, label } from "./api";
export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow || "SECURITY WORKSPACE"}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-actions">{action}</div>}
    </div>
  );
}
export function Empty({
  title = "아직 등록된 항목이 없습니다",
  description = "새 항목을 등록하면 이곳에서 현황을 확인할 수 있습니다.",
  action,
  icon,
}: {
  title?: string;
  description?: string;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        {icon || <IconDatabaseOff size={28} stroke={1.5} />}
      </div>
      <Title order={3} size={19}>
        {title}
      </Title>
      <Text c="dimmed" maw={500} ta="center" size="sm">
        {description}
      </Text>
      {action}
    </div>
  );
}
export function LoadState({
  loading,
  error,
  reload,
}: {
  loading: boolean;
  error: string;
  reload?: () => void;
}) {
  if (loading)
    return (
      <Center p={70}>
        <Stack align="center" gap="sm">
          <Loader color="teal" size="sm" />
          <Text c="dimmed" size="sm">
            최신 정보를 불러오고 있습니다
          </Text>
        </Stack>
      </Center>
    );
  if (error)
    return (
      <Alert
        color="red"
        title="정보를 불러오지 못했습니다"
        icon={<IconAlertTriangle />}
      >
        {error}
        {reload && (
          <Button
            mt="md"
            variant="light"
            color="red"
            size="sm"
            onClick={reload}
            leftSection={<IconRefresh size={16} />}
          >
            다시 시도
          </Button>
        )}
      </Alert>
    );
  return null;
}
export function Status({ value }: { value: any }) {
  return (
    <Badge
      variant="light"
      color={colors[String(value)] || "gray"}
      size="lg"
      fw={500}
      radius="sm"
    >
      {label(value)}
    </Badge>
  );
}
export function Stat({
  label: caption,
  value,
  unit,
  icon,
  detail,
  accent,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  icon: ReactNode;
  detail: string;
  accent?: boolean;
}) {
  return (
    <Paper className={`stat-card ${accent ? "stat-accent" : ""}`}>
      <Group justify="space-between">
        <Text size="sm" fw={500}>
          {caption}
        </Text>
        <span className="stat-icon">{icon}</span>
      </Group>
      <div className="stat-value">
        {value}
        <span>{unit}</span>
      </div>
      <div className="stat-detail">
        {accent && <span className="pulse-dot" />}
        {detail}
      </div>
    </Paper>
  );
}
export function SectionTitle({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="section-title">
      <div>
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  );
}
export function SmallLink({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <Button
      variant="subtle"
      size="compact-sm"
      color="gray"
      rightSection={<IconArrowUpRight size={16} />}
      onClick={onClick}
    >
      {children}
    </Button>
  );
}
