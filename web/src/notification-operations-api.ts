import { api } from "./api";
export type ChannelTracking = {
  enabled: boolean;
  endpoint: string;
  method: "GET" | "POST";
  query: Record<string, unknown>;
  body_template: Record<string, unknown>;
  state_path: string;
  delivered_values: string[];
  failed_values: string[];
  pending_values: string[];
  poll_interval_seconds: number;
  max_checks: number;
  callback_enabled: boolean;
  callback_secret: string;
  callback_secret_configured: boolean;
  clear_callback_secret?: boolean;
};
export type ChannelOperation = {
  channel_id: string;
  tracking: ChannelTracking;
  fallback_channel_id: string;
  protection: {
    enabled: boolean;
    consecutive_failures: number;
    open_seconds: number;
    min_interval_seconds: number;
  };
};
export type NotificationOperationsDocument = {
  config: { enabled: boolean; channels: ChannelOperation[] };
  updated_at: string;
};
export type OperationCircuit = {
  channel_id: string;
  state: string;
  consecutive_failures: number;
  open_until: string;
  next_allowed_at: string;
  updated_at: string;
};
export type OperationReceipt = {
  delivery_id: string;
  channel_id: string;
  state: string;
  checks: number;
  provider_id: string;
  last_code: string;
  next_check_at: string;
  updated_at: string;
};
export type OperationsStatus = {
  channels: OperationCircuit[];
  receipts: OperationReceipt[];
  fallbacks: { parent_id: string; child_id: string; created_at: string }[];
};
export function channelOperationDefaults(channelId: string): ChannelOperation {
  return {
    channel_id: channelId,
    tracking: {
      enabled: false,
      endpoint: "",
      method: "GET",
      query: {},
      body_template: {},
      state_path: "status",
      delivered_values: ["delivered"],
      failed_values: ["failed"],
      pending_values: ["pending"],
      poll_interval_seconds: 60,
      max_checks: 10,
      callback_enabled: false,
      callback_secret: "",
      callback_secret_configured: false,
    },
    fallback_channel_id: "",
    protection: {
      enabled: false,
      consecutive_failures: 5,
      open_seconds: 300,
      min_interval_seconds: 1,
    },
  };
}
export const operationsAPI = {
  config: () =>
    api<NotificationOperationsDocument>("/api/notification-operations"),
  save: (body: unknown) =>
    api<NotificationOperationsDocument>("/api/notification-operations", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  reset: (id: string, reason: string) =>
    api(
      `/api/notification-operations/channels/${encodeURIComponent(id)}/reset`,
      { method: "POST", body: JSON.stringify({ reason }) },
    ),
  refresh: (id: string) =>
    api(
      `/api/notification-operations/receipts/${encodeURIComponent(id)}/refresh`,
      { method: "POST", body: "{}" },
    ),
};
export function operationsBody(
  document: NotificationOperationsDocument,
  revision: string,
) {
  if (!revision)
    throw new Error("설정 기준 시각이 없습니다. 최신 자료를 다시 불러오세요.");
  return {
    config: {
      enabled: document.config.enabled,
      channels: document.config.channels.map((row) => ({
        channel_id: row.channel_id,
        fallback_channel_id: row.fallback_channel_id,
        tracking: {
          enabled: row.tracking.enabled,
          endpoint: row.tracking.endpoint,
          method: row.tracking.method,
          query: row.tracking.query,
          body_template: row.tracking.body_template,
          state_path: row.tracking.state_path,
          delivered_values: row.tracking.delivered_values,
          failed_values: row.tracking.failed_values,
          pending_values: row.tracking.pending_values,
          poll_interval_seconds: row.tracking.poll_interval_seconds,
          max_checks: row.tracking.max_checks,
          callback_enabled: row.tracking.callback_enabled,
          ...(row.tracking.clear_callback_secret
            ? { clear_callback_secret: true }
            : row.tracking.callback_secret
              ? { callback_secret: row.tracking.callback_secret }
              : {}),
        },
        protection: {
          enabled: row.protection.enabled,
          consecutive_failures: row.protection.consecutive_failures,
          open_seconds: row.protection.open_seconds,
          min_interval_seconds: row.protection.min_interval_seconds,
        },
      })),
    },
    expected_updated_at: revision,
  };
}
