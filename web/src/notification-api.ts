import { api } from "./api";
import type { ChannelKind, RuleDraft } from "./notification-state";
export type NotificationChannel = {
  id: string;
  name: string;
  type: ChannelKind;
  enabled: boolean;
  config: Record<string, unknown>;
  secret: string;
  secret_configured: boolean;
  created_at: string;
  updated_at: string;
};
export type NotificationRule = RuleDraft & {
  id: string;
  created_at: string;
  updated_at: string;
};
export type NotificationDelivery = {
  id: string;
  event_type: string;
  rule_id: string;
  rule_name: string;
  channel_id: string;
  channel_name: string;
  channel_type: ChannelKind;
  recipient_masked: string;
  subject: string;
  status: string;
  attempts: number;
  max_attempts: number;
  available_at: string;
  last_error: string;
  created_at: string;
  updated_at: string;
  sent_at?: string;
  cancel_requested?: boolean;
  can_retry: boolean;
  can_cancel: boolean;
};
export type DeliveryDetail = NotificationDelivery & {
  body: string;
  attempt_log: {
    attempt: number;
    status: string;
    code: string;
    detail: string;
    provider_id?: string;
    started_at: string;
    finished_at: string;
  }[];
};
export type DeliveryList = {
  items: NotificationDelivery[];
  total: number;
  page: number;
  page_size: number;
  summary: Record<string, number>;
  as_of: string;
};
export type NotificationPreview = {
  subject: string;
  body: string;
  variables: Record<string, string>;
  sample: boolean;
  recipients_count: number;
};
const id = (value: string) => encodeURIComponent(value);
export const notificationAPI = {
  saveChannel: (body: unknown, channelId?: string) =>
    api<NotificationChannel>(
      `/api/notification-channels${channelId ? "/" + id(channelId) : ""}`,
      { method: channelId ? "PUT" : "POST", body: JSON.stringify(body) },
    ),
  saveRule: (body: unknown, ruleId?: string) =>
    api<NotificationRule>(
      `/api/notification-rules${ruleId ? "/" + id(ruleId) : ""}`,
      { method: ruleId ? "PUT" : "POST", body: JSON.stringify(body) },
    ),
  preview: (body: unknown) =>
    api<NotificationPreview>("/api/notification-rules/preview", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  test: (channelId: string, body: unknown) =>
    api<NotificationDelivery>(
      `/api/notification-channels/${id(channelId)}/test`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  remove: (kind: "channels" | "rules", recordId: string) =>
    api(`/api/notification-${kind}/${id(recordId)}`, { method: "DELETE" }),
  retry: (deliveryId: string, reason: string, confirm: boolean) =>
    api<NotificationDelivery>(
      `/api/notification-deliveries/${id(deliveryId)}/retry`,
      {
        method: "POST",
        body: JSON.stringify({ reason, confirm_duplicate_risk: confirm }),
      },
    ),
  cancel: (deliveryId: string) =>
    api<NotificationDelivery>(
      `/api/notification-deliveries/${id(deliveryId)}/cancel`,
      { method: "POST", body: "{}" },
    ),
};
