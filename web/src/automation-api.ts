import { api } from "./api";
import type { NotificationAutomationConfig } from "./automation-state";
export type NotificationAutomationDocument = {
  config: NotificationAutomationConfig;
  updated_at: string;
};
export type Simulation = {
  id: string;
  created_at: string;
  rule_id: string;
  scanned: number;
  matched: number;
  recipient_count: number;
  estimated_deliveries: number;
  truncated: boolean;
  reasons: { code: string; count: number }[];
  sample: {
    event_id: string | number;
    entity_id: string;
    matched: boolean;
    recipient_count: number;
    reason: string;
  }[];
};
export type PersonalNotification = {
  id: string;
  subject: string;
  body: string;
  status: string;
  event_type: string;
  entity_id: string;
  service_id: string;
  created_at: string;
  acknowledged_at?: string;
  ack_due_at?: string;
  can_ack: boolean;
};
export type PersonalNotificationPage = {
  items: PersonalNotification[];
  total: number;
  page: number;
  page_size: number;
};
export const automationAPI = {
  notificationConfig: () =>
    api<NotificationAutomationDocument>("/api/notification-automation"),
  saveNotificationConfig: (body: unknown) =>
    api<NotificationAutomationDocument>("/api/notification-automation", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  simulate: (body: unknown) =>
    api<Simulation>("/api/notification-automation/simulate", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  acknowledge: (id: string) =>
    api<{ acknowledged_at: string }>(
      `/api/my-notifications/${encodeURIComponent(id)}/ack`,
      { method: "POST", body: "{}" },
    ),
  holdDelivery: (id: string, body: { hold: boolean; reason: string }) =>
    api<{ hold: boolean }>(
      `/api/notification-deliveries/${encodeURIComponent(id)}/hold`,
      { method: "POST", body: JSON.stringify(body) },
    ),
};
