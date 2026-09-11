/** Agent transcripts include service, finding, and scan evidence. */
export const agentReadScopes = [
  "agents:read",
  "services:read",
  "findings:read",
  "scans:read",
] as const;
export function canReadAgents(can: (scope: string) => boolean | undefined) {
  return agentReadScopes.every((scope) => can(scope));
}
export function canStartAgents(can: (scope: string) => boolean | undefined) {
  return canReadAgents(can) && !!can("agents:write") && !!can("ai:use");
}
