// MCP over SSO (MCP-OAUTH-STANDARD.md): the settings group `mcp` holds one
// object, `oauth`, so the administrator's keys read mcp.oauth.enabled,
// mcp.oauth.resource, mcp.oauth.audience and mcp.oauth.scopes as the standard
// names them. Audience and scopes travel as arrays; the server also accepts
// the standard's space-separated form.
export type McpOAuth = {
  enabled: boolean;
  resource: string;
  audience: string[];
  scopes: string[];
};
export const mcpOAuthDefaultScopes = [
  "services:read",
  "findings:read",
  "scans:read",
];
function list(value: unknown): string[] {
  const items = Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string")
    : typeof value === "string"
      ? value.split(/\s+/)
      : [];
  const out: string[] = [];
  for (const item of items.map((v) => v.trim()))
    if (item && !out.includes(item)) out.push(item);
  return out;
}
/** Server or draft values → the form's shape, defaults for anything missing. */
export function mcpOAuthValues(data?: Record<string, unknown>): {
  oauth: McpOAuth;
} {
  const raw = (data?.oauth || {}) as Record<string, unknown>;
  return {
    oauth: {
      enabled: raw.enabled === true,
      resource: typeof raw.resource === "string" ? raw.resource.trim() : "",
      audience: list(raw.audience),
      scopes: "scopes" in raw ? list(raw.scopes) : [...mcpOAuthDefaultScopes],
    },
  };
}
/** The identifier a token's aud must name: the override, else public URL + /mcp. */
export function mcpResourceURL(publicURL: string, resource: string) {
  const custom = resource.trim();
  if (custom) return custom;
  return `${publicURL.trim().replace(/\/+$/, "")}/mcp`;
}
/** Where a refused client is sent to learn the above; always under the public URL. */
export function mcpMetadataURL(publicURL: string) {
  return `${publicURL.trim().replace(/\/+$/, "")}/.well-known/oauth-protected-resource/mcp`;
}
