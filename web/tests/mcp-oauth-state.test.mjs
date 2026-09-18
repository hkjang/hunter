import assert from "node:assert/strict";
import test from "node:test";
import {
  mcpMetadataURL,
  mcpOAuthValues,
  mcpResourceURL,
} from "../src/mcp-oauth-state.ts";

test("a missing group is off with the read scopes, and stored values win", () => {
  assert.deepEqual(mcpOAuthValues(undefined), {
    oauth: {
      enabled: false,
      resource: "",
      audience: [],
      scopes: ["services:read", "findings:read", "scans:read"],
    },
  });
  assert.deepEqual(
    mcpOAuthValues({
      oauth: {
        enabled: true,
        resource: " https://hunter.intra/mcp ",
        audience: "claude-mcp  cursor claude-mcp",
        scopes: ["services:read", 7, "services:read"],
      },
    }),
    {
      oauth: {
        enabled: true,
        resource: "https://hunter.intra/mcp",
        audience: ["claude-mcp", "cursor"],
        scopes: ["services:read"],
      },
    },
  );
  // An explicit empty scope list stays empty so the server can refuse the switch-on.
  assert.deepEqual(mcpOAuthValues({ oauth: { scopes: [] } }).oauth.scopes, []);
  assert.equal(mcpOAuthValues({ oauth: { enabled: "true" } }).oauth.enabled, false);
});

test("resource and metadata addresses derive from the public URL unless overridden", () => {
  assert.equal(
    mcpResourceURL("https://hunter.intra/", ""),
    "https://hunter.intra/mcp",
  );
  assert.equal(
    mcpResourceURL("https://hunter.intra", " https://mcp.hunter.intra/mcp "),
    "https://mcp.hunter.intra/mcp",
  );
  assert.equal(
    mcpMetadataURL("https://hunter.intra//"),
    "https://hunter.intra/.well-known/oauth-protected-resource/mcp",
  );
});
