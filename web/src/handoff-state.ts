// Sending an agent run report to another in-house service (HANDOFF-STANDARD.md).
// Hunter only sends markdown; the receiving service opens /handoff in a new window
// and collects the document from Hunter with a one-time claim.
export const handoffFormat = "markdown";
export const handoffFormats = [
  "markdown",
  "docx",
  "csv",
  "xlsx",
  "txt",
  "pptx",
] as const;
export type HandoffFormat = (typeof handoffFormats)[number];
export type HandoffTarget = {
  name: string;
  origin: string;
  formats: HandoffFormat[];
};
export type HandoffTargets = {
  targets: { name: string; origin: string }[];
  source: string;
  format: string;
};
export type HandoffClaim = {
  claim: string;
  source: string;
  filename: string;
  content_type: string;
  bytes: number;
  expires_at: string;
};
export function handoffClaimRequest(runId: string) {
  return { resource: runId, format: handoffFormat };
}
// The receiving side's address: origin/handoff?source=…&claim=…. Anything that is
// not a bare http(s) origin from the server's list is refused rather than opened.
export function handoffOpenURL(origin: string, source: string, claim: string) {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error("보낼 곳 주소가 올바르지 않습니다.");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.pathname !== "/" && parsed.pathname !== "")
  )
    throw new Error("보낼 곳 주소는 http(s) 오리진이어야 합니다.");
  if (!source || !claim) throw new Error("표를 받지 못했습니다.");
  return `${parsed.origin}/handoff?source=${encodeURIComponent(source)}&claim=${encodeURIComponent(claim)}`;
}
// Targets the settings screen edits: blank rows are dropped so an administrator
// can add a row and leave without it becoming a validation error.
export function handoffTargetsPayload(targets: HandoffTarget[]) {
  return {
    targets: targets
      .filter(
        (t) => t.name.trim() || t.origin.trim() || (t.formats || []).length,
      )
      .map((t) => ({
        name: t.name.trim(),
        origin: t.origin.trim(),
        formats: t.formats || [],
      })),
  };
}
export function emptyHandoffTarget(): HandoffTarget {
  return { name: "", origin: "", formats: [] };
}
