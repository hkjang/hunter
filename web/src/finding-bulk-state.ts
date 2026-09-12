export type BulkFindingPatch = {
  assignee?: string;
  due_date?: string | null;
  status?: string;
};
export const bulkStatuses = [
  "candidate",
  "confirmed",
  "in_progress",
  "retest",
  "inconclusive",
];
export function findingBulkPatch(input: {
  changeAssignee: boolean;
  assignee: string;
  changeDue: boolean;
  clearDue: boolean;
  due: string;
  changeStatus: boolean;
  status: string;
}): BulkFindingPatch {
  const patch: BulkFindingPatch = {};
  if (input.changeAssignee) {
    if (/[\u0000-\u001f\u007f-\u009f]/u.test(input.assignee))
      throw new Error("담당자에는 줄바꿈이나 제어 문자를 입력할 수 없습니다.");
    if (new TextEncoder().encode(input.assignee.trim()).length > 200)
      throw new Error("담당자는 UTF-8 기준 200바이트까지 입력할 수 있습니다.");
    patch.assignee = input.assignee.trim();
  }
  if (input.changeDue) {
    if (input.clearDue) patch.due_date = null;
    else {
      const date = new Date(input.due);
      if (!input.due || !Number.isFinite(date.getTime()))
        throw new Error(
          "유효한 조치 기한을 입력하거나 직접 지정 기한 해제를 선택하세요.",
        );
      patch.due_date = date.toISOString();
    }
  }
  if (input.changeStatus) {
    if (!bulkStatuses.includes(input.status))
      throw new Error("변경할 상태를 선택하세요.");
    patch.status = input.status;
  }
  if (!Object.keys(patch).length)
    throw new Error("변경할 항목을 하나 이상 선택하세요.");
  return patch;
}
