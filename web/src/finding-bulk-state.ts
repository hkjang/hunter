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
    // Counted on the trimmed string because that is the value submitted below,
    // and internal/app/finding_bulk.go validateFindingBulk measures len(name) on
    // the string it receives. Counting the raw input would reject names the
    // server stores, such as one pasted out of a table with trailing spaces.
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
      const wire = date.toISOString();
      // Checked on the string submitted below, not on input.due: toISOString
      // emits ECMA-262's expanded year (+YYYYYY / -YYYYYY) once the UTC instant
      // leaves 0000-9999, and internal/app/finding_ops.go
      // validateFindingOpsResource reads due_date with
      // time.Parse(time.RFC3339, s), whose layout takes exactly four year digits
      // and no sign. The browser time zone decides which side of the boundary a
      // typed value lands on, so an ordinary 9999-12-31T23:59 is in range east
      // of UTC and overflows west of it. Without this the request is a 400 that
      // rolls back the assignee and status in the same patch.
      if (!/^\d{4}-/.test(wire))
        throw new Error(
          "조치 기한을 세계 표준시로 바꾸면 서버가 받을 수 있는 연도 범위를 벗어납니다. 더 가까운 기한을 입력하세요.",
        );
      patch.due_date = wire;
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
