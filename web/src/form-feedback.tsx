import { useEffect, useId, useRef } from "react";
import {
  IconAlertCircle,
  IconCheck,
  IconDeviceFloppy,
  IconPencil,
} from "@tabler/icons-react";
import type { FormIssue } from "./form-state";
import "./forms.css";

export type { FormIssue } from "./form-state";

export function FormFeedback({
  error,
  issues = [],
  success,
  focusKey = 0,
  title,
}: {
  error?: string;
  issues?: FormIssue[];
  success?: string;
  focusKey?: number;
  title?: string;
}) {
  const element = useRef<HTMLDivElement>(null);
  const heading = useId();
  const invalid = !!error || issues.length > 0;
  const signature = issues
    .map((issue) => `${issue.fieldId}:${issue.message}`)
    .join("\n");
  useEffect(() => {
    if (invalid) element.current?.focus();
  }, [invalid, error, signature, focusKey]);
  if (invalid)
    return (
      <div
        ref={element}
        className="form-feedback form-feedback-error"
        role="alert"
        tabIndex={-1}
        aria-labelledby={heading}
      >
        <IconAlertCircle size={22} aria-hidden="true" />
        <div>
          <h3 id={heading}>
            {title ||
              (issues.length
                ? "입력 내용을 확인해 주세요"
                : "저장하지 못했습니다")}
          </h3>
          {error && <p>{error}</p>}
          {issues.length > 0 && (
            <ul>
              {issues.map((issue, index) => (
                <li key={`${issue.fieldId || "form"}-${index}`}>
                  {issue.fieldId ? (
                    <a
                      href={`#${issue.fieldId}`}
                      onClick={(event) => {
                        const field = document.getElementById(issue.fieldId!);
                        if (field) {
                          event.preventDefault();
                          field.focus();
                          field.scrollIntoView({
                            block: "center",
                            behavior: "auto",
                          });
                        }
                      }}
                    >
                      {issue.message}
                    </a>
                  ) : (
                    issue.message
                  )}
                </li>
              ))}
            </ul>
          )}
          <p className="form-feedback-help">
            입력한 내용은 유지되어 있습니다. 확인한 뒤 다시 시도하세요.
          </p>
        </div>
      </div>
    );
  if (success)
    return (
      <div className="form-feedback form-feedback-success" role="status">
        <IconCheck size={20} aria-hidden="true" />
        <p>{success}</p>
      </div>
    );
  return null;
}

export function SaveStatus({
  dirty,
  saving = false,
  savedAt,
}: {
  dirty: boolean;
  saving?: boolean;
  savedAt?: string;
}) {
  const Icon = saving ? IconDeviceFloppy : dirty ? IconPencil : IconCheck;
  return (
    <div
      className={`form-save-status${dirty ? " is-dirty" : ""}`}
      role="status"
      aria-live="polite"
    >
      <Icon size={17} aria-hidden="true" />
      <span>
        {saving
          ? "저장 중입니다…"
          : dirty
            ? "저장하지 않은 변경 사항이 있습니다"
            : savedAt
              ? `저장 완료 · ${new Date(savedAt).toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" })}`
              : "저장된 내용입니다"}
      </span>
    </div>
  );
}

export function useUnsavedChanges(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);
}
