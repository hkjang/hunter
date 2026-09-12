export type FormIssue = { message: string; fieldId?: string };

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => item !== undefined)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, canonical(item)]),
    );
  return value;
}

// Comparison stays in memory. Form drafts, including credentials, are never
// serialized to localStorage or another persistence mechanism by this helper.
export function changed(baseline: unknown, current: unknown): boolean {
  return (
    JSON.stringify(canonical(baseline)) !== JSON.stringify(canonical(current))
  );
}

export function reconcileDrafts<T extends Record<string, unknown>>(
  baseline: T,
  current: T,
  incoming: T,
): T {
  const next = { ...current };
  for (const key of Object.keys(incoming) as (keyof T)[])
    next[key] =
      key in current && changed(baseline[key], current[key])
        ? current[key]
        : incoming[key];
  return next;
}

export function requiredIssues(
  fields: { fieldId: string; label: string; value: unknown }[],
): FormIssue[] {
  return fields
    .filter(
      ({ value }) =>
        value == null ||
        (typeof value === "string" && !value.trim()) ||
        (Array.isArray(value) && !value.length),
    )
    .map(({ fieldId, label }) => ({
      fieldId,
      message: `${label} 항목을 입력하세요.`,
    }));
}

export function invalidFields(form: HTMLFormElement): FormIssue[] {
  return [
    ...form.querySelectorAll<
      HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
    >("input, textarea, select"),
  ]
    .filter((field) => field.willValidate && !field.validity.valid)
    .map((field) => {
      const caption = (
        field.labels?.[0]?.textContent ||
        field.getAttribute("aria-label") ||
        "필수 입력"
      )
        .replace(/\s*\*\s*$/u, "")
        .trim();
      let message = `${caption} 항목의 입력 형식을 확인하세요.`;
      if (field.validity.valueMissing)
        message = `${caption} 항목을 입력하세요.`;
      else if (field.validity.tooShort && "minLength" in field)
        message = `${caption} 항목은 ${field.minLength}자 이상 입력하세요.`;
      else if (field.validity.tooLong && "maxLength" in field)
        message = `${caption} 항목은 ${field.maxLength}자 이하로 입력하세요.`;
      else if (field.validity.rangeUnderflow && "min" in field)
        message = `${caption} 항목은 ${field.min} 이상 입력하세요.`;
      else if (field.validity.rangeOverflow && "max" in field)
        message = `${caption} 항목은 ${field.max} 이하로 입력하세요.`;
      return { fieldId: field.id || undefined, message };
    });
}
