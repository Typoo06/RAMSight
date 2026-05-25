export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info";

export function statusTone(status: string): BadgeTone {
  const normalized = status.toLowerCase();
  if (["completed", "open", "ready"].includes(normalized)) return "success";
  if (["queued", "running", "in_progress"].includes(normalized)) return "info";
  if (["failed", "closed", "cancelled", "canceled"].includes(normalized)) return "danger";
  if (["unknown", "skipped"].includes(normalized)) return "warning";
  return "neutral";
}

export function isActiveJobStatus(status: string): boolean {
  return ["queued", "running"].includes(status.toLowerCase());
}
