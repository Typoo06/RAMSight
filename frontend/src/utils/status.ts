export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info";

export function statusTone(status: string): BadgeTone {
  const normalized = status.toLowerCase();
  if (["completed", "open", "ready", "reviewed", "true_positive"].includes(normalized)) return "success";
  if (["queued", "running", "in_progress", "investigating", "suspicious", "needs_more_evidence"].includes(normalized)) return "info";
  if (["failed", "closed", "cancelled", "canceled", "critical", "high"].includes(normalized)) return "danger";
  if (["unknown", "skipped", "medium"].includes(normalized)) return "warning";
  if (["false_positive", "benign", "ignored"].includes(normalized)) return "neutral";
  if (normalized === "low") return "neutral";
  return "neutral";
}

export function isActiveJobStatus(status: string): boolean {
  return ["queued", "running"].includes(status.toLowerCase());
}
