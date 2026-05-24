export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info";

export function statusTone(status: string): BadgeTone {
  const normalized = status.toLowerCase();
  if (["completed", "open", "ready"].includes(normalized)) return "success";
  if (["queued", "running", "in_progress"].includes(normalized)) return "info";
  if (["failed", "closed"].includes(normalized)) return "danger";
  return "neutral";
}
