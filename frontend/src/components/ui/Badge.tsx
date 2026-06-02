import type { BadgeTone } from "../../utils/status";

interface BadgeProps {
  children: string;
  tone?: BadgeTone;
}

export function Badge({ children, tone = "neutral" }: BadgeProps) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
