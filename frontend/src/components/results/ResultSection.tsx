import type { ReactNode } from "react";
import { Card } from "../ui/Card";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";

interface ResultSectionProps {
  actions?: ReactNode;
  children: ReactNode;
  empty?: boolean;
  emptyMessage?: string;
  error?: string | null;
  loading?: boolean;
  title: string;
}

export function ResultSection({ actions, children, empty, emptyMessage, error, loading, title }: ResultSectionProps) {
  return (
    <Card title={title} actions={actions}>
      {loading && <LoadingState label={`Loading ${title.toLowerCase()}...`} />}
      {error && <ErrorState message={error} title={`${title} unavailable`} />}
      {!loading && !error && empty && <p className="muted">{emptyMessage ?? "No records are available for this section."}</p>}
      {!loading && !error && !empty && children}
    </Card>
  );
}

