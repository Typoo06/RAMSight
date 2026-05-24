interface LoadingStateProps {
  label?: string;
}

export function LoadingState({ label = "Loading RAMSight data..." }: LoadingStateProps) {
  return <div className="state state-loading">{label}</div>;
}
