interface ErrorStateProps {
  message: string;
  title?: string;
}

export function ErrorState({ message, title = "RAMSight could not load this view" }: ErrorStateProps) {
  return (
    <div className="state state-error" role="alert">
      <strong>{title}</strong>
      <span>{message}</span>
    </div>
  );
}
