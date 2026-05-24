import type { ReactNode } from "react";

interface TableProps {
  children: ReactNode;
  caption?: string;
}

export function Table({ caption, children }: TableProps) {
  return (
    <div className="table-wrap">
      <table className="table">
        {caption && <caption>{caption}</caption>}
        {children}
      </table>
    </div>
  );
}
