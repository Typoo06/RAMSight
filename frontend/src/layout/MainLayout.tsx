import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

interface MainLayoutProps {
  children: ReactNode;
}

export function MainLayout({ children }: MainLayoutProps) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">R</span>
          <div>
            <strong>RAMSight</strong>
            <span>Memory-only malware analysis</span>
          </div>
        </div>
        <nav aria-label="RAMSight navigation">
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/cases">Cases</NavLink>
          <NavLink to="/chatbot">AI assistant</NavLink>
        </nav>
      </aside>
      <div className="main-column">
        <header className="topbar">
          <div>
            <span className="eyebrow">Local lab</span>
            <h1>RAMSight</h1>
          </div>
          <span className="topbar-note">Windows MVP, Linux-ready architecture</span>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
