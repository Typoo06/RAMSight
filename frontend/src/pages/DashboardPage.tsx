import { Link } from "react-router-dom";
import { Card } from "../components/ui/Card";

export function DashboardPage() {
  return (
    <div className="page-stack">
      <section className="page-heading">
        <span className="eyebrow">Dashboard</span>
        <h2>RAMSight triage workspace</h2>
        <p>Track memory forensic cases and prepare evidence workflows from one compact local lab view.</p>
      </section>

      <div className="dashboard-grid">
        <Card title="Cases">
          <p>Open, create, and review RAMSight cases before adding evidence in the next workflow step.</p>
          <Link className="text-link" to="/cases">
            View cases
          </Link>
        </Card>
        <Card title="Analysis Pipeline">
          <p>Worker analysis, parsing, detection, IOC extraction, and HTML report generation are wired through the backend.</p>
          <span className="muted">Detailed result views arrive in Task 12C.</span>
        </Card>
        <Card title="Evidence Intake">
          <p>Browser upload is intentionally not included in this foundation screen.</p>
          <span className="muted">Evidence upload arrives in Task 12B.</span>
        </Card>
      </div>
    </div>
  );
}
