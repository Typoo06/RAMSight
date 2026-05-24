import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listCases } from "../api/cases";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { Table } from "../components/ui/Table";
import type { Case } from "../types/domain";
import { statusTone } from "../utils/status";

export function CasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    listCases({ limit: 100 })
      .then((response) => {
        if (active) setCases(response.items);
      })
      .catch((err: unknown) => {
        if (active) setError(err instanceof Error ? err.message : "RAMSight could not load cases.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div>
          <span className="eyebrow">Cases</span>
          <h2>RAMSight cases</h2>
          <p>Create and review memory triage cases.</p>
        </div>
        <Link to="/cases/new">
          <Button type="button">New case</Button>
        </Link>
      </section>

      {loading && <LoadingState label="Loading RAMSight cases..." />}
      {error && <ErrorState message={error} />}
      {!loading && !error && cases.length === 0 && (
        <Card title="No cases yet">
          <p>Start a RAMSight investigation by creating a case. Evidence upload is handled in the next workflow task.</p>
          <Link className="text-link" to="/cases/new">
            Create the first case
          </Link>
        </Card>
      )}
      {!loading && !error && cases.length > 0 && (
        <Card>
          <Table caption="RAMSight case list">
            <thead>
              <tr>
                <th>Case code</th>
                <th>Name</th>
                <th>Status</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((item) => (
                <tr key={item.id}>
                  <td>
                    <Link to={`/cases/${item.id}`}>{item.case_code}</Link>
                  </td>
                  <td>{item.name}</td>
                  <td>
                    <Badge tone={statusTone(item.status)}>{item.status}</Badge>
                  </td>
                  <td>{new Date(item.updated_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </div>
  );
}
