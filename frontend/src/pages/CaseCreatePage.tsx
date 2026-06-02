import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { createCase } from "../api/cases";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";

export function CaseCreatePage() {
  const navigate = useNavigate();
  const [caseCode, setCaseCode] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const created = await createCase({
        case_code: caseCode.trim(),
        description: description.trim() || null,
        name: name.trim(),
        status: "open",
      });
      navigate(`/cases/${created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "RAMSight could not create this case.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="page-stack narrow-page">
      <section className="page-heading">
        <span className="eyebrow">New case</span>
        <h2>Create RAMSight case</h2>
        <p>Set up the investigation record before evidence intake.</p>
      </section>

      {error && <ErrorState message={error} title="Case creation failed" />}

      <Card>
        <form className="form-stack" onSubmit={handleSubmit}>
          <label>
            Case code
            <input required value={caseCode} onChange={(event) => setCaseCode(event.target.value)} placeholder="CASE-2026-001" />
          </label>
          <label>
            Name
            <input required value={name} onChange={(event) => setName(event.target.value)} placeholder="Workstation memory triage" />
          </label>
          <label>
            Description
            <textarea value={description} onChange={(event) => setDescription(event.target.value)} rows={5} placeholder="Short investigation context" />
          </label>
          <div className="form-actions">
            <Link className="text-link" to="/cases">
              Cancel
            </Link>
            <Button disabled={submitting} type="submit">
              {submitting ? "Creating..." : "Create case"}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
