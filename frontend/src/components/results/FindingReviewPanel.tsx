import { useEffect, useState } from "react";
import {
  createRiskFindingNote,
  listRiskFindingNotes,
  updateRiskFindingReview,
} from "../../api/riskFindings";
import type { AnalystNote, RiskFinding } from "../../types/domain";
import { formatDateTime } from "../../utils/format";
import { Button } from "../ui/Button";

interface FindingReviewPanelProps {
  finding: RiskFinding;
  onSaved: (finding: RiskFinding) => void;
}

const REVIEW_STATUSES = ["new", "investigating", "reviewed"];
const ANALYST_VERDICTS = ["true_positive", "false_positive", "benign", "suspicious", "needs_more_evidence", "ignored"];
const SEVERITY_OVERRIDES = ["low", "medium", "high", "critical"];

function displayLabel(value: string): string {
  return value.replaceAll("_", " ");
}

export function FindingReviewPanel({ finding, onSaved }: FindingReviewPanelProps) {
  const [reviewStatus, setReviewStatus] = useState(finding.review_status || "new");
  const [analystVerdict, setAnalystVerdict] = useState(finding.analyst_verdict || "");
  const [severityOverride, setSeverityOverride] = useState(finding.severity_override || "");
  const [reviewedByName, setReviewedByName] = useState(finding.reviewed_by_name || "");
  const [reviewNote, setReviewNote] = useState("");
  const [newNote, setNewNote] = useState("");
  const [notes, setNotes] = useState<AnalystNote[]>([]);
  const [loadingNotes, setLoadingNotes] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.resolve().then(() => {
      if (!active) return null;
      setLoadingNotes(true);
      setError(null);
      return listRiskFindingNotes(finding.id);
    }).then((response) => {
      if (!response || !active) return;
      setNotes(response.items);
    }).catch((err: unknown) => {
      if (active) setError(err instanceof Error ? err.message : "RAMSight could not load analyst notes.");
    }).finally(() => {
      if (active) setLoadingNotes(false);
    });
    return () => {
      active = false;
    };
  }, [finding.id]);

  function reloadNotes() {
    return listRiskFindingNotes(finding.id).then((response) => setNotes(response.items));
  }

  async function saveReview() {
    setSaving(true);
    setError(null);
    try {
      const updated = await updateRiskFindingReview(finding.id, {
        review_status: reviewStatus,
        analyst_verdict: analystVerdict || null,
        severity_override: severityOverride || null,
        reviewed_by_name: reviewedByName || null,
        note: reviewNote || null,
      });
      setReviewNote("");
      onSaved(updated);
      if (reviewNote.trim()) await reloadNotes();
    } catch (err) {
      setError(err instanceof Error ? err.message : "RAMSight could not update the finding review.");
    } finally {
      setSaving(false);
    }
  }

  async function addNote() {
    if (!newNote.trim()) {
      setError("Note content is required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const created = await createRiskFindingNote(finding.id, {
        content: newNote,
        author_name: reviewedByName || null,
        note_type: "finding_review",
      });
      setNotes((current) => [...current, created]);
      setNewNote("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "RAMSight could not add the analyst note.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="review-panel">
      <div className="review-grid">
        <label>
          <span>Review status</span>
          <select value={reviewStatus} onChange={(event) => setReviewStatus(event.target.value)}>
            {REVIEW_STATUSES.map((status) => <option key={status} value={status}>{displayLabel(status)}</option>)}
          </select>
        </label>
        <label>
          <span>Analyst verdict</span>
          <select value={analystVerdict} onChange={(event) => setAnalystVerdict(event.target.value)}>
            <option value="">Not set</option>
            {ANALYST_VERDICTS.map((verdict) => <option key={verdict} value={verdict}>{displayLabel(verdict)}</option>)}
          </select>
        </label>
        <label>
          <span>Severity override</span>
          <select value={severityOverride} onChange={(event) => setSeverityOverride(event.target.value)}>
            <option value="">Use detected severity</option>
            {SEVERITY_OVERRIDES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
          </select>
        </label>
        <label>
          <span>Reviewer</span>
          <input maxLength={255} value={reviewedByName} onChange={(event) => setReviewedByName(event.target.value)} placeholder="Optional analyst name" />
        </label>
      </div>

      <label className="review-note-field">
        <span>Review note</span>
        <textarea maxLength={4000} rows={3} value={reviewNote} onChange={(event) => setReviewNote(event.target.value)} placeholder="Optional note saved with this review update" />
      </label>
      <div className="button-row">
        <Button type="button" onClick={saveReview} disabled={saving}>Save review</Button>
      </div>

      <div className="review-notes">
        <h3>Analyst notes</h3>
        {loadingNotes && <p className="muted">Loading notes...</p>}
        {!loadingNotes && notes.length === 0 && <p className="muted">No analyst notes are linked to this finding yet.</p>}
        {notes.map((note) => (
          <article className="note-item" key={note.id}>
            <p>{note.content}</p>
            <span>{note.author_name || "Unspecified analyst"} | {formatDateTime(note.created_at)}</span>
          </article>
        ))}
      </div>

      <label className="review-note-field">
        <span>Add note</span>
        <textarea maxLength={4000} rows={3} value={newNote} onChange={(event) => setNewNote(event.target.value)} placeholder="Add a separate analyst note" />
      </label>
      <div className="button-row">
        <Button type="button" variant="secondary" onClick={addNote} disabled={saving}>Add note</Button>
      </div>

      {error && <p className="error-text">{error}</p>}
    </div>
  );
}
