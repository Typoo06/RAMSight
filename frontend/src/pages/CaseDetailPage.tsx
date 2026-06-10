import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { createAnalysisJob, listAnalysisJobs } from "../api/analysisJobs";
import { getCase } from "../api/cases";
import { listEvidences } from "../api/evidences";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { LoadingState } from "../components/ui/LoadingState";
import { Table } from "../components/ui/Table";
import type { AnalysisJob, AnalysisPluginProfile, Case, Evidence } from "../types/domain";
import { displayValue, formatBytes, formatDateTime, formatDurationMs, shortHash } from "../utils/format";
import { statusTone } from "../utils/status";

const DEFAULT_ANALYSIS_PROFILE: AnalysisPluginProfile = "windows_memory_yara_elastic";

const ANALYSIS_PROFILE_OPTIONS: Array<{ description: string; label: string; value: AnalysisPluginProfile }> = [
  {
    value: "windows_default",
    label: "Standard Windows triage",
    description: "Fast default RAMSight analysis without YARA process-memory scanning.",
  },
  {
    value: "windows_memory_yara_elastic",
    label: "Elastic YARA",
    description: "Recommended demo path: standard Windows triage plus Elastic third-party YARA process-memory scanning.",
  },
  {
    value: "windows_memory_yara_neo23x0",
    label: "Neo23x0 Signature Base YARA",
    description: "Runs standard Windows triage plus Neo23x0 Signature Base process-memory YARA rules.",
  },
  {
    value: "windows_memory_yara_third_party_all",
    label: "Third-party YARA All (slow)",
    description: "Runs Elastic and Neo23x0 YARA packs together. Use explicitly; this can be slow and memory intensive on large dumps.",
  },
];

const PROFILE_LABELS: Record<string, string> = {
  windows_default: "Standard Windows triage",
  windows_memory_yara: "Elastic YARA (compatibility alias)",
  windows_memory_yara_elastic: "Elastic YARA",
  windows_memory_yara_neo23x0: "Neo23x0 Signature Base YARA",
  windows_memory_yara_third_party_all: "Third-party YARA All (slow)",
};

function evidenceOsFamily(evidence: Evidence): string {
  return evidence.os_family || "windows";
}

function normalizedEvidenceOsFamily(evidence: Evidence): string {
  return (evidence.os_family || "unknown").toLowerCase();
}

function supportsWindowsAnalysisProfiles(evidence: Evidence): boolean {
  const osFamily = normalizedEvidenceOsFamily(evidence);
  return osFamily === "windows" || osFamily === "unknown";
}

function profileDescription(profile: AnalysisPluginProfile): string {
  return ANALYSIS_PROFILE_OPTIONS.find((option) => option.value === profile)?.description ?? "RAMSight analysis profile.";
}

function profileHelpText(evidence: Evidence, profile: AnalysisPluginProfile): string {
  const osFamily = normalizedEvidenceOsFamily(evidence);
  if (osFamily === "linux") return "Linux analysis profiles are planned; Windows MVP profiles are not available for Linux evidence.";
  if (osFamily !== "windows" && osFamily !== "unknown") return "This evidence OS family does not have a RAMSight analysis profile yet.";
  if (osFamily === "unknown") return "OS is unknown; use these Windows MVP profiles only when the dump is expected to be Windows.";
  return profileDescription(profile);
}

function profileLabel(profile: string | null | undefined): string {
  return PROFILE_LABELS[String(profile || "").toLowerCase()] ?? displayValue(profile);
}

export function CaseDetailPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const [caseRecord, setCaseRecord] = useState<Case | null>(null);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [caseLoading, setCaseLoading] = useState(true);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(true);
  const [evidences, setEvidences] = useState<Evidence[]>([]);
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [jobsError, setJobsError] = useState<string | null>(null);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [profileByEvidenceId, setProfileByEvidenceId] = useState<Record<string, AnalysisPluginProfile>>({});
  const [startError, setStartError] = useState<string | null>(null);
  const [startingEvidenceId, setStartingEvidenceId] = useState<string | null>(null);

  useEffect(() => {
    if (!caseId) return;
    let active = true;

    getCase(caseId)
      .then((item) => {
        if (active) setCaseRecord(item);
      })
      .catch((err: unknown) => {
        if (active) setCaseError(err instanceof Error ? err.message : "RAMSight could not load this case.");
      })
      .finally(() => {
        if (active) setCaseLoading(false);
      });

    listEvidences({ case_id: caseId, limit: 100 })
      .then((response) => {
        if (active) setEvidences(response.items);
      })
      .catch((err: unknown) => {
        if (active) setEvidenceError(err instanceof Error ? err.message : "RAMSight could not load evidence metadata.");
      })
      .finally(() => {
        if (active) setEvidenceLoading(false);
      });

    listAnalysisJobs({ case_id: caseId, limit: 100 })
      .then((response) => {
        if (active) setJobs(response.items);
      })
      .catch((err: unknown) => {
        if (active) setJobsError(err instanceof Error ? err.message : "RAMSight could not load analysis jobs.");
      })
      .finally(() => {
        if (active) setJobsLoading(false);
      });

    return () => {
      active = false;
    };
  }, [caseId]);

  const evidenceNameById = useMemo(() => {
    return new Map(evidences.map((evidence) => [evidence.id, evidence.original_filename]));
  }, [evidences]);

  function selectedProfileForEvidence(evidence: Evidence): AnalysisPluginProfile {
    return profileByEvidenceId[evidence.id] ?? DEFAULT_ANALYSIS_PROFILE;
  }

  async function handleStartAnalysis(evidence: Evidence) {
    if (!caseId) return;
    setStartError(null);
    setStartingEvidenceId(evidence.id);
    try {
      const pluginProfile = supportsWindowsAnalysisProfiles(evidence) ? selectedProfileForEvidence(evidence) : null;
      const job = await createAnalysisJob({
        case_id: caseId,
        evidence_id: evidence.id,
        os_family: evidenceOsFamily(evidence),
        os_version: evidence.os_version,
        architecture: evidence.architecture,
        kernel_version: evidence.kernel_version,
        symbol_table: evidence.symbol_table,
        plugin_profile: pluginProfile,
      });
      navigate(`/cases/${caseId}/jobs/${job.id}`);
    } catch (err) {
      setStartError(err instanceof Error ? err.message : "RAMSight could not create an analysis job.");
    } finally {
      setStartingEvidenceId(null);
    }
  }

  if (!caseId) return <ErrorState message="RAMSight could not identify the requested case." />;
  if (caseLoading) return <LoadingState label="Loading RAMSight case..." />;
  if (caseError) return <ErrorState message={caseError} />;
  if (!caseRecord) return <ErrorState message="RAMSight did not return case metadata." />;

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div>
          <span className="eyebrow">Case detail</span>
          <h2>{caseRecord.name}</h2>
          <p>{caseRecord.case_code}</p>
        </div>
        <Badge tone={statusTone(caseRecord.status)}>{caseRecord.status}</Badge>
      </section>

      <div className="detail-grid">
        <Card title="Case metadata">
          <dl className="metadata-list">
            <div><dt>Case code</dt><dd>{caseRecord.case_code}</dd></div>
            <div><dt>Status</dt><dd>{caseRecord.status}</dd></div>
            <div><dt>Created</dt><dd>{formatDateTime(caseRecord.created_at)}</dd></div>
            <div><dt>Updated</dt><dd>{formatDateTime(caseRecord.updated_at)}</dd></div>
          </dl>
          <p>{caseRecord.description || "No case description has been recorded."}</p>
        </Card>
        <Card title="Workflow" actions={<Link className="text-link" to="/cases">Back to cases</Link>}>
          <p>Upload memory evidence, choose an analysis profile, then monitor the worker job until RAMSight reaches a terminal status.</p>
          <p className="section-note">Large browser uploads use chunked transfer. RAMSight stores memory dump bytes in object storage and keeps metadata, hashes, and normalized records in PostgreSQL.</p>
          <Link className="text-link" to={`/cases/${caseId}/evidence/upload`}>
            Upload evidence
          </Link>
        </Card>
      </div>

      {startError && <ErrorState message={startError} title="Analysis job could not be created" />}

      <Card title="Evidence" actions={<Link className="text-link" to={`/cases/${caseId}/evidence/upload`}>Upload evidence</Link>}>
        <p className="section-note">Evidence rows show stored metadata only. RAMSight does not keep memory dump contents in React state or PostgreSQL.</p>
        {evidenceLoading && <LoadingState label="Loading RAMSight evidence metadata..." />}
        {evidenceError && <ErrorState message={evidenceError} title="Evidence metadata unavailable" />}
        {!evidenceLoading && !evidenceError && evidences.length === 0 && (
          <p className="muted">No evidence has been uploaded for this case yet. Upload a memory image to begin RAMSight triage.</p>
        )}
        {!evidenceLoading && !evidenceError && evidences.length > 0 && (
          <div className="item-list">
            {evidences.map((evidence) => {
              const selectedProfile = selectedProfileForEvidence(evidence);
              const profileAvailable = supportsWindowsAnalysisProfiles(evidence);
              const isStarting = startingEvidenceId === evidence.id;

              return (
                <article className="item-panel" key={evidence.id}>
                  <header className="item-panel-header">
                    <div>
                      <strong>{evidence.original_filename}</strong>
                      <span>{displayValue(evidence.source_type)} evidence</span>
                    </div>
                    <div className="analysis-start-controls">
                      <label className="analysis-profile-label">
                        <span>Analysis profile</span>
                        <select
                          aria-label={`Analysis profile for ${evidence.original_filename}`}
                          disabled={!profileAvailable || isStarting}
                          value={selectedProfile}
                          onChange={(event) => {
                            const value = event.target.value as AnalysisPluginProfile;
                            setProfileByEvidenceId((current) => ({ ...current, [evidence.id]: value }));
                          }}
                        >
                          {ANALYSIS_PROFILE_OPTIONS.map((option) => (
                            <option key={option.value} value={option.value}>{option.label}</option>
                          ))}
                        </select>
                      </label>
                      <p className="field-help profile-help">{profileHelpText(evidence, selectedProfile)}</p>
                      <Button
                        disabled={!profileAvailable || isStarting}
                        type="button"
                        onClick={() => void handleStartAnalysis(evidence)}
                      >
                        {!profileAvailable ? "Profile unavailable" : isStarting ? "Starting..." : "Start analysis"}
                      </Button>
                    </div>
                  </header>
                  <dl className="metadata-list metadata-list-wide">
                    <div><dt>OS family</dt><dd>{displayValue(evidence.os_family)}</dd></div>
                    <div><dt>OS version</dt><dd>{displayValue(evidence.os_version)}</dd></div>
                    <div><dt>Architecture</dt><dd>{displayValue(evidence.architecture)}</dd></div>
                    <div><dt>Kernel version</dt><dd>{displayValue(evidence.kernel_version)}</dd></div>
                    <div><dt>Symbol table</dt><dd>{displayValue(evidence.symbol_table)}</dd></div>
                    <div><dt>Acquisition tool</dt><dd>{displayValue(evidence.acquisition_tool)}</dd></div>
                    <div><dt>Acquisition time</dt><dd>{formatDateTime(evidence.acquisition_time)}</dd></div>
                    <div><dt>Size</dt><dd>{formatBytes(evidence.size_bytes)}</dd></div>
                    <div><dt>MD5</dt><dd><code title={evidence.md5 ?? undefined}>{shortHash(evidence.md5)}</code></dd></div>
                    <div><dt>SHA256</dt><dd><code title={evidence.sha256 ?? undefined}>{shortHash(evidence.sha256)}</code></dd></div>
                  </dl>
                </article>
              );
            })}
          </div>
        )}
      </Card>

      <Card title="Analysis jobs">
        {jobsLoading && <LoadingState label="Loading RAMSight analysis jobs..." />}
        {jobsError && <ErrorState message={jobsError} title="Analysis jobs unavailable" />}
        {!jobsLoading && !jobsError && jobs.length === 0 && (
          <p className="muted">No analysis jobs have been created for this case yet.</p>
        )}
        {!jobsLoading && !jobsError && jobs.length > 0 && (
          <Table caption="RAMSight analysis jobs for this case">
            <thead>
              <tr>
                <th>Status</th>
                <th>Evidence</th>
                <th>OS</th>
                <th>Profile</th>
                <th>Updated</th>
                <th>Duration</th>
                <th>Monitor</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id}>
                  <td><Badge tone={statusTone(job.status)}>{job.status}</Badge></td>
                  <td>{evidenceNameById.get(job.evidence_id) ?? job.evidence_id}</td>
                  <td>{displayValue(job.os_family)}</td>
                  <td>{profileLabel(job.plugin_profile)}</td>
                  <td>{formatDateTime(job.updated_at)}</td>
                  <td>{formatDurationMs(job.duration_ms)}</td>
                  <td>
                    <Link className="text-link" to={`/cases/${caseId}/jobs/${job.id}`}>
                      View results
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}
