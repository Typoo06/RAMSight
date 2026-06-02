import { FormEvent, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { uploadEvidence } from "../api/evidences";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import type { OSFamily } from "../types/domain";

const ALLOWED_EXTENSIONS = [".raw", ".mem", ".vmem", ".dmp", ".lime"];

function hasAllowedExtension(filename: string): boolean {
  const normalized = filename.toLowerCase();
  return ALLOWED_EXTENSIONS.some((extension) => normalized.endsWith(extension));
}

function appendOptional(formData: FormData, key: string, value: string) {
  const trimmed = value.trim();
  if (trimmed) formData.append(key, trimmed);
}

export function EvidenceUploadPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [acquisitionTime, setAcquisitionTime] = useState("");
  const [acquisitionTool, setAcquisitionTool] = useState("");
  const [architecture, setArchitecture] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState("");
  const [kernelVersion, setKernelVersion] = useState("");
  const [osFamily, setOsFamily] = useState<OSFamily>("windows");
  const [osVersion, setOsVersion] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [symbolTable, setSymbolTable] = useState("");

  function handleFileChange() {
    const file = fileInputRef.current?.files?.[0];
    setFileName(file?.name ?? "");
    if (!file) {
      setError(null);
      return;
    }
    if (!hasAllowedExtension(file.name)) {
      setError(`RAMSight accepts memory dumps with these extensions: ${ALLOWED_EXTENSIONS.join(", ")}.`);
      return;
    }
    setError(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!caseId) {
      setError("RAMSight could not identify the target case.");
      return;
    }

    const file = fileInputRef.current?.files?.[0];
    if (!file) {
      setError("Choose a memory dump before uploading evidence.");
      return;
    }
    if (!hasAllowedExtension(file.name)) {
      setError(`RAMSight accepts memory dumps with these extensions: ${ALLOWED_EXTENSIONS.join(", ")}.`);
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("case_id", caseId);
      formData.append("os_family", osFamily || "windows");
      formData.append("file", file);
      appendOptional(formData, "os_version", osVersion);
      appendOptional(formData, "architecture", architecture);
      appendOptional(formData, "kernel_version", kernelVersion);
      appendOptional(formData, "symbol_table", symbolTable);
      appendOptional(formData, "acquisition_tool", acquisitionTool);
      if (acquisitionTime) formData.append("acquisition_time", new Date(acquisitionTime).toISOString());

      await uploadEvidence(formData);
      navigate(`/cases/${caseId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "RAMSight could not upload this evidence.");
    } finally {
      setSubmitting(false);
    }
  }

  if (!caseId) return <ErrorState message="RAMSight could not identify the target case." />;

  return (
    <div className="page-stack narrow-page">
      <section className="page-heading">
        <span className="eyebrow">Evidence upload</span>
        <h2>Upload RAMSight evidence</h2>
        <p>Store the memory dump in MinIO/S3 and keep only metadata in PostgreSQL.</p>
      </section>

      {error && <ErrorState message={error} title="Evidence upload needs attention" />}

      <Card>
        <form className="form-stack" onSubmit={handleSubmit}>
          <label>
            Memory dump file
            <input ref={fileInputRef} type="file" onChange={handleFileChange} />
            <span className="field-help">Allowed extensions: {ALLOWED_EXTENSIONS.join(", ")}.</span>
            {fileName && <span className="field-help">Selected file: {fileName}</span>}
          </label>

          <div className="form-grid-two">
            <label>
              OS family
              <select value={osFamily} onChange={(event) => setOsFamily(event.target.value as OSFamily)}>
                <option value="windows">Windows MVP</option>
                <option value="linux">Linux-ready / planned</option>
                <option value="unknown">Unknown</option>
              </select>
            </label>
            <label>
              Architecture
              <input value={architecture} onChange={(event) => setArchitecture(event.target.value)} placeholder="x64" />
            </label>
          </div>

          <label>
            OS version
            <input value={osVersion} onChange={(event) => setOsVersion(event.target.value)} placeholder="Windows 10 22H2" />
          </label>

          <div className="form-grid-two">
            <label>
              Kernel version
              <input value={kernelVersion} onChange={(event) => setKernelVersion(event.target.value)} placeholder="Optional kernel build" />
            </label>
            <label>
              Symbol table
              <input value={symbolTable} onChange={(event) => setSymbolTable(event.target.value)} placeholder="Optional symbol table" />
            </label>
          </div>

          <div className="form-grid-two">
            <label>
              Acquisition tool
              <input value={acquisitionTool} onChange={(event) => setAcquisitionTool(event.target.value)} placeholder="WinPmem, LiME, Magnet RAM Capture" />
            </label>
            <label>
              Acquisition time
              <input type="datetime-local" value={acquisitionTime} onChange={(event) => setAcquisitionTime(event.target.value)} />
            </label>
          </div>

          <div className="form-actions">
            <Link className="text-link" to={`/cases/${caseId}`}>
              Cancel
            </Link>
            <Button disabled={submitting} type="submit">
              {submitting ? "Uploading..." : "Upload evidence"}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

