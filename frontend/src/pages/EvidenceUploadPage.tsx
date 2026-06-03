import { FormEvent, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  cancelEvidenceUpload,
  completeEvidenceUpload,
  initiateEvidenceUpload,
  uploadEvidenceChunk,
} from "../api/evidences";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import type { OSFamily } from "../types/domain";

const ALLOWED_EXTENSIONS = [".raw", ".mem", ".vmem", ".dmp", ".lime"];
const MAX_CHUNK_RETRIES = 2;

type UploadStatus = "idle" | "preparing" | "uploading" | "finalizing" | "completed" | "failed" | "cancelled";

interface UploadProgress {
  status: UploadStatus;
  uploadedBytes: number;
  totalBytes: number;
  uploadedChunks: number;
  totalChunks: number;
  message: string;
}

function hasAllowedExtension(filename: string): boolean {
  const normalized = filename.toLowerCase();
  return ALLOWED_EXTENSIONS.some((extension) => normalized.endsWith(extension));
}

function optionalValue(value: string): string | null {
  const trimmed = value.trim();
  return trimmed || null;
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function progressPercent(progress: UploadProgress | null): number {
  if (!progress || progress.totalBytes <= 0) return 0;
  return Math.min(100, Math.round((progress.uploadedBytes / progress.totalBytes) * 100));
}

export function EvidenceUploadPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const activeUploadIdRef = useRef<string | null>(null);
  const activeControllerRef = useRef<AbortController | null>(null);
  const cancelRequestedRef = useRef(false);
  const [acquisitionTime, setAcquisitionTime] = useState("");
  const [acquisitionTool, setAcquisitionTool] = useState("");
  const [architecture, setArchitecture] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState("");
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [kernelVersion, setKernelVersion] = useState("");
  const [osFamily, setOsFamily] = useState<OSFamily>("windows");
  const [osVersion, setOsVersion] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [symbolTable, setSymbolTable] = useState("");
  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null);

  function handleFileChange() {
    const file = fileInputRef.current?.files?.[0];
    setFileName(file?.name ?? "");
    setFileSize(file?.size ?? null);
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

  async function uploadChunkWithRetry(uploadId: string, chunkIndex: number, chunk: Blob): Promise<number> {
    let lastError: unknown = null;
    for (let attempt = 0; attempt <= MAX_CHUNK_RETRIES; attempt += 1) {
      if (cancelRequestedRef.current) throw new Error("Evidence upload was cancelled.");
      const controller = new AbortController();
      activeControllerRef.current = controller;
      try {
        const result = await uploadEvidenceChunk(uploadId, chunkIndex, chunk, controller.signal);
        activeControllerRef.current = null;
        return result.uploaded_bytes;
      } catch (err) {
        activeControllerRef.current = null;
        lastError = err;
        if (cancelRequestedRef.current) throw new Error("Evidence upload was cancelled.", { cause: err });
        if (attempt >= MAX_CHUNK_RETRIES) break;
        setUploadProgress((current) => current
          ? { ...current, message: `Retrying chunk ${chunkIndex + 1} after a network error...` }
          : current);
      }
    }
    if (lastError instanceof Error) {
      throw new Error(lastError.message, { cause: lastError });
    }
    throw new Error("RAMSight could not upload an evidence chunk.", { cause: lastError });
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
    cancelRequestedRef.current = false;
    activeUploadIdRef.current = null;
    setUploadProgress({
      status: "preparing",
      uploadedBytes: 0,
      totalBytes: file.size,
      uploadedChunks: 0,
      totalChunks: 0,
      message: "Preparing RAMSight chunked upload session...",
    });

    try {
      const session = await initiateEvidenceUpload({
        case_id: caseId,
        original_filename: file.name,
        size_bytes: file.size,
        os_family: osFamily || "windows",
        os_version: optionalValue(osVersion),
        architecture: optionalValue(architecture),
        kernel_version: optionalValue(kernelVersion),
        symbol_table: optionalValue(symbolTable),
        acquisition_tool: optionalValue(acquisitionTool),
        acquisition_time: acquisitionTime ? new Date(acquisitionTime).toISOString() : null,
      });
      activeUploadIdRef.current = session.upload_id;
      setUploadProgress({
        status: "uploading",
        uploadedBytes: 0,
        totalBytes: file.size,
        uploadedChunks: 0,
        totalChunks: session.total_chunks,
        message: "Uploading evidence chunks...",
      });

      for (let chunkIndex = 0; chunkIndex < session.total_chunks; chunkIndex += 1) {
        if (cancelRequestedRef.current) throw new Error("Evidence upload was cancelled.");
        const start = chunkIndex * session.chunk_size;
        const end = Math.min(start + session.chunk_size, file.size);
        const chunk = file.slice(start, end);
        const uploadedBytes = await uploadChunkWithRetry(session.upload_id, chunkIndex, chunk);
        setUploadProgress({
          status: "uploading",
          uploadedBytes,
          totalBytes: file.size,
          uploadedChunks: chunkIndex + 1,
          totalChunks: session.total_chunks,
          message: "Uploading evidence chunks...",
        });
      }

      setUploadProgress((current) => current
        ? { ...current, status: "finalizing", message: "Finalizing upload, hashing evidence, and storing metadata..." }
        : current);
      await completeEvidenceUpload(session.upload_id);
      activeUploadIdRef.current = null;
      setUploadProgress((current) => current
        ? { ...current, status: "completed", uploadedBytes: file.size, message: "Evidence upload completed." }
        : current);
      navigate(`/cases/${caseId}`);
    } catch (err) {
      const cancelled = cancelRequestedRef.current;
      setUploadProgress((current) => current
        ? { ...current, status: cancelled ? "cancelled" : "failed", message: cancelled ? "Evidence upload was cancelled." : "Evidence upload failed." }
        : current);
      if (!cancelled) {
        setError(err instanceof Error ? err.message : "RAMSight could not upload this evidence.");
      }
    } finally {
      setSubmitting(false);
      activeControllerRef.current = null;
      cancelRequestedRef.current = false;
    }
  }

  async function handleCancelUpload() {
    cancelRequestedRef.current = true;
    activeControllerRef.current?.abort();
    const uploadId = activeUploadIdRef.current;
    if (uploadId) {
      try {
        await cancelEvidenceUpload(uploadId);
      } catch {
        // The session may already be gone if the backend cleaned it up.
      }
      activeUploadIdRef.current = null;
    }
    setUploadProgress((current) => current
      ? { ...current, status: "cancelled", message: "Evidence upload was cancelled." }
      : current);
    setSubmitting(false);
  }

  if (!caseId) return <ErrorState message="RAMSight could not identify the target case." />;

  const percent = progressPercent(uploadProgress);

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
            <input ref={fileInputRef} disabled={submitting} type="file" onChange={handleFileChange} />
            <span className="field-help">Allowed extensions: {ALLOWED_EXTENSIONS.join(", ")}.</span>
            <span className="field-help">RAMSight uploads large evidence in browser chunks to reduce memory pressure.</span>
            {fileName && <span className="field-help">Selected file: {fileName}{fileSize !== null ? ` (${formatBytes(fileSize)})` : ""}</span>}
          </label>

          <div className="form-grid-two">
            <label>
              OS family
              <select disabled={submitting} value={osFamily} onChange={(event) => setOsFamily(event.target.value as OSFamily)}>
                <option value="windows">Windows MVP</option>
                <option value="linux">Linux-ready / planned</option>
                <option value="unknown">Unknown</option>
              </select>
            </label>
            <label>
              Architecture
              <input disabled={submitting} value={architecture} onChange={(event) => setArchitecture(event.target.value)} placeholder="x64" />
            </label>
          </div>

          <label>
            OS version
            <input disabled={submitting} value={osVersion} onChange={(event) => setOsVersion(event.target.value)} placeholder="Windows 10 22H2" />
          </label>

          <div className="form-grid-two">
            <label>
              Kernel version
              <input disabled={submitting} value={kernelVersion} onChange={(event) => setKernelVersion(event.target.value)} placeholder="Optional kernel build" />
            </label>
            <label>
              Symbol table
              <input disabled={submitting} value={symbolTable} onChange={(event) => setSymbolTable(event.target.value)} placeholder="Optional symbol table" />
            </label>
          </div>

          <div className="form-grid-two">
            <label>
              Acquisition tool
              <input disabled={submitting} value={acquisitionTool} onChange={(event) => setAcquisitionTool(event.target.value)} placeholder="WinPmem, LiME, Magnet RAM Capture" />
            </label>
            <label>
              Acquisition time
              <input disabled={submitting} type="datetime-local" value={acquisitionTime} onChange={(event) => setAcquisitionTime(event.target.value)} />
            </label>
          </div>

          {uploadProgress && uploadProgress.status !== "idle" && (
            <div className="upload-progress-panel" role="status" aria-live="polite">
              <div className="upload-progress-header">
                <strong>{uploadProgress.message}</strong>
                <span>{percent}%</span>
              </div>
              <progress className="upload-progress-bar" value={percent} max={100} />
              <span className="field-help">
                {formatBytes(uploadProgress.uploadedBytes)} of {formatBytes(uploadProgress.totalBytes)} uploaded · chunk {uploadProgress.uploadedChunks} of {uploadProgress.totalChunks || "pending"} · status {uploadProgress.status}
              </span>
            </div>
          )}

          <div className="form-actions">
            {!submitting && (
              <Link className="text-link" to={`/cases/${caseId}`}>
                Cancel
              </Link>
            )}
            {submitting && (
              <Button type="button" variant="secondary" onClick={handleCancelUpload}>
                Cancel upload
              </Button>
            )}
            <Button disabled={submitting} type="submit">
              {submitting ? "Uploading..." : "Upload evidence"}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
