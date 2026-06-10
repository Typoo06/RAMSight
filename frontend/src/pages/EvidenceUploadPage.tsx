import { FormEvent, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  cancelMultipartEvidenceUpload,
  completeMultipartEvidenceUpload,
  initiateMultipartEvidenceUpload,
  presignMultipartEvidencePart,
  recordMultipartEvidencePart,
} from "../api/evidences";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import type { OSFamily } from "../types/domain";

const ALLOWED_EXTENSIONS = [".raw", ".mem", ".vmem", ".dmp", ".lime"];
const MAX_PART_RETRIES = 2;
const MULTIPART_UPLOAD_CONCURRENCY = 2;

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

function uploadPartToPresignedUrl(
  uploadUrl: string,
  part: Blob,
  activeXhrs: Set<XMLHttpRequest>,
  onProgress: (loadedBytes: number) => void,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    activeXhrs.add(xhr);

    xhr.open("PUT", uploadUrl);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded);
    };
    xhr.onload = () => {
      activeXhrs.delete(xhr);
      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error("Object storage rejected an evidence upload part."));
        return;
      }
      const etag = xhr.getResponseHeader("ETag");
      if (!etag) {
        reject(new Error("Object storage did not return an ETag for this upload part. Check MinIO CORS ExposeHeaders."));
        return;
      }
      onProgress(part.size);
      resolve(etag);
    };
    xhr.onerror = () => {
      activeXhrs.delete(xhr);
      reject(new Error("Object storage could not receive an evidence upload part."));
    };
    xhr.onabort = () => {
      activeXhrs.delete(xhr);
      reject(new Error("Evidence upload was cancelled."));
    };
    xhr.send(part);
  });
}

export function EvidenceUploadPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const activeUploadIdRef = useRef<string | null>(null);
  const activeXhrsRef = useRef<Set<XMLHttpRequest>>(new Set());
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

  async function uploadPartWithRetry(
    sessionId: string,
    partNumber: number,
    part: Blob,
    onProgress: (loadedBytes: number) => void,
  ): Promise<number> {
    let lastError: unknown = null;
    for (let attempt = 0; attempt <= MAX_PART_RETRIES; attempt += 1) {
      if (cancelRequestedRef.current) throw new Error("Evidence upload was cancelled.");
      try {
        const presigned = await presignMultipartEvidencePart(sessionId, partNumber);
        const etag = await uploadPartToPresignedUrl(presigned.upload_url, part, activeXhrsRef.current, onProgress);
        await recordMultipartEvidencePart(sessionId, partNumber, etag, part.size);
        return part.size;
      } catch (err) {
        lastError = err;
        onProgress(0);
        if (cancelRequestedRef.current) throw new Error("Evidence upload was cancelled.", { cause: err });
        if (attempt >= MAX_PART_RETRIES) break;
        setUploadProgress((current) => current
          ? { ...current, message: `Retrying part ${partNumber} after an upload error...` }
          : current);
      }
    }
    if (lastError instanceof Error) {
      throw new Error(lastError.message, { cause: lastError });
    }
    throw new Error("RAMSight could not upload an evidence part.", { cause: lastError });
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
    const selectedFile = file;
    if (!hasAllowedExtension(selectedFile.name)) {
      setError(`RAMSight accepts memory dumps with these extensions: ${ALLOWED_EXTENSIONS.join(", ")}.`);
      return;
    }

    setSubmitting(true);
    setError(null);
    cancelRequestedRef.current = false;
    activeUploadIdRef.current = null;
    activeXhrsRef.current.clear();
    setUploadProgress({
      status: "preparing",
      uploadedBytes: 0,
      totalBytes: selectedFile.size,
      uploadedChunks: 0,
      totalChunks: 0,
      message: "Preparing RAMSight direct multipart upload...",
    });

    try {
      const session = await initiateMultipartEvidenceUpload({
        case_id: caseId,
        filename: selectedFile.name,
        size_bytes: selectedFile.size,
        content_type: selectedFile.type || "application/octet-stream",
        os_family: osFamily || "windows",
        os_version: optionalValue(osVersion),
        architecture: optionalValue(architecture),
        kernel_version: optionalValue(kernelVersion),
        symbol_table: optionalValue(symbolTable),
        acquisition_tool: optionalValue(acquisitionTool),
        acquisition_time: acquisitionTime ? new Date(acquisitionTime).toISOString() : null,
      });
      activeUploadIdRef.current = session.upload_session_id;

      const partSize = session.recommended_part_size_bytes;
      const totalParts = session.expected_part_count;
      let nextPartNumber = 1;
      let completedParts = 0;
      let completedBytes = 0;
      const inFlightProgress = new Map<number, number>();

      function currentUploadedBytes(): number {
        return completedBytes + [...inFlightProgress.values()].reduce((total, value) => total + value, 0);
      }

      function setPartProgress(partNumber: number, loadedBytes: number) {
        if (loadedBytes <= 0) inFlightProgress.delete(partNumber);
        else inFlightProgress.set(partNumber, loadedBytes);
        setUploadProgress({
          status: "uploading",
          uploadedBytes: Math.min(currentUploadedBytes(), selectedFile.size),
          totalBytes: selectedFile.size,
          uploadedChunks: completedParts,
          totalChunks: totalParts,
          message: "Uploading evidence parts directly to object storage...",
        });
      }

      setUploadProgress({
        status: "uploading",
        uploadedBytes: 0,
        totalBytes: selectedFile.size,
        uploadedChunks: 0,
        totalChunks: totalParts,
        message: "Uploading evidence parts directly to object storage...",
      });

      async function worker() {
        while (!cancelRequestedRef.current) {
          const partNumber = nextPartNumber;
          nextPartNumber += 1;
          if (partNumber > totalParts) return;

          const start = (partNumber - 1) * partSize;
          const end = Math.min(start + partSize, selectedFile.size);
          const part = selectedFile.slice(start, end);
          const uploadedPartBytes = await uploadPartWithRetry(session.upload_session_id, partNumber, part, (loaded) => {
            setPartProgress(partNumber, loaded);
          });
          inFlightProgress.delete(partNumber);
          completedBytes += uploadedPartBytes;
          completedParts += 1;
          setUploadProgress({
            status: "uploading",
            uploadedBytes: Math.min(currentUploadedBytes(), selectedFile.size),
            totalBytes: selectedFile.size,
            uploadedChunks: completedParts,
            totalChunks: totalParts,
            message: "Uploading evidence parts directly to object storage...",
          });
        }
      }

      const workerCount = Math.min(MULTIPART_UPLOAD_CONCURRENCY, totalParts);
      await Promise.all(Array.from({ length: workerCount }, () => worker()));
      if (cancelRequestedRef.current) throw new Error("Evidence upload was cancelled.");

      setUploadProgress((current) => current
        ? { ...current, status: "finalizing", message: "Completing multipart upload and hashing evidence from object storage..." }
        : current);
      await completeMultipartEvidenceUpload(session.upload_session_id);
      activeUploadIdRef.current = null;
      setUploadProgress((current) => current
        ? { ...current, status: "completed", uploadedBytes: selectedFile.size, uploadedChunks: totalParts, message: "Evidence upload completed." }
        : current);
      navigate(`/cases/${caseId}`);
    } catch (err) {
      const cancelled = cancelRequestedRef.current;
      activeXhrsRef.current.forEach((xhr) => xhr.abort());
      setUploadProgress((current) => current
        ? { ...current, status: cancelled ? "cancelled" : "failed", message: cancelled ? "Evidence upload was cancelled." : "Evidence upload failed." }
        : current);
      if (!cancelled) {
        setError(err instanceof Error ? err.message : "RAMSight could not upload this evidence.");
      }
    } finally {
      setSubmitting(false);
      activeXhrsRef.current.clear();
      cancelRequestedRef.current = false;
    }
  }

  async function handleCancelUpload() {
    cancelRequestedRef.current = true;
    activeXhrsRef.current.forEach((xhr) => xhr.abort());
    const uploadId = activeUploadIdRef.current;
    if (uploadId) {
      try {
        await cancelMultipartEvidenceUpload(uploadId);
      } catch {
        // The session may already be gone if the backend or object storage cleaned it up.
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
            <span className="field-help">RAMSight uploads large evidence directly to object storage with multipart presigned URLs. The backend does not assemble the full dump in /tmp.</span>
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
                {formatBytes(uploadProgress.uploadedBytes)} of {formatBytes(uploadProgress.totalBytes)} uploaded · part {uploadProgress.uploadedChunks} of {uploadProgress.totalChunks || "pending"} · status {uploadProgress.status}
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
