# Large Evidence Browser Upload

RAMSight uses browser chunked upload for large memory dumps. The frontend slices the selected file with `File.slice()` and sends one chunk at a time to the backend upload-session API. The backend writes chunks to a temporary session file, hashes the completed file from disk, uploads it to MinIO/S3, and stores only metadata in PostgreSQL.

The direct multipart upload endpoint is intentionally capped for demo safety. Use chunked upload for memory dumps and reserve direct upload for small validation files only.

## Configuration

Development defaults are documented in `.env.example`:

```text
EVIDENCE_UPLOAD_TEMP_DIR=/tmp/ramsight-evidence-uploads
EVIDENCE_UPLOAD_CHUNK_SIZE_BYTES=4194304
EVIDENCE_UPLOAD_SESSION_TTL_SECONDS=86400
EVIDENCE_MAX_UPLOAD_BYTES=21474836480
EVIDENCE_DIRECT_UPLOAD_MAX_BYTES=268435456
```

The default chunk size is 16 MiB. Browser upload temporarily needs disk space roughly equal to the evidence size before the file is copied into MinIO/S3. A 6 GiB memory image can require about 6 GiB of temporary upload space plus MinIO object storage.

## Safety Notes

- Do not commit memory dumps, raw outputs, IOC exports, or generated reports.
- Do not store memory dump bytes in PostgreSQL.
- Keep `EVIDENCE_UPLOAD_TEMP_DIR` outside the repository.
- Monitor Docker/WSL disk and memory usage during large upload validation.
- RAMSight does not expose MinIO credentials to the frontend.

## Browser Validation Workflow

1. Start RAMSight with Docker Compose.
2. Open the case evidence upload page in the browser.
3. Select the large memory dump, for example `attack2`.
4. Confirm upload progress shows chunk count, uploaded bytes, and percentage.
5. Monitor `vmmemwsl` and Docker resource usage while upload runs.
6. Confirm RAMSight creates evidence metadata with size, MD5, and SHA256.
7. Start the desired analysis profile, such as `windows_memory_yara_elastic`, after upload completes.

If an upload is cancelled, RAMSight asks the backend to remove the temporary upload session. Expired or failed sessions may still need operational cleanup from the configured temp directory.
