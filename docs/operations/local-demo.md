# Local Demo Operations

RAMSight is currently intended for local university-project validation and demo workflows. These commands keep the Docker Compose environment predictable while handling large memory evidence safely.

## Start Services

Start already-built services in the background:

```bash
docker compose -f docker-compose.dev.yml up -d postgres redis minio backend worker frontend
```

Check container state:

```bash
docker compose -f docker-compose.dev.yml ps
```

## Rebuild Images

Rebuild the application images after dependency or Dockerfile changes:

```bash
docker compose --progress=plain -f docker-compose.dev.yml build backend worker frontend
```

## Database Migrations

Run migrations from the backend container so Compose service names resolve correctly:

```bash
docker compose -f docker-compose.dev.yml exec backend alembic upgrade head
```

Inspect the current revision:

```bash
docker compose -f docker-compose.dev.yml exec backend alembic current
```

## Health and Readiness

The basic health endpoint confirms the API process is running:

```bash
curl http://localhost:8000/health
```

The readiness endpoint checks database, Redis, and object storage availability without exposing credentials or object keys:

```bash
curl http://localhost:8000/ready
```

A `not_ready` response means one or more local dependencies need attention. Check service state and logs before rerunning large uploads or analysis jobs.


## Demo Preflight

Run the lightweight preflight before a local demo or thesis presentation. It checks backend health, backend readiness, the frontend URL, and whether Git is tracking memory-dump-like files. It does not upload evidence, download reports, or run a Volatility analysis job.

```bash
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173
```

To include a completed analysis job summary without downloading generated files:

```bash
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173 --job-id <analysis-job-id>
```

For machine-readable output:

```bash
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173 --json
```

Use `--strict` with `--job-id` when optional job result endpoints should fail the preflight instead of producing warnings. A passing preflight means the local demo surface is reachable and basic dependencies are ready; it does not prove that a new large memory analysis will complete.

## Stale Upload Cleanup

Browser chunked uploads use temporary disk space before the completed evidence file is uploaded to MinIO/S3. If the browser, backend, Docker, or WSL shuts down mid-upload, expired upload sessions can remain in the configured temp directory.

Run cleanup from the repository root:

```bash
python scripts/cleanup_stale_upload_sessions.py
```

The script removes only expired UUID-named upload session directories under `EVIDENCE_UPLOAD_TEMP_DIR` and prints aggregate counts. It does not remove registered evidence records, MinIO objects, reports, IOC exports, or raw Volatility outputs.

## Large Evidence Disk and Memory Notes

Large memory dumps require temporary upload space plus object storage space. A 6 GiB memory image can temporarily need about 6 GiB in the upload temp directory and additional MinIO storage after completion.

On WSL/Docker Desktop, monitor disk and memory pressure during upload and analysis. If uploads stall or containers become unhealthy, inspect resource usage before retrying.

Use browser chunked upload for large memory dumps. The direct multipart upload endpoint is capped by `EVIDENCE_DIRECT_UPLOAD_MAX_BYTES` so an accidental large direct upload fails early instead of filling temporary disk space.

For the thesis defense demo, choose the `windows_memory_yara_elastic` analysis profile. It runs the Windows Volatility triage plugins plus the validated Elastic third-party YARA pack for process-memory scanning. The generated report is HTML; PDF export is not implemented in the current demo build.


## Test and Build Commands

Backend tests:

```bash
docker compose -f docker-compose.dev.yml exec backend pytest /tests/backend
```

Worker tests:

```bash
docker compose -f docker-compose.dev.yml exec worker pytest /tests/worker
```

Frontend build:

```bash
docker compose -f docker-compose.dev.yml exec frontend npm run build
```

Frontend lint, if a lint script exists:

```bash
docker compose -f docker-compose.dev.yml exec frontend sh -lc "npm run | grep -q '^  lint' && npm run lint || echo 'No lint script; skipping lint'"
```

## Troubleshooting Commands

```bash
docker compose -f docker-compose.dev.yml logs backend --tail=100
docker compose -f docker-compose.dev.yml logs worker --tail=100
docker compose -f docker-compose.dev.yml logs minio --tail=100
docker compose -f docker-compose.dev.yml logs redis --tail=100
```

Confirm no memory dump files are tracked by Git:

```bash
git ls-files | grep -Ei '\.(raw|mem|dmp|vmem|lime|aff4)$' || true
```

Generated report and IOC export files should also stay out of Git:

```bash
git ls-files | grep -Ei '(technical_report|ioc_export|report).*\.(html|json|csv)$' || true
```

## Safety Reminders

- Do not commit memory dumps or real evidence files.
- Do not store memory dump bytes in PostgreSQL.
- Do not expose MinIO credentials to the frontend.
- Keep analysis offline and based on acquired memory images.
