# RAMSight

RAMSight is a local/dev memory forensics and memory-only malware triage platform for university project and thesis demonstration work. It analyzes acquired memory images offline with Volatility 3 and YARA, normalizes artifacts into PostgreSQL, stores large files in MinIO/S3, and presents findings, IOCs, analyst review metadata, and HTML reports through a React frontend.

The project is Windows-first for the MVP while keeping the data model and rule/plugin structure OS-aware for future Linux support. Findings are triage indicators that require analyst review; they are not conclusive by themselves.

## Local Services

The Docker Compose development stack includes:

- `backend`: FastAPI API service
- `frontend`: React + TypeScript dashboard
- `worker`: Celery analysis worker
- `postgres`: metadata and normalized records
- `redis`: Celery broker/result backend
- `minio`: evidence, raw outputs, parsed outputs, IOC exports, and reports

## Quick Start

Start the local services:

```bash
docker compose -f docker-compose.dev.yml up -d postgres redis minio backend worker frontend
```

Run database migrations:

```bash
docker compose -f docker-compose.dev.yml exec backend alembic upgrade head
```

Check local readiness:

```bash
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173
```

For the memory-only malware defense demo, use the `windows_memory_yara_elastic` analysis profile when starting a Windows memory job. It runs the standard Volatility triage plugins plus process-memory YARA scanning with the validated Elastic third-party pack. The legacy `windows_memory_yara` profile remains a backward-compatible alias for Elastic YARA; it does not use the archived RAMSight demo rules. The faster `windows_default` profile is still available when YARA scan time is not acceptable.

Optional advanced profiles are available for deeper Volatility coverage: `windows_memory_deep`, `windows_memory_deep_yara_elastic`, `windows_memory_deep_yara_neo23x0`, `windows_memory_deep_yara_third_party_all`, `windows_malware_evasion`, `windows_kernel_rootkit`, and `windows_investigation_context`. The `windows_memory_yara_third_party_all` profile is baseline triage plus Elastic + Neo23x0 YARA and is slow; `windows_memory_deep_yara_third_party_all` adds deep VAD/injection/thread/module plugins and is very slow, intended for advanced investigation only.

Run a strict preflight against the known local demo job, if that job exists in your database:

```bash
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173 --job-id 48c0f65b-79e7-4728-bc27-f55f986a7ae2 --strict
```

## Verification Commands

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

Script tests:

```bash
python -m pytest tests/scripts
```

## Documentation

Start here for local demo and submission workflows:

- [Documentation index](docs/README.md)
- [Local demo operations](docs/operations/local-demo.md)
- [Local demo and thesis defense runbook](docs/demo/local-defense-runbook.md)
- [Large evidence browser upload notes](docs/validation/large-evidence-browser-upload.md)
- [YARA rule guide](docs/YARA_RULES.md)
- [Third-party rule pack guide](docs/rules/THIRD_PARTY_RULES.md)
- [Developer setup](docs/developer-guide/dev-setup.md)

## Safety Rules

- Do not execute malware with this platform.
- Do not commit memory dumps or real evidence files.
- Do not commit generated reports, IOC exports, raw Volatility output, or parsed output files.
- Store evidence, raw outputs, parsed outputs, reports, and IOC exports in MinIO/S3.
- Store only metadata, normalized artifacts, findings, IOCs, reports metadata, and analyst review metadata in PostgreSQL.
- Keep secrets out of Git. Use `.env.example` only for local-development placeholders.
- Use browser chunked upload for large memory dumps. The direct multipart upload endpoint is capped for demo safety.
- PDF export is not implemented in the current demo build; use the generated technical HTML report and IOC JSON/CSV exports.
- This project is lab/demo-ready, not production-ready. It intentionally does not include full production auth/RBAC, TLS, backup, or secret-manager integration.

Safety checks before committing:

```bash
git ls-files | grep -Ei '\.(raw|mem|dmp|vmem|lime|aff4)$' || true
git ls-files | grep -Ei '(technical_report|ioc_export|report).*\.(html|json|csv)$' || true
```

Both commands should return no tracked files.
