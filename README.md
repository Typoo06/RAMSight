# Memory Malware Triage Platform

Initial scaffold for a DFIR-oriented platform that analyzes Windows memory dumps offline using Volatility 3, configurable detection rules, YARA, IOC extraction, risk scoring, and report generation.

## Planned Components

- `backend/`: FastAPI API, database models, service layer, MinIO storage integration, detection/report metadata.
- `worker/`: Celery worker for Volatility execution, parsing, detection, IOC extraction, and report generation.
- `frontend/`: React + TypeScript analyst dashboard.
- `rules/`: YARA rules, Python/config detection rules, and risk scoring configuration.
- `reports/`: HTML/PDF report templates.
- `infra/`: Docker Compose and local service configuration.
- `docs/`: Architecture, API, user, developer, and thesis documentation.
- `scripts/`: Setup, migration, bucket creation, and demo helpers.
- `tests/`: Backend, worker, detection, and integration tests.
- `sample-data/`: Metadata and expected results only.

## Development Status

This is an initial repository scaffold. Business logic is intentionally not implemented yet.

