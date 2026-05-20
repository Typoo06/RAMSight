# Development Setup

This project is Docker-first for local development.

## Prerequisites

- Docker Desktop or Docker Engine with Compose support
- VS Code task runner support, if using the checked-in `.vscode/tasks.json`

## Environment

Copy `.env.example` to `.env` for local overrides. Keep secrets out of Git and use development-only placeholder values locally.

The default development services are:

- Backend API: `http://localhost:8000`
- Frontend: `http://localhost:5173`
- MinIO API: `http://localhost:9000`
- MinIO Console: `http://localhost:9001`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

## Common Commands

Prefer the existing VS Code tasks when available:

- `docker: up dev`
- `docker: down dev`
- `backend: tests`
- `frontend: lint`

Equivalent shell commands:

```powershell
docker compose -f docker-compose.dev.yml up --build
docker compose -f docker-compose.dev.yml down
cd backend && pytest
cd frontend && npm run lint
```

To validate Compose syntax without starting services:

```powershell
docker compose -f docker-compose.dev.yml config
```

## Database Migrations

Alembic configuration lives under `backend/`. Run migrations from inside the backend container so the service hostname `postgres` resolves correctly:

```powershell
docker compose -f docker-compose.dev.yml exec backend alembic upgrade head
```

To inspect the current revision:

```powershell
docker compose -f docker-compose.dev.yml exec backend alembic current
```

## Safety Notes

- Do not commit memory dumps or real evidence files.
- Use MinIO/S3 or ignored local folders for large evidence.
- Do not run malware samples.
- Keep analysis offline and based on memory dump files.
