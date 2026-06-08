# Documentation

Project documentation lives here, including local operations, demo guidance, architecture notes, developer setup, validation notes, and thesis materials.

## Start Here

- [Local demo operations](operations/local-demo.md)
- [Local demo and thesis defense runbook](demo/local-defense-runbook.md)
- [Developer setup](developer-guide/dev-setup.md)

## Large Evidence and Validation

- [Large evidence browser upload validation](validation/large-evidence-browser-upload.md)

## Architecture

- [Database foundation](architecture/database-foundation.md)

## Final Demo Checklist

```bash
docker compose -f docker-compose.dev.yml up -d postgres redis minio backend worker frontend
docker compose -f docker-compose.dev.yml exec backend alembic upgrade head
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173
git ls-files | grep -Ei '\.(raw|mem|dmp|vmem|lime|aff4)$' || true
git ls-files | grep -Ei '(technical_report|ioc_export|report).*\.(html|json|csv)$' || true
```

The Git checks should return no tracked files.
