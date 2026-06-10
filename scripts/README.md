# Scripts

Setup, migration, MinIO bucket creation, validation, and demo helper scripts live here. Scripts must not download or execute malware. They must not commit memory dumps, generated reports, IOC exports, raw Volatility output, or secrets.

## Demo Preflight

Run a lightweight local readiness check before a RAMSight demo:

```bash
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173
```

Optionally summarize an existing analysis job without downloading report files, IOC exports, memory dumps, or raw outputs:

```bash
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173 --job-id <analysis-job-id>
```

Use `--json` for machine-readable output and `--strict` to make optional job result endpoint failures fail the preflight. For a full presentation workflow, see the [local defense runbook](../docs/demo/local-defense-runbook.md).

## Stale Upload Cleanup

Clean expired browser upload temp sessions after an interrupted local upload:

```bash
python scripts/cleanup_stale_upload_sessions.py
```

The cleanup script prints safe aggregate counts only. It does not remove registered evidence, MinIO objects, generated reports, IOC exports, raw Volatility output, or parsed output.
