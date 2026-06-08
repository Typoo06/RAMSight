# Scripts

Setup, migration, MinIO bucket creation, validation, and demo helper scripts live here.

Scripts must not download or execute malware. They must not commit memory dumps, generated reports, IOC exports, raw Volatility output, or secrets.

## Demo Preflight

Run a lightweight local readiness check before a RAMSight demo:

```bash
python scripts/demo/preflight_check.py
```

Optionally summarize an existing analysis job without downloading report files or raw outputs:

```bash
python scripts/demo/preflight_check.py --job-id <analysis-job-id>
```

Use `--json` for machine-readable output and `--strict` to make optional job result endpoint failures fail the preflight.

For a full presentation workflow, see the [local defense runbook](../docs/demo/local-defense-runbook.md).
