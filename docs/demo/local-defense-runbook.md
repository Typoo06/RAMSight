# RAMSight Local Demo and Thesis Defense Runbook

This runbook supports a local RAMSight demonstration for the thesis topic: memory-only malware triage with Volatility Framework. It is intended for a university project or defense setting, not for production operations.

RAMSight findings should be presented as triage indicators that support investigation. They require analyst review and are not conclusive by themselves. Demo YARA rules are triage aids and should not be described as production malware signatures.

## 1. Demo Purpose

The demo shows how RAMSight handles a large Windows memory image in a local Docker Compose environment:

- upload or reference memory evidence without storing dump bytes in PostgreSQL
- run Volatility 3 plugins through a worker pipeline
- normalize process, network, module, command, memory-region, and YARA artifacts
- correlate suspicious memory-region evidence with findings and IOCs
- export IOCs and generate a technical HTML report
- support analyst review of findings

The key message is that memory analysis can expose evidence that may not exist as a normal file on disk, especially for memory-only or process-injection style activity.

## 2. Pre-Demo Checklist

Before presenting, confirm:

- Docker Desktop or Docker Engine is running.
- WSL is healthy if using Docker Desktop on Windows.
- There is enough disk space for Docker volumes, MinIO objects, and temporary upload files.
- No memory dump files are tracked by Git.
- Docker Compose services are started.
- Database migrations are applied.
- `/health` and `/ready` pass.
- The local preflight script passes.
- The known-good attack2 job is still available if you plan to use the completed result instead of rerunning analysis.

Known-good local demo example, not a universal expected value:

```text
Job ID: 48c0f65b-79e7-4728-bc27-f55f986a7ae2
Evidence: attack2_process_Injection.mem
OS: Windows 10 x64
Profile: windows_memory_yara
Plugin results: 9 total, 9 completed, 0 failed
Risk findings: 69
IOC records: 60
Reports: 1
```

## 3. Start Commands

Start the local services:

```bash
docker compose -f docker-compose.dev.yml up -d postgres redis minio backend worker frontend
```

Apply migrations:

```bash
docker compose -f docker-compose.dev.yml exec backend alembic upgrade head
```

Check service state:

```bash
docker compose -f docker-compose.dev.yml ps
```

## 4. Preflight Commands

Run the basic local preflight:

```bash
python scripts/demo/preflight_check.py \
  --api-base http://localhost:8000/api/v1 \
  --frontend-url http://localhost:5173
```

Run the strict preflight with the known-good local job example:

```bash
python scripts/demo/preflight_check.py \
  --api-base http://localhost:8000/api/v1 \
  --frontend-url http://localhost:5173 \
  --job-id 48c0f65b-79e7-4728-bc27-f55f986a7ae2 \
  --strict
```

A passing preflight means the demo surface is reachable, dependencies are ready, and the optional job metadata is available. It does not prove that a new large analysis run will always complete.

## 5. Suggested Demo Flow

1. Open the frontend:

   ```text
   http://localhost:5173
   ```

2. Show the case and evidence metadata. Point out OS metadata, file size, MD5/SHA256 hashes, and that PostgreSQL stores metadata rather than dump bytes.

3. Upload or register a lab memory dump. For large memory dumps, use the browser chunked upload workflow rather than the direct multipart upload endpoint.

4. Start analysis with the `windows_memory_yara` profile. This is the recommended memory-only malware demo path because it includes process-memory YARA scanning in addition to the standard Windows Volatility triage plugins.

5. Open the completed attack2 analysis job. Use the known-good job if the goal is presentation stability instead of rerunning a large analysis.

6. Show plugin results. Explain the role of the main Windows plugins:

   - `windows.pslist`: active process list
   - `windows.psscan`: process scan for hidden or unlinked process candidates
   - `windows.pstree`: process hierarchy
   - `windows.cmdline`: process command lines
   - `windows.netscan`: network endpoints
   - `windows.dlllist`: loaded modules
   - `windows.handles`: handle metadata where available
   - `windows.malfind`: suspicious memory-region evidence
   - `windows.vadyarascan`: YARA scan over process memory regions

7. Explain suspicious findings and memory-only evidence. Focus on:

   - executable memory regions from `malfind`
   - process-centered risk summaries
   - YARA process-memory matches as triage support
   - IOC records derived from normalized artifacts and findings

8. Review IOC records and export IOC JSON/CSV if useful.

9. Open the technical HTML report. PDF export is not implemented in the current demo build. Emphasize the report sections:

   - Executive Summary
   - Plugin Results
   - Suspicious Process Summary
   - Memory-only Evidence Chains
   - IOC Summary
   - YARA Matches
   - Raw and parsed output references

10. Show analyst review workflow if relevant. Keep the message cautious: review status and notes help organize triage, but they do not replace expert analysis.

## 6. Thesis Defense Talking Points

Use concise, careful language:

- Memory analysis is useful because process-injection and memory-only activity may leave stronger evidence in RAM than on disk.
- Volatility is used because it provides established memory forensics plugins for processes, modules, network state, command lines, and suspicious memory regions.
- YARA is used as triage support for matching patterns in process memory. Demo rules are not production malware signatures.
- RAMSight normalizes artifacts so analysts can compare evidence across plugins instead of reading raw Volatility output only.
- Risk findings and IOCs are generated from normalized artifacts to support investigation and reporting.
- The HTML report and IOC exports make results easier to review, preserve, and discuss.
- Analyst review fields support a practical triage workflow for confirming, dismissing, or documenting findings.

Limitations to state clearly:

- RAMSight is not a replacement for expert forensic analysis.
- Findings are triage indicators and are not conclusive by themselves.
- Demo YARA rules are not production malware signatures.
- Results depend on memory image quality, operating-system support, symbol/plugin behavior, and Volatility output.
- False positives remain possible, especially for noisy user-writable paths, broad YARA rules, and benign software behavior.
- The current environment is local/dev and intentionally does not include production auth or RBAC.

## 7. Troubleshooting

### Backend Not Reachable

```bash
curl http://localhost:8000/health
docker compose -f docker-compose.dev.yml logs backend --tail=100
```

If `/health` fails, check whether the backend container is running and whether port `8000` is available.

### Frontend Not Reachable

```bash
curl http://localhost:5173
docker compose -f docker-compose.dev.yml logs frontend --tail=100
```

If the browser still shows stale UI behavior, refresh the page and confirm the frontend container was rebuilt when needed.

### Readiness Is `not_ready`

```bash
curl http://localhost:8000/ready
docker compose -f docker-compose.dev.yml ps
```

Readiness checks database, Redis, and object storage. A failed dependency should be repaired before starting a new large upload or analysis run.

### Redis Down

```bash
docker compose -f docker-compose.dev.yml logs redis --tail=100
docker compose -f docker-compose.dev.yml restart redis backend worker
```

Redis is needed for Celery dispatch. If Redis was unavailable when a job was created, create a fresh job after services recover.

### MinIO or Object Storage Down

```bash
docker compose -f docker-compose.dev.yml logs minio --tail=100
curl http://localhost:9000/minio/health/live
```

Object storage is required for evidence, raw outputs, parsed outputs, reports, and IOC exports. Do not bypass it by storing dump bytes in PostgreSQL.

### Worker Not Consuming Jobs

```bash
docker compose -f docker-compose.dev.yml logs worker --tail=100
docker compose -f docker-compose.dev.yml restart worker
```

Check whether Redis is ready and whether the worker image has the expected Volatility/YARA dependencies.

### Upload Session Left Behind After Crash

```bash
python scripts/cleanup_stale_upload_sessions.py
```

The cleanup script removes expired upload-session temp directories only. It does not remove registered evidence, MinIO objects, reports, IOC exports, or raw plugin output.

### Report Looks Old

Generated technical reports are persisted HTML files. If a report was generated before later display improvements, download a report from a newer completed job or regenerate by rerunning the analysis workflow if that is acceptable for the demo schedule.

### WSL or Docker Resource Pressure

```bash
df -h
free -h
docker system df
```

Large memory dumps can require substantial temporary disk space and long-running worker time. Avoid rerunning a 5 GiB analysis during a live defense unless you have already validated the environment and have enough time.

## 8. Safety Checklist

Before committing or presenting from the repository, run:

```bash
git ls-files | grep -Ei '\.(raw|mem|dmp|vmem|lime|aff4)$' || true
git ls-files | grep -Ei '(technical_report|ioc_export|report).*\.(html|json|csv)$' || true
```

Both commands should return no tracked files. Memory dumps, raw Volatility outputs, generated reports, and IOC exports should remain outside Git.

## 9. Closing Message

A strong closing statement for the demo is:

RAMSight demonstrates a local workflow for turning volatile memory evidence into normalized artifacts, triage findings, IOCs, and a technical report. The result supports investigation of memory-only malware behavior, but each finding still requires analyst validation and supporting context.
