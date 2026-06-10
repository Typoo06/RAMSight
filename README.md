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

## Thesis Report Notes: Chapters 2, 3, and 4

The thesis topic is **"Using Volatility Framework to analyze memory-only malware"**. RAMSight is the practical application built for that topic: it analyzes previously acquired memory dumps in an offline lab workflow, normalizes Volatility results, correlates memory-only malware indicators, and presents findings through a dashboard and technical report.

These notes can be reused as the technical foundation for Chapter 2, Chapter 3, and Chapter 4 of the written report.

### Chapter 2: Requirement Analysis

#### Problem Context

Memory-only malware and process-injection style attacks may leave weak or incomplete evidence on disk. The payload can be loaded into process memory, executed from private executable pages, or hidden behind a legitimate process name. Traditional file-based inspection is therefore not enough for a DFIR workflow. Analysts need a controlled way to inspect memory dumps, correlate process, memory, command-line, network, module, and YARA evidence, and export results for review.

RAMSight solves this problem as a lab-safe triage platform. It does not execute malware and does not download malware samples. The platform receives an acquired memory image, stores it as sensitive evidence, runs Volatility 3 plugins in a worker process, preserves raw plugin output, parses structured artifacts, runs detection rules, extracts IOCs, and generates an HTML technical report.

#### Functional Requirements

RAMSight is designed to support these core workflows:

- Create and manage investigation cases.
- Upload or register memory dump evidence.
- Store evidence metadata, hashes, operating-system metadata, acquisition tool, and acquisition time.
- Store large evidence files and generated outputs in MinIO/S3-compatible object storage instead of PostgreSQL.
- Create asynchronous analysis jobs so long-running Volatility analysis does not block API requests.
- Select Volatility plugins by OS-aware analysis profile.
- Run the Windows MVP plugin profile: `windows.pslist`, `windows.psscan`, `windows.pstree`, `windows.cmdline`, `windows.netscan`, `windows.dlllist`, `windows.handles`, and `windows.malfind`.
- Run optional YARA process-memory profiles such as `windows_memory_yara_elastic`, `windows_memory_yara_neo23x0`, and third-party combined profiles.
- Preserve raw Volatility output for verification.
- Parse raw output into normalized artifacts: process, command, network, module, memory-region, and YARA records.
- Run configurable YAML detection rules and OS-scoped risk scoring.
- Correlate memory-only malware evidence across memory regions, YARA matches, command lines, modules, and network endpoints.
- Extract and export IOCs in JSON/CSV.
- Display findings, IOCs, plugin results, artifacts, analyst review metadata, and reports in the React dashboard.
- Generate a technical HTML report with case metadata, evidence hashes, job details, suspicious processes, memory evidence chains, YARA matches, IOCs, recommendations, and raw output references.

#### Non-Functional Requirements

Important non-functional requirements are:

- **Safety:** analysis is offline and based on memory dump files only.
- **Evidence handling:** dumps are sensitive and must not be committed to Git.
- **Scalability for large files:** memory dumps and raw outputs are stored in object storage, while PostgreSQL stores metadata and normalized records.
- **Reliability:** worker tasks preserve partial results when a plugin, parser, IOC stage, or report stage fails.
- **Traceability:** raw plugin output and parsed output references are retained.
- **Configurable detection:** rules, YARA packs, and scoring thresholds are kept outside hardcoded UI logic.
- **Cross-platform readiness:** Windows is the MVP target, but schemas, artifacts, plugin registry, reports, and frontend types use OS-aware fields and generic artifact names so Linux support can be added later.
- **Practical reporting:** findings are triage indicators requiring analyst review, not automatic malware verdicts.

#### Architecture Principle

The application follows this data flow:

```text
Analyst
  -> React dashboard
  -> FastAPI backend
  -> PostgreSQL metadata + MinIO evidence storage
  -> Redis/Celery analysis queue
  -> Worker
  -> Volatility 3 + YARA
  -> Raw outputs in MinIO
  -> Parsers
  -> Normalized artifacts in PostgreSQL
  -> Detection and risk scoring
  -> IOC extraction
  -> HTML report
  -> Dashboard and report download
```

The backend handles API requests, metadata, validation, job creation, and result queries. The worker handles expensive analysis. PostgreSQL stores structured records. MinIO stores large binary and generated objects. React presents the workflow to the analyst.

#### Selected Solution

RAMSight uses:

- **Volatility 3** for memory forensics because it provides established plugins for processes, modules, network state, command lines, memory regions, and malware-oriented analysis.
- **YARA** for defensive process-memory pattern matching.
- **FastAPI** for a modular API service.
- **Celery and Redis** for asynchronous analysis jobs.
- **PostgreSQL** for relational metadata, artifact, finding, IOC, and report records.
- **MinIO/S3-compatible storage** for evidence, raw outputs, parsed outputs, IOC exports, and reports.
- **React + TypeScript** for a practical DFIR dashboard.
- **Docker Compose** for a reproducible local lab environment.

### Chapter 3: Related Knowledge

#### Memory Forensics

Memory forensics analyzes a captured image of volatile memory to reconstruct the runtime state of a system. It can reveal evidence that is unavailable or incomplete on disk: running processes, command lines, loaded modules, sockets, handles, injected memory pages, shellcode-like regions, and strings or patterns left by malware.

For this project, memory acquisition is assumed to happen outside RAMSight. RAMSight receives the dump and records metadata such as `os_family`, `os_version`, `architecture`, `kernel_version`, `symbol_table`, `acquisition_tool`, and `acquisition_time`.

#### Volatility 3

Volatility 3 is the main analysis engine. The important Windows plugins for this project are:

| Plugin | Purpose |
| --- | --- |
| `windows.pslist` | Enumerates active processes. |
| `windows.psscan` | Scans memory for process objects and can reveal hidden or unlinked process candidates. |
| `windows.pstree` | Reconstructs parent-child process relationships. |
| `windows.cmdline` | Extracts command-line context, useful for encoded PowerShell and suspicious execution. |
| `windows.netscan` | Extracts network endpoints and process ownership. |
| `windows.dlllist` | Lists loaded user-mode modules. |
| `windows.handles` | Collects handle context. |
| `windows.malfind` | Identifies suspicious executable/private memory regions related to injection. |
| `windows.vadyarascan` | Scans process memory VADs with selected YARA rules. |

RAMSight also registers deeper optional plugin profiles for VAD analysis, process hollowing, module inconsistencies, thread analysis, evasion indicators, kernel/rootkit triage, and investigation context.

#### Memory-Only Malware Indicators

Memory-only malware should be treated as a correlation problem. A single indicator is rarely enough. RAMSight focuses on combinations such as:

- A suspicious executable memory region from `malfind`.
- A YARA match in process memory.
- A process command line containing encoded PowerShell or suspicious script keywords.
- A process with public remote network activity.
- A module loaded from `Temp`, `AppData`, `Users\Public`, `/tmp`, or another user-writable path.
- A process visible in `psscan` but missing from `pslist`.
- A system process name running from the wrong path.

These signals are converted into risk findings and then grouped into process-centered evidence chains.

#### YARA

YARA rules describe textual, binary, or regex patterns and boolean conditions for matching suspicious content. In RAMSight, YARA is used as a defensive triage aid for memory scanning. The project supports third-party rule packs such as Elastic and Neo23x0 through import, validation, and build scripts.

YARA matches are not final malware conclusions. They must be interpreted with process identity, memory region, command line, module path, and network context.

#### Risk Scoring and Analyst Review

Risk levels follow this default scale:

```text
0-3      Low
4-7      Medium
8-12     High
13+      Critical
```

Rules include `os_scope` values of `all`, `windows`, or `linux`. This keeps detection extensible while supporting the Windows MVP first. Findings include review fields such as `review_status`, `analyst_verdict`, `severity_override`, and analyst notes, because DFIR results require human validation.

### Chapter 4: Application

#### Application Description

RAMSight is a local web platform for memory malware triage. The analyst creates a case, uploads memory evidence, starts an analysis job, monitors plugin execution, reviews normalized artifacts, checks risk findings and IOCs, and downloads a technical report.

The application is intentionally lab/demo oriented. It is suitable for university project demonstration and controlled validation, but it is not yet a production incident-response platform.

#### Main Workflow

```text
1. Create a case.
2. Upload or register a memory dump.
3. Record evidence hashes and OS/acquisition metadata.
4. Create an analysis job with a selected plugin profile.
5. Dispatch the job to Celery.
6. Worker downloads the dump from MinIO.
7. Worker runs selected Volatility plugins.
8. Worker uploads raw plugin outputs.
9. Parsers normalize plugin output into artifacts.
10. Detection rules generate risk findings.
11. IOC extractor exports JSON/CSV pivots.
12. Report generator creates the technical HTML report.
13. Dashboard displays artifacts, findings, IOCs, plugin coverage, and report links.
```

#### Backend Implementation

The backend is organized around thin FastAPI endpoints and service classes/functions. It manages cases, evidence, analysis jobs, artifact queries, IOC queries, plugin results, risk findings, reports, and downloads. Evidence records store hashes and object-storage references. Analysis jobs store status, selected profile, OS metadata, requested plugins, runtime duration, and errors.

The backend does not run Volatility directly. It sends analysis jobs to Celery through `AnalysisJobDispatcher`, keeping long-running work outside HTTP request handling.

#### Worker Implementation

The worker implements the analysis pipeline in `worker/app/tasks/analysis.py`. It claims queued jobs, creates an isolated workspace, downloads evidence, selects plugins from the OS-aware registry, runs Volatility, uploads raw output, parses structured artifacts, persists results, runs detection, extracts IOCs, and generates reports.

The worker is resilient by design. If one plugin fails, its error is stored in `plugin_results`. If parsing fails for one plugin, the rest of the job can still produce useful records. If IOC extraction or report generation fails, completed plugin and artifact records are still preserved.

#### Detection Implementation

Detection rules are stored under `rules/detection/`, and scoring configuration is stored under `rules/risk_scoring/`. The detection engine evaluates artifacts with rules such as:

- `WIN_SYSTEM_PROCESS_WRONG_PATH`
- `WIN_SUSPICIOUS_PARENT_CHILD`
- `WIN_PSSCAN_ONLY_PROCESS`
- encoded PowerShell and suspicious command rules
- suspicious module path rules
- network connection rules
- malfind memory-region rules
- YARA match rules
- memory-only correlation rules

The most important rules for the thesis are memory-only correlation rules:

- `MEMORY_PROCESS_INJECTION_CANDIDATE`
- `MEMORY_REGION_WITH_NETWORK_ACTIVITY`
- `MEMORY_REGION_WITH_SUSPICIOUS_COMMAND`
- `MEMORY_REGION_WITH_SUSPICIOUS_MODULE`
- `YARA_MATCH_IN_PROCESS_MEMORY`

These rules help turn raw Volatility observations into analyst-friendly evidence chains.

#### Frontend and Reporting

The React frontend includes pages for dashboard, case list, case creation, case detail, evidence upload, and analysis job status. The analysis job page loads plugin results, artifacts, risk findings, IOCs, reports, and job status. It displays process evidence, memory-region records, YARA matches, plugin coverage, finding review controls, IOC tables, and report download links.

The technical HTML report includes:

- Executive summary.
- Case information.
- Evidence metadata and hashes.
- Analysis job metadata.
- Plugin coverage and status.
- Top actionable detections.
- Suspicious process summary.
- Memory-only evidence chains.
- Threat-oriented IOCs and investigation artifacts.
- Network indicators.
- Suspicious module paths.
- Memory region findings.
- YARA matches.
- Raw and parsed output references.
- Incident response recommendations.
- Analyst notes.

PDF export is not implemented in the current demo build. For thesis submission, use the generated HTML report and convert it externally if a PDF copy is required.

#### Practical Lab Scenarios

Recommended safe lab scenarios for Chapter 4 are:

| Scenario | Goal | Expected RAMSight evidence |
| --- | --- | --- |
| Process injection memory dump | Show memory-region and YARA triage. | `malfind` region, process-centered finding, optional YARA match. |
| Office to encoded PowerShell | Show suspicious parent-child and command detection. | `pstree` relationship, `cmdline` artifact, encoded PowerShell finding. |
| Hidden process candidate | Show cross-view process analysis. | Process appears in `psscan` but not `pslist`. |
| Injected process with public network activity | Show memory + network correlation. | Critical memory-region-with-network finding and IOC export. |
| Suspicious module path | Show module-path triage. | DLL/module loaded from temporary or user-writable path. |

#### Verification

Use the following verification commands before a demo or thesis defense:

```bash
docker compose -f docker-compose.dev.yml exec backend pytest /tests/backend
docker compose -f docker-compose.dev.yml exec worker pytest /tests/worker
docker compose -f docker-compose.dev.yml exec frontend npm run build
python -m pytest tests/scripts
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173
```

Also confirm that no evidence files or generated reports are tracked by Git:

```bash
git ls-files | grep -Ei '\.(raw|mem|dmp|vmem|lime|aff4)$' || true
git ls-files | grep -Ei '(technical_report|ioc_export|report).*\.(html|json|csv)$' || true
```

#### Current Limitations

- Windows analysis is the MVP; Linux support is reserved in the architecture but not fully implemented.
- Findings are triage indicators and require analyst validation.
- Third-party YARA packs can be noisy and slow on large dumps.
- The local/dev stack does not include production authentication, RBAC, TLS, backup, or secret-manager integration.
- PDF report export is planned but not implemented in the current demo build.
