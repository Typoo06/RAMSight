# Project Structure

This document describes the repository layout for RAMSight, a local/dev memory forensics and memory-only malware triage platform.

The platform is designed to support both Windows and Linux memory dump analysis.

Implementation priority:

- MVP: Windows memory dump analysis first.
- Planned extension: Linux memory dump analysis.
- Architecture, database models, API schemas, detection rules, plugin registry, and frontend types must be OS-aware from the beginning.

```text
RAMSight/
├── backend/                 # FastAPI API service
├── worker/                  # Celery analysis worker
├── frontend/                # React + TypeScript dashboard
├── rules/                   # Detection, YARA, and risk scoring rules
├── reports/                 # Report templates
├── infra/                   # Docker and service configuration
├── docs/                    # Project documentation
├── scripts/                 # Setup and operational scripts
├── tests/                   # Automated tests
├── sample-data/             # Metadata and expected results only
├── AGENTS.md                # Repository instructions for Codex
├── .env.example             # Example local configuration
└── .gitignore               # Local, generated, and sensitive file ignores
````

---

## Cross-Platform Analysis Strategy

The system must not hardcode Windows-only assumptions.

Each evidence file and analysis job should include OS-aware metadata:

```text
os_family: windows | linux | unknown
os_version
architecture
kernel_version
symbol_table
acquisition_tool
acquisition_time
```

The MVP will implement Windows analysis first, but the data model and rule system must allow Linux support later without major schema redesign.

Preferred cross-platform artifact names:

```text
process_artifacts
network_artifacts
module_artifacts
memory_region_artifacts
command_artifacts
yara_matches
iocs
risk_findings
plugin_results
reports
```

Avoid Windows-only top-level model names such as:

```text
dll_artifacts
malfind_artifacts
```

Instead, use generic models and store the plugin origin in fields such as:

```text
source_plugin = windows.dlllist
source_plugin = windows.malfind
source_plugin = linux.lsmod
source_plugin = linux.vmayarascan
```

---

## Backend

```text
backend/
├── app/
│   ├── api/v1/endpoints/    # FastAPI route modules
│   ├── core/                # Settings, security, logging, shared configuration
│   ├── db/                  # Database session and migration support
│   ├── models/              # SQLAlchemy models
│   ├── schemas/             # Pydantic request/response schemas
│   ├── services/            # Business/service layer
│   ├── storage/             # MinIO/S3 client integration
│   ├── detection/           # Rule metadata, risk scoring helpers, recommendation helpers
│   ├── reports/             # Report metadata/service integration
│   └── main.py              # FastAPI application entry point
└── pyproject.toml           # Backend Python package configuration
```

### Backend Responsibilities

The backend is responsible for:

```text
- User authentication
- Case management
- Evidence metadata management
- Evidence upload registration
- Hash calculation metadata
- Analysis job creation
- Job status tracking
- Artifact query APIs
- IOC query/export APIs
- Report metadata and download APIs
- Dashboard summary APIs
```

The backend should not run heavy Volatility analysis directly inside request handlers. Heavy analysis must be delegated to the worker.

---

## Worker

```text
worker/
├── app/
│   ├── celery_app.py        # Celery application entry point
│   ├── tasks/               # Celery task modules
│   ├── volatility/          # Volatility runner integration
│   ├── parsers/             # Volatility output parsers
│   ├── detection/           # Detection pipeline and risk scoring execution
│   ├── ioc/                 # IOC extraction
│   ├── reports/             # Report generation tasks
│   └── utils/               # Temporary workspace, job logging, helpers
└── pyproject.toml           # Worker Python package configuration
```

### Worker Responsibilities

The worker handles long-running analysis jobs:

```text
1. Receive analysis job from Celery
2. Download memory dump from MinIO/S3
3. Create isolated temporary workspace
4. Run selected Volatility plugins
5. Preserve raw plugin outputs
6. Parse plugin outputs into structured artifacts
7. Run detection rules
8. Calculate risk scores
9. Extract IOC
10. Generate HTML reports
11. Upload outputs and reports to MinIO/S3
12. Update job status in PostgreSQL
```

---

## Volatility Plugin Profiles

Plugin execution must be based on OS profiles.

### Windows MVP Plugin Profile

```text
windows.pslist
windows.psscan
windows.pstree
windows.cmdline
windows.netscan
windows.dlllist
windows.handles
windows.malfind
windows.vadyarascan (optional windows_memory_yara profile)
```

### Planned Linux Plugin Profile

Linux support is planned for later. The initial architecture should reserve support for plugins such as:

```text
linux.pslist
linux.bash
linux.lsmod
linux.lsof
linux.elfs
linux.check_creds
linux.check_syscall
linux.check_modules
linux.hidden_modules
linux.vmayarascan
```

The MVP does not need to implement Linux parsing immediately, but the plugin registry should allow adding Linux plugin groups later.

---

## Artifact Model Strategy

Artifacts should be modeled by forensic concept, not by a single operating system.

### Process Artifacts

Used for both Windows and Linux process information.

Possible sources:

```text
windows.pslist
windows.psscan
windows.pstree
linux.pslist
```

### Network Artifacts

Used for network connection data.

Possible sources:

```text
windows.netscan
Linux network-related plugins in later extension
```

### Module Artifacts

Used for loaded modules, DLLs, shared libraries, kernel modules, or ELF-related mappings.

Possible sources:

```text
windows.dlllist
linux.lsmod
linux.elfs
```

### Memory Region Artifacts

Used for suspicious memory regions, injected code, executable memory pages, or YARA scan regions.

Possible sources:

```text
windows.malfind
linux.vmayarascan
yarascan
```

### Command Artifacts

Used for command-line arguments, shell history, PowerShell commands, Bash history, or suspicious execution strings.

Possible sources:

```text
windows.cmdline
linux.bash
```

---

## Frontend

```text
frontend/
├── src/
│   ├── api/                 # Backend API clients
│   ├── components/          # Reusable UI components
│   ├── pages/               # Dashboard pages
│   ├── hooks/               # React hooks
│   ├── types/               # Shared TypeScript types
│   ├── utils/               # Formatting and helper functions
│   └── styles/              # Global styles
├── package.json             # Frontend package metadata
├── tsconfig.json            # TypeScript configuration
└── vite.config.ts           # Vite configuration
```

### Frontend Responsibilities

The frontend should support:

```text
- Login
- Case list
- Create case
- Evidence upload
- Evidence metadata display
- OS family display: Windows / Linux / Unknown
- Analysis job status
- Suspicious process table
- Process detail page
- Network artifact table
- Module artifact table
- Memory region findings
- YARA matches
- IOC table
- Report download
```

The frontend must not duplicate detection logic. Detection and risk scoring belong to the backend/worker.

---

## Rules

```text
rules/
├── yara/                    # YARA rules
├── detection/               # YAML detection rules
└── risk_scoring/            # Risk score profiles
```

### Rule Design

Detection rules must support OS scoping:

```text
os_scope: all
os_scope: windows
os_scope: linux
```

Example rule categories:

```text
- suspicious process name or path
- system process running from wrong path
- suspicious parent-child relationship
- encoded PowerShell command
- suspicious Bash command
- external network connection
- hidden process candidate
- suspicious module path
- suspicious memory region
- malfind hit
- YARA match
```

### Risk Levels

Default risk levels:

```text
0–3      Low
4–7      Medium
8–12     High
13+      Critical
```

---

## Reports

```text
reports/
├── templates/               # Jinja2 HTML report templates
└── static/                  # CSS, images, report assets
```

Reports should support:

```text
- Technical HTML report
- Executive-summary style sections inside the technical report
- IOC export references
```

The MVP generates HTML reports. PDF export is planned for a later task and should reuse the same HTML template.

Report content should include:

```text
1. Case information
2. Evidence metadata
3. Evidence hash values
4. OS family and architecture
5. Analysis job information
6. Top suspicious processes
7. Risk score summary
8. Network indicators
9. Module artifacts
10. Memory region findings
11. YARA matches
12. IOC table
13. Analyst notes
14. Incident response recommendations
15. References to raw plugin outputs
```

---

## Infra

```text
infra/
├── nginx/                   # Reverse proxy configuration
├── postgres/                # PostgreSQL initialization and backup scripts
├── redis/                   # Redis configuration
├── minio/                   # MinIO bucket setup and policies
└── docker/                  # Dockerfile.dev / Dockerfile templates
```

The development stack should include:

```text
frontend
backend
worker
postgres
redis
minio
```

Optional services:

```text
nginx
flower
pgadmin
minio-console
```

---

## MinIO / S3 Storage Layout

Large memory dumps must not be stored in PostgreSQL.

PostgreSQL stores metadata only. MinIO/S3 stores large files and generated outputs.

```text
evidences/
└── case-{case_id}/
    └── evidence-{evidence_id}/
        └── memory_dump.raw

volatility-outputs/
└── case-{case_id}/
    └── job-{job_id}/
        ├── raw/
        ├── parsed/
        └── logs/

reports/
└── case-{case_id}/
    └── job-{job_id}/
        ├── technical_report.html
        ├── executive_summary.html
        └── ioc_export.csv

temp/
└── job-{job_id}/
```

---

## Database Entity Direction

The database should support the following major entities:

```text
users
cases
evidences
analysis_jobs
plugin_results
process_artifacts
network_artifacts
module_artifacts
memory_region_artifacts
command_artifacts
yara_matches
iocs
risk_findings
reports
analyst_notes
audit_logs
```

General relationship:

```text
Case
 ├── Evidence
 │    └── AnalysisJob
 │         ├── PluginResult
 │         ├── ProcessArtifact
 │         ├── NetworkArtifact
 │         ├── ModuleArtifact
 │         ├── MemoryRegionArtifact
 │         ├── CommandArtifact
 │         ├── YaraMatch
 │         ├── IOC
 │         ├── RiskFinding
 │         └── Report
 └── AnalystNote
```

---

## Docs

```text
docs/
├── architecture/            # System architecture, data flow, database design
├── api/                     # OpenAPI and API references
├── demo/                    # Local demo and thesis defense runbooks
├── operations/              # Local operations and reliability notes
├── deployment/              # Docker setup and deployment instructions
├── user-guide/              # User-facing guide
├── developer-guide/         # Developer guide
├── validation/              # Validation notes and sanitized examples
└── thesis-materials/        # Materials used for academic report
```

---

## Scripts

```text
scripts/
├── demo/
│   └── preflight_check.py   # Local demo readiness checks
├── validation/              # Small validation summary helpers
├── cleanup_stale_upload_sessions.py
└── README.md
```

---

## Tests

```text
tests/
├── backend/                 # Backend API and service tests
├── worker/                  # Worker and pipeline tests
├── detection/               # Rule engine, risk score, IOC tests
└── integration/             # End-to-end flow tests
```

Testing should cover:

```text
- API health checks
- case creation
- evidence metadata creation
- evidence hash calculation
- job creation
- plugin registry selection by OS
- parser output normalization
- detection rule execution
- IOC extraction
- report generation
```

---

## Sample Data

```text
sample-data/
├── README.md
├── memory-dumps/
│   ├── .gitkeep
│   └── DO_NOT_COMMIT_LARGE_FILES.txt
├── metadata/
└── expected-results/
```

Do not commit real memory dump files.

Only commit:

```text
- metadata
- source links
- expected IOC examples
- expected findings
- small parser fixtures
```

---

## Evidence Safety

Large memory dumps must not be committed to Git.

Use MinIO/S3 or ignored local folders for:

```text
- memory dumps
- generated Volatility outputs
- generated reports
- generated IOC exports
- temporary workspaces
```

Memory dump files may contain sensitive data. Treat them as forensic evidence.

The system should calculate and store:

```text
MD5
SHA256
file size
original filename
upload time
acquisition time
acquisition tool
os_family
architecture
kernel_version
symbol_table
```

---

## MVP Scope

The MVP focuses on Windows memory analysis.

Required MVP features:

```text
- user login
- create case
- upload memory dump
- calculate hash values
- store evidence in MinIO/S3
- create analysis job
- run Windows Volatility plugin profile
- preserve raw plugin outputs
- parse core artifacts
- run detection rules
- calculate risk score
- extract IOC
- generate HTML report
- show results in React dashboard
```

Linux support is a planned extension. The schema, rule engine, plugin registry, report templates, and frontend types must be ready for Linux support, but Linux parsing does not need to be implemented in the first MVP.

---

## Thesis Report Chapter 2: Requirement Analysis

This section documents the detailed requirement analysis for the thesis topic:

```text
Using Volatility Framework to analyze memory-only malware.
```

RAMSight is the application component of the thesis. It demonstrates how a DFIR-oriented platform can support offline memory dump analysis, triage memory-only malware indicators, and present results in a form that is useful for lab validation, reporting, and analyst review.

### 2.1 Problem Statement

Memory-only malware and process-injection techniques reduce reliance on files stored on disk. A malicious payload may be injected into a legitimate process, executed from private memory pages, loaded reflectively, or controlled through script-based commands. In these cases, disk artifacts alone may not be enough to explain what happened.

The platform therefore needs to inspect volatile memory evidence and correlate multiple forensic signals:

```text
process list
process scan
process tree
command lines
network endpoints
loaded modules
memory regions
YARA matches
IOCs
analyst notes
raw plugin output references
```

The key requirement is not only to run Volatility, but to transform Volatility output into a repeatable triage workflow:

```text
memory dump -> raw plugin output -> normalized artifacts -> detection findings -> IOC export -> technical report
```

The system must remain safe for a university lab. It must not execute malware samples. It analyzes already acquired memory dumps only.

### 2.2 Stakeholders and Users

Primary users:

```text
- Student or researcher demonstrating the thesis project
- DFIR analyst in a controlled lab
- Instructor or reviewer validating the workflow
```

Secondary users:

```text
- Developer extending Volatility plugin support
- Developer adding detection rules
- Developer preparing demo data and report evidence
```

The user experience should prioritize practical DFIR tasks: create a case, add evidence, start analysis, inspect suspicious processes, inspect memory-only evidence chains, export IOCs, and download the technical report.

### 2.3 Functional Requirements

#### Case Management

The system must support:

```text
- creating a case
- listing cases
- viewing case details
- associating evidence, jobs, reports, and analyst notes with a case
```

Relevant repository areas:

```text
backend/app/models/case.py
backend/app/services/case_service.py
backend/app/api/v1/endpoints/cases.py
frontend/src/pages/CasesPage.tsx
frontend/src/pages/CaseCreatePage.tsx
frontend/src/pages/CaseDetailPage.tsx
```

#### Evidence Management

The system must support:

```text
- uploading or registering memory evidence
- recording original filename, content type, file size, MD5, and SHA256
- recording OS metadata: os_family, os_version, architecture, kernel_version, symbol_table
- recording acquisition metadata: acquisition_tool and acquisition_time
- storing large evidence bytes in object storage instead of PostgreSQL
- validating evidence extensions and upload size limits
```

Relevant repository areas:

```text
backend/app/models/evidence.py
backend/app/schemas/evidence.py
backend/app/services/evidence_service.py
backend/app/services/evidence_upload_session_service.py
backend/app/storage/
frontend/src/pages/EvidenceUploadPage.tsx
```

#### Analysis Job Management

The system must support:

```text
- creating an analysis job for an evidence item
- selecting an OS-aware plugin profile
- storing requested plugins when a custom plugin set is used
- tracking status: queued, running, completed, failed, skipped
- storing start time, completion time, duration, and safe error messages
- dispatching long-running jobs to Celery instead of running them in FastAPI handlers
```

Relevant repository areas:

```text
backend/app/models/analysis_job.py
backend/app/services/analysis_job_service.py
backend/app/services/job_dispatcher.py
backend/app/api/v1/endpoints/analysis_jobs.py
worker/app/tasks/analysis.py
worker/app/tasks/status.py
```

#### Volatility Execution

The system must support:

```text
- checking that Volatility is available in the worker environment
- selecting plugins by OS family and plugin profile
- running plugins with controlled timeout settings
- passing YARA rule paths to YARA-capable plugins
- preserving raw stdout/stderr and execution metadata
- uploading raw plugin output to MinIO/S3
- recording plugin result status and error summaries
```

Relevant repository areas:

```text
worker/app/volatility/registry.py
worker/app/volatility/runner.py
worker/app/volatility/commands.py
worker/app/storage/
```

#### Artifact Normalization

The system must parse raw plugin output into cross-platform artifact concepts:

```text
process_artifacts
command_artifacts
network_artifacts
module_artifacts
memory_region_artifacts
yara_matches
plugin_results
```

Relevant repository areas:

```text
worker/app/parsers/registry.py
worker/app/parsers/processes.py
worker/app/parsers/commands.py
worker/app/parsers/network.py
worker/app/parsers/modules.py
worker/app/parsers/memory_regions.py
worker/app/parsers/yara.py
backend/app/models/*_artifact.py
backend/app/models/yara_match.py
```

#### Detection and Risk Scoring

The system must support rule categories including:

```text
- system process running from the wrong path
- suspicious parent-child relationship
- hidden process candidate from pslist vs psscan
- encoded PowerShell or suspicious command line
- external network connection
- suspicious module path
- executable/private memory region
- malfind result
- YARA match
- memory-region plus network correlation
- memory-region plus suspicious command correlation
- memory-region plus suspicious module correlation
```

Rules must be configurable and OS-scoped:

```text
os_scope: all
os_scope: windows
os_scope: linux
```

Relevant repository areas:

```text
rules/detection/
rules/risk_scoring/default_score.yaml
worker/app/detection/engine.py
worker/app/detection/loader.py
worker/app/detection/rules.py
worker/app/detection/scoring.py
worker/app/detection/persistence.py
backend/app/models/risk_finding.py
```

#### IOC Extraction

The system must extract useful pivots from normalized artifacts and findings:

```text
- remote IP addresses
- remote endpoints
- process names and PIDs
- suspicious command values
- suspicious paths
- YARA rule names and target references
- memory-region linked context
```

It must deduplicate IOC records and export them for analyst workflow.

Relevant repository areas:

```text
worker/app/ioc/
backend/app/models/ioc.py
backend/app/api/v1/endpoints/iocs.py
frontend/src/components/results/IocTable.tsx
```

#### Reporting

The generated report must include:

```text
- executive summary
- case information
- evidence metadata and hashes
- analysis job metadata
- plugin coverage and plugin status
- top actionable detections
- suspicious process summary
- memory-only evidence chains
- IOC summaries
- network indicators
- suspicious module paths
- memory region findings
- YARA matches
- raw and parsed output references
- incident response recommendations
- analyst notes
```

Relevant repository areas:

```text
reports/templates/technical_report.html.j2
worker/app/reports/context.py
worker/app/reports/render.py
worker/app/reports/recommendations.py
worker/app/reports/persistence.py
backend/app/models/report.py
frontend/src/components/results/ReportSection.tsx
```

PDF export is not implemented in the current demo build. The MVP generates HTML technical reports, and a PDF can be produced externally for submission if required.

### 2.4 Non-Functional Requirements

#### Safety

The project must:

```text
- never execute malware
- never download malware unless explicitly instructed and isolated
- analyze existing memory dump files offline
- treat memory dumps as sensitive evidence
- avoid committing real memory dumps, raw outputs, generated reports, or IOC exports
```

#### Evidence Integrity

The system stores hash values and metadata for each evidence file:

```text
MD5
SHA256
size_bytes
original_filename
storage_bucket
storage_key
os_family
architecture
kernel_version
symbol_table
acquisition_tool
acquisition_time
```

This supports traceability from report findings back to the original evidence object.

#### Scalability and Reliability

Memory dumps can be large. The system therefore:

```text
- stores dump bytes in MinIO/S3, not PostgreSQL
- uses chunked upload for large browser uploads
- runs analysis in Celery workers
- preserves partial results if one plugin or parser fails
- stores safe error summaries in plugin and job metadata
- keeps raw output references for later verification
```

#### Maintainability

The project separates responsibilities:

```text
FastAPI endpoints -> request/response layer
Services -> business logic
Models -> database persistence
Worker -> long-running analysis pipeline
Parsers -> Volatility output normalization
Detection -> rule evaluation and scoring
Reports -> report context and rendering
Frontend -> display and analyst workflow
```

Detection logic must not be duplicated in the frontend.

#### Cross-Platform Design

Windows is the MVP target, but the schema and code should avoid Windows-only top-level assumptions. This is why RAMSight uses:

```text
os_family
os_scope
source_plugin
process_artifacts
module_artifacts
memory_region_artifacts
command_artifacts
```

instead of only Windows-specific concepts such as `dll_artifacts` or `malfind_artifacts` as top-level generic models.

### 2.5 Architecture and Working Principle

The principle of operation is:

```text
Analyst
  -> React dashboard
  -> FastAPI API
  -> PostgreSQL metadata
  -> MinIO evidence storage
  -> Redis/Celery queue
  -> Worker
  -> Volatility 3 and YARA
  -> MinIO raw outputs
  -> Parsers
  -> PostgreSQL artifacts
  -> Detection and scoring
  -> IOC extraction
  -> HTML report
  -> Dashboard review and report download
```

This design supports the main research goal: showing how Volatility output can be converted into an end-to-end memory-only malware triage workflow.

### 2.6 Solution Selection Rationale

| Requirement | Selected solution | Rationale |
| --- | --- | --- |
| Memory analysis | Volatility 3 | Established framework for memory forensics with Windows and Linux plugin support. |
| Process-memory pattern matching | YARA | Practical rule language for defensive malware pattern matching. |
| API layer | FastAPI | Suitable for modular Python APIs and typed schemas. |
| Long-running jobs | Celery + Redis | Keeps heavy analysis outside HTTP request handlers. |
| Metadata storage | PostgreSQL | Fits relational case/evidence/job/artifact/finding records. |
| Large object storage | MinIO/S3 | Fits memory dumps, raw outputs, parsed outputs, IOC exports, and reports. |
| Frontend | React + TypeScript | Supports a practical dashboard with typed API data. |
| Deployment | Docker Compose | Reproducible local lab environment for demonstration. |

### 2.7 Practical Scenarios

The report and demo should include practical situations, not only static architecture:

```text
1. Office document starts encoded PowerShell.
2. Injected process has executable/private memory regions.
3. Process has a public remote network endpoint.
4. System process name runs from an unexpected path.
5. Process appears in psscan but not pslist.
6. Process loads a module from Temp, AppData, Users Public, /tmp, or /dev/shm.
7. YARA matches a suspicious pattern inside process memory.
```

RAMSight is useful because it can correlate these events by process and present them as triage findings instead of isolated command output.

---

## Thesis Report Chapter 3: Related Knowledge

### 3.1 Memory Forensics

Memory forensics is the analysis of volatile memory captured from a running system. Unlike disk forensics, memory forensics can reveal runtime-only evidence:

```text
- active and hidden process objects
- process parent-child relationships
- command-line arguments
- network sockets and endpoints
- loaded modules and DLLs
- injected or executable private memory regions
- shellcode-like bytes
- credentials or sensitive strings in memory
- YARA pattern matches
```

Memory evidence is volatile and sensitive. A memory dump may include user documents, credentials, browser data, tokens, and process secrets. This is why RAMSight treats dump files as evidence and stores them outside Git.

### 3.2 Volatility Framework 3

Volatility 3 is the core forensic engine used by RAMSight. It provides memory analysis plugins that can inspect different operating-system structures. RAMSight uses it through a worker runner rather than direct interactive commands.

The Windows MVP profile uses:

| Plugin | Forensic purpose |
| --- | --- |
| `windows.pslist` | Enumerates active processes using standard OS-linked structures. |
| `windows.psscan` | Scans memory for process objects and helps find hidden/unlinked candidates. |
| `windows.pstree` | Reconstructs process hierarchy and suspicious parent-child relationships. |
| `windows.cmdline` | Extracts command-line context such as encoded PowerShell. |
| `windows.netscan` | Extracts network endpoints and maps them to PIDs/processes. |
| `windows.dlllist` | Lists loaded modules and DLL paths. |
| `windows.handles` | Collects handle context for investigation. |
| `windows.malfind` | Identifies memory regions consistent with injection or suspicious executable memory. |
| `windows.vadyarascan` | Runs YARA scanning across process VAD memory regions. |

RAMSight also reserves and documents deeper profiles:

```text
windows_memory_deep
windows_memory_deep_yara_elastic
windows_memory_deep_yara_neo23x0
windows_memory_deep_yara_third_party_all
windows_malware_evasion
windows_kernel_rootkit
windows_investigation_context
```

These profiles make the solution more practical because different incidents require different depth. A quick baseline scan is useful for demos or large files; deeper profiles are useful when there is enough time and compute.

### 3.3 Memory-Only Malware

Memory-only malware is a broad category of activity where the most important payload or execution evidence is found in RAM rather than as a normal file on disk. Typical techniques include:

```text
- process injection
- reflective DLL loading
- shellcode loaded into private executable pages
- process hollowing
- process masquerading
- unlinked process or module artifacts
- script-based download and execute behavior
```

No single artifact proves memory-only malware by itself. For example:

```text
malfind output alone -> suspicious memory region, needs context
YARA match alone -> pattern hit, needs rule quality review
public network endpoint alone -> may be benign, needs process context
encoded PowerShell alone -> suspicious, but must be interpreted
```

RAMSight therefore emphasizes evidence chains:

```text
process identity
  + memory-region evidence
  + command-line evidence
  + network evidence
  + module path evidence
  + YARA evidence
  -> process-centered risk finding
```

### 3.4 YARA Rules

YARA is a rule-based pattern matching tool used by malware researchers and defenders. A YARA rule normally contains metadata, strings, and a boolean condition. It can match text strings, byte sequences, and regular expressions.

In RAMSight:

```text
- YARA is used as a defensive triage aid.
- Runtime profiles use validated third-party packs.
- Elastic and Neo23x0 packs can be imported, validated, and compiled.
- YARA matches are stored as yara_matches.
- Rule metadata can be enriched into match records.
- YARA findings are correlated with process, memory, command, module, and network evidence.
```

Important limitations:

```text
- YARA can produce false positives.
- Broad rules should not be treated as conclusive malware evidence.
- Large memory dumps can make YARA scanning slow.
- Heavy YARA profiles should be selected deliberately.
```

### 3.5 Rule Engine and Risk Scoring

RAMSight's detection engine evaluates normalized artifact rows, not raw terminal output. This makes rules easier to test and easier to reuse across plugins.

Rule examples:

```text
WIN_SYSTEM_PROCESS_WRONG_PATH
WIN_SUSPICIOUS_PARENT_CHILD
WIN_PSSCAN_ONLY_PROCESS
MEMORY_PROCESS_INJECTION_CANDIDATE
MEMORY_REGION_WITH_NETWORK_ACTIVITY
MEMORY_REGION_WITH_SUSPICIOUS_COMMAND
MEMORY_REGION_WITH_SUSPICIOUS_MODULE
YARA_MATCH_IN_PROCESS_MEMORY
```

Default risk levels:

```text
0-3      Low
4-7      Medium
8-12     High
13+      Critical
```

The goal of scoring is prioritization, not automatic conviction. A critical finding means the analyst should review it first.

### 3.6 IOC Extraction

IOCs in RAMSight are investigation pivots derived from evidence. They may include:

```text
remote IP address
remote IP:port endpoint
domain or URL string when available
process and PID context
file or module path
YARA rule name
command-line indicator
memory-region reference
```

IOCs are deduplicated and exported as JSON/CSV to support hunting in firewall, proxy, EDR, SIEM, or other lab tools.

### 3.7 Web Application and Background Processing Concepts

The application follows a common production-style pattern even though it is a local demo:

```text
Frontend -> API -> Queue -> Worker -> Storage -> Database -> Report
```

This separation is important because memory analysis is slow and can fail in plugin-specific ways. Running all analysis inside a web request would make the system fragile. Celery workers provide a safer execution boundary for Volatility.

### 3.8 Evidence Safety and Ethics

The project must be presented as a defensive analysis platform:

```text
- It does not execute malware.
- It does not create malware.
- It does not download malware as part of the normal workflow.
- It analyzes memory dumps in a controlled lab.
- It treats findings as triage indicators.
```

For a thesis defense, this framing is important: RAMSight demonstrates defensive memory analysis, not malware operation.

---

## Thesis Report Chapter 4: Application

### 4.1 Application Overview

RAMSight is a local web application that turns a Windows memory dump into:

```text
- Volatility plugin results
- normalized forensic artifacts
- memory-only malware triage findings
- IOC records and exports
- analyst review metadata
- technical HTML report
```

The product goal is to support a repeatable workflow for memory-only malware investigation in a safe lab.

### 4.2 End-to-End Workflow

The end-to-end workflow is:

```text
1. Analyst creates a case.
2. Analyst uploads or registers a memory dump.
3. Backend records evidence metadata and hashes.
4. Backend stores large evidence bytes in MinIO.
5. Analyst creates an analysis job and selects a profile.
6. Backend dispatches a Celery task.
7. Worker claims the queued job.
8. Worker downloads the evidence into an isolated workspace.
9. Worker runs selected Volatility plugins.
10. Worker uploads raw plugin outputs.
11. Parser registry converts output to normalized artifacts.
12. Detection engine evaluates YAML rules.
13. Risk findings are persisted.
14. IOC extractor deduplicates and exports IOCs.
15. Report generator builds an HTML technical report.
16. Frontend displays results and report links.
```

### 4.3 Backend Application Details

The backend is built with FastAPI and SQLAlchemy. Important responsibilities:

```text
- request validation through Pydantic schemas
- case and evidence service logic
- object-storage integration
- analysis job creation and status tracking
- query APIs for artifacts, IOCs, findings, plugin results, and reports
- download URL generation for stored outputs
```

Important backend models:

| Model | Purpose |
| --- | --- |
| `Case` | Investigation container. |
| `Evidence` | Memory dump metadata, hashes, storage reference, OS metadata. |
| `AnalysisJob` | Status, profile, timing, requested plugins, errors. |
| `PluginResult` | Volatility plugin execution metadata and raw/parsed output references. |
| `ProcessArtifact` | Process evidence from `pslist`, `psscan`, `pstree`, or later Linux plugins. |
| `CommandArtifact` | Command-line and shell-history style evidence. |
| `NetworkArtifact` | Network endpoints linked to process context. |
| `ModuleArtifact` | DLL, module, driver, shared-library, or ELF-like evidence. |
| `MemoryRegionArtifact` | Suspicious or executable memory region evidence. |
| `YaraMatch` | YARA rule matches against memory. |
| `RiskFinding` | Detection result, severity, score, recommendation, review metadata. |
| `IOC` | Exportable investigation pivot. |
| `Report` | Generated report metadata and object-storage reference. |

### 4.4 Worker Pipeline Details

The worker task `run_analysis_job` is the main execution pipeline.

Important implementation choices:

```text
- Only queued jobs can be claimed, which helps avoid duplicate worker execution.
- Evidence storage metadata is validated before analysis.
- The downloaded evidence filename is normalized to avoid unsafe paths.
- Raw plugin output is uploaded even when parsing later fails.
- Plugin failures are recorded per plugin instead of losing the whole job.
- Detection errors are stored as findings/stage errors where possible.
- IOC and report failures do not erase already completed analysis artifacts.
```

The worker creates a useful chain of custody for analysis results:

```text
evidence object -> plugin result -> raw output object -> parsed output object -> normalized artifact -> finding -> IOC/report
```

### 4.5 Volatility Profiles in the Application

Baseline Windows profile:

```text
windows_default
  windows.pslist
  windows.psscan
  windows.pstree
  windows.cmdline
  windows.netscan
  windows.dlllist
  windows.handles
  windows.malfind
```

Memory + YARA profiles:

```text
windows_memory_yara
windows_memory_yara_elastic
windows_memory_yara_neo23x0
windows_memory_yara_third_party_all
```

Deep memory profiles:

```text
windows_memory_deep
windows_memory_deep_yara_elastic
windows_memory_deep_yara_neo23x0
windows_memory_deep_yara_third_party_all
```

Specialized profiles:

```text
windows_malware_evasion
windows_kernel_rootkit
windows_investigation_context
```

The report should explain that heavy YARA and deep profiles are slower and should be used when the investigation needs deeper coverage.

### 4.6 Detection Pipeline Details

The detection pipeline loads YAML rules and evaluates them against artifacts. Important memory-only detections:

| Rule | Purpose |
| --- | --- |
| `MEMORY_PROCESS_INJECTION_CANDIDATE` | Converts suspicious executable memory-region evidence into a process injection candidate. |
| `MEMORY_REGION_WITH_NETWORK_ACTIVITY` | Correlates memory-region evidence with public remote network activity by PID. |
| `MEMORY_REGION_WITH_SUSPICIOUS_COMMAND` | Correlates executable memory evidence with suspicious command-line behavior. |
| `MEMORY_REGION_WITH_SUSPICIOUS_MODULE` | Correlates memory evidence with user-writable module paths. |
| `YARA_MATCH_IN_PROCESS_MEMORY` | Creates a cautious finding when process-memory YARA scanning reports a match. |

This is the key application logic for the thesis because it demonstrates practical triage of memory-only malware signs.

### 4.7 Frontend Application Details

The frontend is built with React and TypeScript. Important pages and components:

```text
frontend/src/pages/DashboardPage.tsx
frontend/src/pages/CasesPage.tsx
frontend/src/pages/CaseCreatePage.tsx
frontend/src/pages/CaseDetailPage.tsx
frontend/src/pages/EvidenceUploadPage.tsx
frontend/src/pages/AnalysisJobStatusPage.tsx
frontend/src/components/results/FindingTable.tsx
frontend/src/components/results/IocTable.tsx
frontend/src/components/results/PluginResultTable.tsx
frontend/src/components/results/ArtifactDrilldown.tsx
frontend/src/components/results/MemoryEvidenceGraph.tsx
frontend/src/components/results/ReportSection.tsx
```

The analysis status page is the main investigation screen. It combines:

```text
- job status
- selected profile
- plugin coverage
- YARA status
- findings
- IOCs
- process artifacts
- command artifacts
- network artifacts
- module artifacts
- memory regions
- YARA matches
- report links
```

The frontend does not implement detection logic. It displays backend and worker results.

### 4.8 Technical Report Details

The HTML report template is:

```text
reports/templates/technical_report.html.j2
```

The report is designed for both technical review and thesis demonstration. Important sections:

```text
Executive Summary
Case Information
Evidence Metadata
Analysis Job
Analysis Summary
Plugin Results
Top Actionable Detections
Suspicious Process Summary
Memory-only Evidence Chains
Threat-Oriented IOCs
Investigation Artifacts
Network Indicators
Suspicious Module Paths
Memory Region Findings
YARA Matches
Raw and Parsed Output References
Incident Response Recommendations
Analyst Notes
```

The strongest thesis evidence should come from:

```text
- plugin coverage summary
- suspicious process summary
- memory-only evidence chains
- YARA matches
- IOC summary
- raw output references
```

These show that the platform does more than run Volatility commands; it organizes the results into an analyst workflow.

### 4.9 Suggested Lab Demonstrations

Use safe, already acquired memory dumps. Do not run malware during the demo.

| Demo scenario | What it proves | Expected evidence |
| --- | --- | --- |
| Process injection sample dump | Volatility memory-region analysis and risk correlation. | `windows.malfind`, memory-region findings, process evidence chain. |
| Process-memory YARA match | Defensive YARA triage over memory. | `windows.vadyarascan`, YARA matches, cautious YARA findings. |
| Office spawns PowerShell | Command-line and process-tree detection. | Suspicious parent-child, encoded PowerShell or suspicious command finding. |
| Hidden process candidate | Cross-view process analysis. | `psscan` evidence not present in `pslist`. |
| Network beacon from suspicious process | IOC extraction and network correlation. | Public remote endpoint, IOC export, critical memory/network finding. |
| Suspicious module path | Module path triage. | Module loaded from temporary or user-writable path. |

### 4.10 Verification Plan

Recommended verification commands:

```bash
docker compose -f docker-compose.dev.yml up -d postgres redis minio backend worker frontend
docker compose -f docker-compose.dev.yml exec backend alembic upgrade head
python scripts/demo/preflight_check.py --api-base http://localhost:8000/api/v1 --frontend-url http://localhost:5173
docker compose -f docker-compose.dev.yml exec backend pytest /tests/backend
docker compose -f docker-compose.dev.yml exec worker pytest /tests/worker
docker compose -f docker-compose.dev.yml exec frontend npm run build
python -m pytest tests/scripts
```

Evidence safety checks:

```bash
git ls-files | grep -Ei '\.(raw|mem|dmp|vmem|lime|aff4)$' || true
git ls-files | grep -Ei '(technical_report|ioc_export|report).*\.(html|json|csv)$' || true
```

Both commands should return no tracked files.

### 4.11 Difficulties and Mitigations

| Difficulty | Impact | Mitigation in RAMSight |
| --- | --- | --- |
| Large memory dumps | Slow upload, storage pressure, timeout risk. | MinIO storage, chunked upload, worker processing. |
| Volatility plugin failures | Partial analysis failure. | Per-plugin status, raw output preservation, safe error summaries. |
| Parser fragility | Output format changes can break parsing. | Parser registry, focused parser tests, raw output references. |
| YARA false positives | Noisy findings. | YARA shown as triage evidence, correlation with other artifacts. |
| YARA scan time | Slow analysis on large dumps. | Separate YARA profiles and timeout policies. |
| Analyst interpretation | Findings may be misunderstood as final verdicts. | Review fields, recommendations, cautious report language. |
| Linux support | Planned but not complete. | OS-aware schema and plugin registry reserved for extension. |
| Production security | Local demo stack lacks production hardening. | Clearly documented as lab/demo-ready only. |

### 4.12 Current Application Limitations

Current limitations to state clearly in the report:

```text
- Windows analysis is implemented first; Linux support is an architectural extension.
- Findings are triage indicators and require analyst validation.
- PDF export is planned but not implemented in the current demo build.
- Third-party YARA rules can be noisy and expensive on large dumps.
- The Docker Compose environment is local/dev and lacks production auth, RBAC, TLS, backup, and secret-manager integration.
- Results depend on memory image quality, Volatility support, symbols, plugin behavior, and rule quality.
```

### 4.13 Submission Package Recommendation

For the thesis submission folder, include:

```text
- full Word report
- exported PDF version of the report
- presentation slides
- source code folder or archive
- README and setup instructions
- screenshots of dashboard and report
- sanitized sample metadata or expected results
- generated report examples if they do not contain sensitive evidence
- references and third-party rule license notes
```

Do not include real memory dumps or sensitive evidence files in the submitted repository unless explicitly approved and safely handled.

