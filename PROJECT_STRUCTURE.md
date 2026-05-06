# Project Structure

This document describes the intended repository layout for the Memory Malware Triage Platform.

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
10. Generate HTML/PDF reports
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
yarascan
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
├── static/                  # CSS, images, report assets
└── examples/                # Example generated reports
```

Reports should support:

```text
- Technical report
- Executive summary
- IOC export
```

The MVP should generate HTML first. PDF export should reuse the same HTML template later.

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
        ├── technical_report.pdf
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
├── deployment/              # Docker setup and deployment instructions
├── user-guide/              # User-facing guide
├── developer-guide/         # Developer guide
└── thesis-materials/        # Materials used for academic report
```

---

## Scripts

```text
scripts/
├── dev_setup.sh
├── run_migrations.sh
├── create_minio_buckets.sh
├── seed_demo_data.py
├── run_demo_analysis.sh
├── export_openapi.sh
├── clean_outputs.sh
└── backup_database.sh
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


