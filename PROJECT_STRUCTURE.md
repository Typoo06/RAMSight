# Project Structure

This document describes the intended repository layout for the Memory Malware Triage Platform.

```text
memory-malware-triage-platform/
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
```

## Backend

```text
backend/
├── app/
│   ├── api/v1/endpoints/    # FastAPI route modules
│   ├── core/                # Settings and shared configuration
│   ├── db/                  # Database session and migration support
│   ├── detection/           # Detection-related backend metadata/helpers
│   ├── models/              # SQLAlchemy models
│   ├── reports/             # Report metadata/service integration
│   ├── schemas/             # Pydantic schemas
│   ├── services/            # Business/service layer
│   ├── storage/             # MinIO/S3 client integration
│   └── main.py              # FastAPI application entry point placeholder
└── pyproject.toml           # Backend Python package configuration
```

## Worker

```text
worker/
├── app/
│   ├── celery_app.py        # Celery application entry point placeholder
│   ├── detection/           # Detection task orchestration
│   ├── ioc/                 # IOC extraction
│   ├── parsers/             # Volatility output parsers
│   ├── reports/             # Report generation tasks
│   ├── tasks/               # Celery task modules
│   └── volatility/          # Volatility runner integration
└── pyproject.toml           # Worker Python package configuration
```

## Frontend

```text
frontend/
├── src/
│   ├── api/                 # Backend API clients
│   ├── components/          # Reusable UI components
│   ├── pages/               # Dashboard pages
│   └── types/               # Shared TypeScript types
├── package.json             # Frontend package metadata
├── tsconfig.json            # TypeScript configuration
└── vite.config.ts           # Vite configuration
```

## Evidence Safety

Large memory dumps must not be committed to Git. Use MinIO/S3 or ignored local folders for evidence files and generated outputs.

