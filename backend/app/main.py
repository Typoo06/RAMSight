# FastAPI application entry point.

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.api.v1.endpoints import health
from app.core.config import get_settings
from app.core.logging import configure_logging

configure_logging()
settings = get_settings()

app = FastAPI(title="Memory Malware Triage API")
app.include_router(health.router)
app.include_router(api_router, prefix="/api/v1")
