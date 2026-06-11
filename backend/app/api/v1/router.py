# API v1 router registration.

from fastapi import APIRouter

from app.api.v1.endpoints import analysis_jobs, artifacts, cases, chatbot, evidences, iocs, plugin_results, reports, risk_findings

api_router = APIRouter()
api_router.include_router(cases.router, prefix="/cases", tags=["cases"])
api_router.include_router(evidences.router, prefix="/evidences", tags=["evidences"])
api_router.include_router(analysis_jobs.router, prefix="/analysis-jobs", tags=["analysis-jobs"])
api_router.include_router(plugin_results.router, tags=["plugin-results"])
api_router.include_router(artifacts.router, tags=["artifacts"])
api_router.include_router(iocs.router, prefix="/iocs", tags=["iocs"])
api_router.include_router(risk_findings.router, prefix="/risk-findings", tags=["risk-findings"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(chatbot.router, prefix="/chatbot", tags=["chatbot"])
