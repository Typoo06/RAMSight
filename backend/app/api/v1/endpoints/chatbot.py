# Chatbot support endpoints.

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.services.deepseek_provider import generateLlmAnswer
from app.services.web_enrichment_provider import enrichWithGoogleAiMode

router = APIRouter()


class WebEnrichmentRequest(BaseModel):
    query: str = Field(min_length=1, max_length=280)


class WebEnrichmentResponse(BaseModel):
    enabled: bool
    available: bool
    reason: str
    content: str


class LlmAnswerRequest(BaseModel):
    jobContext: dict = Field(default_factory=dict)
    conversationMessages: list[dict] = Field(default_factory=list)
    userMessage: str = Field(min_length=1, max_length=2000)
    webEnrichment: str | None = Field(default=None, max_length=2500)
    standardAnswer: str | None = Field(default=None, max_length=4000)
    mode: str = Field(default="llm", max_length=32)


class LlmAnswerResponse(BaseModel):
    enabled: bool
    attempted: bool
    success: bool
    answer: str
    fallback_reason: str | None = None


@router.post("/web-enrichment", response_model=WebEnrichmentResponse)
async def web_enrichment(
    payload: WebEnrichmentRequest,
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    return await enrichWithGoogleAiMode(payload.query, settings)


@router.post("/llm-answer", response_model=LlmAnswerResponse)
async def llm_answer(
    payload: LlmAnswerRequest,
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    return await generateLlmAnswer(payload.model_dump(), settings)
