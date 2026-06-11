# Optional web enrichment provider for RAMSight Chatbot.

import httpx

from app.core.config import Settings

SERPAPI_SEARCH_URL = "https://serpapi.com/search"
MAX_QUERY_LENGTH = 280


def _extract_text(payload: dict) -> str:
    for key in ("answer", "summary", "snippet"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    ai_overview = payload.get("ai_overview")
    if isinstance(ai_overview, dict):
        text = _extract_text(ai_overview)
        if text:
            return text

    answer_box = payload.get("answer_box")
    if isinstance(answer_box, dict):
        text = _extract_text(answer_box)
        if text:
            return text

    organic_results = payload.get("organic_results")
    if isinstance(organic_results, list):
        snippets = []
        for result in organic_results[:3]:
            if not isinstance(result, dict):
                continue
            title = str(result.get("title") or "").strip()
            snippet = str(result.get("snippet") or "").strip()
            if title or snippet:
                snippets.append(": ".join(part for part in (title, snippet) if part))
        if snippets:
            return "\n".join(snippets)

    return ""


async def enrichWithGoogleAiMode(query: str, settings: Settings) -> dict[str, object]:
    """Call SerpApi Google AI Mode with a short threat-context query."""
    if not settings.chatbot_enable_web_enrichment:
        return {"enabled": False, "available": False, "reason": "disabled", "content": ""}
    if not settings.serpapi_key:
        return {"enabled": True, "available": False, "reason": "missing_key", "content": ""}

    safe_query = " ".join(query.split())[:MAX_QUERY_LENGTH]
    if not safe_query:
        return {"enabled": True, "available": False, "reason": "empty_query", "content": ""}

    params = {
        "engine": settings.serpapi_engine or "google_ai_mode",
        "q": safe_query,
        "api_key": settings.serpapi_key,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(SERPAPI_SEARCH_URL, params=params)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:  # noqa: BLE001 - enrichment must never break standard chatbot answers.
        return {"enabled": True, "available": False, "reason": "api_error", "content": "", "error": str(exc)}

    content = _extract_text(payload)
    return {
        "enabled": True,
        "available": bool(content),
        "reason": "ok" if content else "empty_result",
        "content": content[:1800],
    }
