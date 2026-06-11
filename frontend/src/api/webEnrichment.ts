import { apiRequest, jsonBody } from "./client";

export interface WebEnrichmentResponse {
  enabled: boolean;
  available: boolean;
  reason: string;
  content: string;
}

export function enrichWithGoogleAiMode(query: string): Promise<WebEnrichmentResponse> {
  return apiRequest<WebEnrichmentResponse>("/api/v1/chatbot/web-enrichment", {
    method: "POST",
    body: jsonBody({ query }),
  });
}
