import { apiRequest, jsonBody } from "./client";
import type { StoredChatMessage } from "./chatbotConversations";

export interface LlmAnswerRequest {
  jobContext: Record<string, unknown>;
  conversationMessages: StoredChatMessage[];
  userMessage: string;
  webEnrichment?: string | null;
  standardAnswer?: string | null;
  mode: "llm";
}

export interface LlmAnswerResponse {
  enabled: boolean;
  attempted: boolean;
  success: boolean;
  answer: string;
  fallback_reason: string | null;
}

export function generateLlmAnswer(payload: LlmAnswerRequest): Promise<LlmAnswerResponse> {
  return apiRequest<LlmAnswerResponse>("/api/v1/chatbot/llm-answer", {
    method: "POST",
    body: jsonBody(payload),
  });
}
