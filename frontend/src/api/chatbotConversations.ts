export type ChatRole = "user" | "assistant";

export interface StoredChatMessage {
  id: string;
  role: ChatRole;
  content: string;
  createdAt: string;
}

export interface ChatConversation {
  conversation_id: string;
  job_id: string;
  messages: StoredChatMessage[];
  createdAt: string;
  updatedAt: string;
}

export const CHAT_CONVERSATIONS_STORAGE_KEY = "ramsight_chat_conversations";

function nowIso(): string {
  return new Date().toISOString();
}

export function createMessage(role: ChatRole, content: string): StoredChatMessage {
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    role,
    content,
    createdAt: nowIso(),
  };
}

function isConversation(value: unknown): value is ChatConversation {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ChatConversation>;
  return typeof candidate.conversation_id === "string"
    && typeof candidate.job_id === "string"
    && Array.isArray(candidate.messages)
    && typeof candidate.createdAt === "string"
    && typeof candidate.updatedAt === "string";
}

export function loadConversations(): ChatConversation[] {
  const raw = window.localStorage.getItem(CHAT_CONVERSATIONS_STORAGE_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isConversation);
  } catch {
    return [];
  }
}

export function saveConversations(conversations: ChatConversation[]): void {
  window.localStorage.setItem(CHAT_CONVERSATIONS_STORAGE_KEY, JSON.stringify(conversations));
}

export function upsertConversation(
  conversations: ChatConversation[],
  jobId: string,
  messagesToAppend: StoredChatMessage[],
): ChatConversation[] {
  const existing = conversations.find((conversation) => conversation.job_id === jobId);
  const timestamp = nowIso();

  if (!existing) {
    return [
      {
        conversation_id: `job-${jobId}`,
        job_id: jobId,
        messages: messagesToAppend,
        createdAt: timestamp,
        updatedAt: timestamp,
      },
      ...conversations,
    ];
  }

  return conversations
    .map((conversation) => conversation.job_id === jobId
      ? {
          ...conversation,
          messages: [...conversation.messages, ...messagesToAppend],
          updatedAt: timestamp,
        }
      : conversation)
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
}
