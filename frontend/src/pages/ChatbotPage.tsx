import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { answerChatbotQuestion } from "../api/chatbotAgent";
import { extractJobId } from "../api/chatbot";
import {
  createMessage,
  loadConversations,
  saveConversations,
  upsertConversation,
  type ChatConversation,
  type StoredChatMessage,
} from "../api/chatbotConversations";
import { Card } from "../components/ui/Card";

const QUICK_QUESTIONS = [
  "Summarize this job",
  "Is this likely malware?",
  "Show high-risk processes",
  "Explain suspicious IOCs",
  "What should I investigate first?",
  "Generate analyst notes",
];

function shortJobId(jobId: string): string {
  return jobId.length > 18 ? `${jobId.slice(0, 8)}...${jobId.slice(-6)}` : jobId;
}

export function ChatbotPage() {
  const [searchParams] = useSearchParams();
  const [input, setInput] = useState("");
  const [conversations, setConversations] = useState<ChatConversation[]>(() => loadConversations());
  const [selectedJobId, setSelectedJobId] = useState<string | null>(() => searchParams.get("job_id"));
  const [unscopedMessages, setUnscopedMessages] = useState<StoredChatMessage[]>([]);
  const [lastMode, setLastMode] = useState<"Standard" | "DeepSeek LLM" | "Standard fallback">("Standard");
  const [sending, setSending] = useState(false);
  const autoPromptKey = useRef<string | null>(null);
  const conversationEndRef = useRef<HTMLDivElement | null>(null);

  const selectedConversation = conversations.find((conversation) => conversation.job_id === selectedJobId) ?? null;
  const displayedMessages = selectedConversation?.messages ?? unscopedMessages;

  const initialPrompt = useMemo(() => {
    const prompt = searchParams.get("prompt");
    const jobId = searchParams.get("job_id");
    if (prompt) return prompt;
    return jobId ? `Summarize report for job ${jobId}` : null;
  }, [searchParams]);

  const commitConversations = useCallback((updater: (current: ChatConversation[]) => ChatConversation[]) => {
    setConversations((current) => {
      const next = updater(current);
      saveConversations(next);
      return next;
    });
  }, []);

  const appendToConversation = useCallback((jobId: string, messages: StoredChatMessage[]) => {
    commitConversations((current) => upsertConversation(current, jobId, messages));
  }, [commitConversations]);

  const sendMessage = useCallback(async (messageText: string) => {
    const trimmed = messageText.trim();
    if (!trimmed || sending) return;

    const messageJobId = extractJobId(trimmed);
    const targetJobId = messageJobId ?? selectedJobId;
    const conversationBefore = targetJobId
      ? conversations.find((conversation) => conversation.job_id === targetJobId)?.messages ?? []
      : unscopedMessages;
    const userMessage = createMessage("user", trimmed);
    setInput("");

    if (targetJobId) {
      setSelectedJobId(targetJobId);
      setUnscopedMessages([]);
      appendToConversation(targetJobId, [userMessage]);
    } else {
      setUnscopedMessages((current) => [...current, userMessage]);
    }

    setSending(true);
    try {
      const response = await answerChatbotQuestion(trimmed, targetJobId, conversationBefore);
      setLastMode(response.mode);
      const assistantMessage = createMessage("assistant", response.answer);
      if (response.jobId) {
        setSelectedJobId(response.jobId);
        appendToConversation(response.jobId, [assistantMessage]);
      } else {
        setUnscopedMessages((current) => [...current, assistantMessage]);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "RAMSight could not answer this AI assistant request.";
      const assistantMessage = createMessage("assistant", `I could not load the selected job data. ${message}`);
      if (targetJobId) appendToConversation(targetJobId, [assistantMessage]);
      else setUnscopedMessages((current) => [...current, assistantMessage]);
    } finally {
      setSending(false);
    }
  }, [appendToConversation, conversations, selectedJobId, sending, unscopedMessages]);

  useEffect(() => {
    conversationEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [displayedMessages, sending]);

  useEffect(() => {
    if (!initialPrompt || autoPromptKey.current === initialPrompt) return;
    autoPromptKey.current = initialPrompt;
    void sendMessage(initialPrompt);
  }, [initialPrompt, sendMessage]);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void sendMessage(input);
  }

  function handleQuickQuestion(question: string) {
    if (!selectedJobId) return;
    const prompt = question === "Summarize this job" ? `Summarize job ${selectedJobId}` : question;
    void sendMessage(prompt);
  }

  return (
    <div className="page-stack">
      <section className="page-heading">
        <span className="eyebrow">Standard mode</span>
        <h2>AI assistant</h2>
        <p>{selectedJobId ? `Current job: ${selectedJobId}` : "Select a job conversation or ask: Summarize job <job_id>"}</p>
      </section>

      <div className="chatbot-layout">
        <aside className="chatbot-conversation-panel" aria-label="AI assistant conversations">
          <h2>Conversations</h2>
          {conversations.length === 0 ? (
            <p className="muted">No job conversations yet.</p>
          ) : (
            <div className="chatbot-conversation-list">
              {conversations.map((conversation) => (
                <button
                  className={`chatbot-conversation-item${conversation.job_id === selectedJobId ? " active" : ""}`}
                  key={conversation.conversation_id}
                  title={conversation.job_id}
                  type="button"
                  onClick={() => setSelectedJobId(conversation.job_id)}
                >
                  {shortJobId(conversation.job_id)}
                </button>
              ))}
            </div>
          )}
        </aside>

        <Card className="chatbot-card">
          <div className="chatbot-current-job">
            <span className="eyebrow">Current job</span>
            <strong>{selectedJobId ?? "No job selected"}</strong>
            <span className="chatbot-mode">Mode: {lastMode}</span>
          </div>

          {selectedJobId && (
            <div className="chatbot-quick-questions" aria-label="Suggested quick questions">
              {QUICK_QUESTIONS.map((question) => (
                <button className="button button-subtle button-small" disabled={sending} key={question} type="button" onClick={() => handleQuickQuestion(question)}>
                  {question}
                </button>
              ))}
            </div>
          )}

          <div className="chatbot-messages" aria-live="polite">
            {displayedMessages.length === 0 ? (
              <div className="chatbot-empty-state">
                <p>Select a job conversation or ask: Summarize job &lt;job_id&gt;</p>
              </div>
            ) : (
              displayedMessages.map((message) => (
                <article className={`chatbot-message chatbot-message-${message.role}`} key={message.id}>
                  <strong>{message.role === "user" ? "You" : "AI assistant"}</strong>
                  <p>{message.content}</p>
                </article>
              ))
            )}
            {sending && (
              <article className="chatbot-message chatbot-message-assistant">
                <strong>AI assistant</strong>
                <p>Loading current job results and preparing an answer...</p>
              </article>
            )}
            <div ref={conversationEndRef} />
          </div>

          <form className="chatbot-input-row" onSubmit={handleSubmit}>
            <label>
              <span className="sr-only">Ask AI assistant</span>
              <textarea
                placeholder={selectedJobId ? "Ask about the selected job..." : "Ask a question or paste a job_id..."}
                rows={3}
                value={input}
                onChange={(event) => setInput(event.target.value)}
              />
            </label>
            <button className="button button-primary" disabled={sending || !input.trim()} type="submit">
              Send
            </button>
          </form>
          <p className="chatbot-warning">AI assistant can make mistakes; please double check important info.</p>
        </Card>
      </div>
    </div>
  );
}
