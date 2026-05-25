export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

function apiUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}

async function parseResponse(response: Response): Promise<unknown> {
  if (response.status === 204) {
    return null;
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

function validationDetailMessage(items: unknown[]): string | null {
  const messages = items
    .map((item) => {
      if (!item || typeof item !== "object" || !("msg" in item)) return null;
      const message = String((item as { msg: unknown }).msg);
      const location = "loc" in item && Array.isArray((item as { loc: unknown }).loc)
        ? (item as { loc: unknown[] }).loc.join(".")
        : null;
      return location ? `${location}: ${message}` : message;
    })
    .filter((message): message is string => Boolean(message));
  return messages.length > 0 ? messages.join("; ") : null;
}

function detailMessage(detail: unknown): string {
  if (typeof detail === "string") {
    return detail;
  }
  if (detail && typeof detail === "object" && "detail" in detail) {
    const nested = (detail as { detail?: unknown }).detail;
    if (Array.isArray(nested)) {
      return validationDetailMessage(nested) ?? "RAMSight API validation failed.";
    }
    return typeof nested === "string" ? nested : JSON.stringify(nested);
  }
  return "RAMSight API request failed.";
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(apiUrl(path), { ...init, headers });
  } catch (err) {
    throw new ApiError(
      "RAMSight could not reach the API. Confirm the backend is running and VITE_API_BASE_URL/CORS are configured for this frontend origin.",
      0,
      err,
    );
  }
  const payload = await parseResponse(response);

  if (!response.ok) {
    throw new ApiError(detailMessage(payload), response.status, payload);
  }

  return payload as T;
}

export function jsonBody<T>(body: T): string {
  return JSON.stringify(body);
}
