export interface ReadinessResponse {
  status: string;
  checks: {
    database?: string;
    redis?: string;
    object_storage?: string;
  };
}

function backendRootUrl(): string {
  const configured = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
  return configured.replace(/\/api\/v1$/i, "");
}

function safeCheckValue(value: unknown): string {
  return typeof value === "string" && value.trim() ? value : "unknown";
}

export async function getReadiness(): Promise<ReadinessResponse> {
  const response = await fetch(`${backendRootUrl()}/ready`);
  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload || typeof payload !== "object") {
    throw new Error("RAMSight readiness is unavailable.");
  }

  const record = payload as { checks?: Record<string, unknown>; status?: unknown };
  const checks = record.checks ?? {};
  return {
    status: safeCheckValue(record.status),
    checks: {
      database: safeCheckValue(checks.database),
      redis: safeCheckValue(checks.redis),
      object_storage: safeCheckValue(checks.object_storage),
    },
  };
}
