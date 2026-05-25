export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not recorded";
  return date.toLocaleString();
}

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "Not recorded";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

export function displayValue(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "Not recorded";
  return String(value);
}

export function shortHash(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
}

