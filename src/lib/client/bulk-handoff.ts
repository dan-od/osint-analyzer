// Hands a pasted list or uploaded CSV from the dashboard to the bulk page.
// Session storage only: it never leaves the browser until the job starts.
const KEY = 'oa-bulk-handoff';

export interface BulkHandoff {
  text: string;
  name: string;
}

export function stashBulkInput(handoff: BulkHandoff): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(handoff));
  } catch {
    // storage unavailable; the bulk page just opens empty
  }
}

export function takeBulkInput(): BulkHandoff | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    sessionStorage.removeItem(KEY);
    return raw ? (JSON.parse(raw) as BulkHandoff) : null;
  } catch {
    return null;
  }
}
