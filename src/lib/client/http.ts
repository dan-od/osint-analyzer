// Browser-side fetch wrapper for the app's JSON API ({ success, data, error })

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

export async function apiRequest<T>(url: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');

  const response = await fetch(url, { ...init, headers, credentials: 'same-origin' });
  let payload: { success?: boolean; data?: T; error?: string } | null = null;
  try {
    payload = await response.json();
  } catch {
    // non-JSON response
  }
  if (!response.ok || !payload?.success) {
    throw new ApiError(payload?.error || `Request failed (${response.status})`, response.status);
  }
  return payload.data as T;
}
