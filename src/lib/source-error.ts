// A source that could not answer. The task runner turns it into a "Skipped"
// row: `reason` is shown in the findings table (plain words, never scored),
// `detail` (status and response body) only goes to the server log.

export class SourceUnavailable extends Error {
  constructor(
    readonly reason: string,
    readonly detail?: string
  ) {
    super(reason);
    this.name = 'SourceUnavailable';
  }
}

export function statusReason(status: number): string {
  if (status === 401 || status === 403) return `the key was refused (HTTP ${status})`;
  if (status === 402) return 'the account is out of credits (HTTP 402)';
  if (status === 404) return 'the service answered "not found" (HTTP 404)';
  if (status === 429) return 'rate limit reached (HTTP 429), try again later';
  if (status >= 500) return `the service is having problems (HTTP ${status})`;
  return `unexpected answer (HTTP ${status})`;
}

/** Status and body of a failed response, one line, with the key blanked out. */
export async function responseDetail(response: Response, secret?: string): Promise<string> {
  let body = (await response.text().catch(() => '')).replace(/\s+/g, ' ').trim().slice(0, 4000);
  if (secret) body = body.split(secret).join('[key]');
  return `HTTP ${response.status}${body ? ` ${body}` : ''}`;
}

/** Error for a non-2xx response. `reason` overrides the generic wording. */
export async function unavailableResponse(
  source: string,
  response: Response,
  options: { reason?: string; secret?: string } = {}
): Promise<SourceUnavailable> {
  return new SourceUnavailable(
    options.reason ?? `${source} unavailable: ${statusReason(response.status)}.`,
    await responseDetail(response, options.secret)
  );
}

/** Anything thrown while calling a source (network error, timeout, unreadable JSON). */
export function asUnavailable(source: string, error: unknown): SourceUnavailable {
  if (error instanceof SourceUnavailable) return error;
  const name = error instanceof Error ? error.name : '';
  const message = error instanceof Error ? error.message : String(error);
  if (name === 'TimeoutError' || name === 'AbortError') {
    return new SourceUnavailable(`${source} unavailable: no answer in time.`, message);
  }
  if (error instanceof SyntaxError) {
    return new SourceUnavailable(`${source} unavailable: its answer could not be read.`, message);
  }
  return new SourceUnavailable(`${source} unavailable: could not reach it.`, message);
}

/**
 * Remembers an account-level failure (bad key, no credits) for a while, so
 * later checks skip at once instead of repeating a call that will fail.
 */
export class Cooldown {
  private until = 0;
  private reason = '';

  constructor(private readonly ms: number) {}

  /** Throws (without a log detail, so it isn't logged again) while cooling down */
  check(): void {
    if (Date.now() < this.until) throw new SourceUnavailable(this.reason);
  }

  trip(failure: SourceUnavailable): SourceUnavailable {
    this.until = Date.now() + this.ms;
    this.reason = failure.reason;
    return failure;
  }
}
