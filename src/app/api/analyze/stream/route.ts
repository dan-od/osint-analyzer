// Single lookup with live progress: newline-delimited JSON events
// (plan → progress / task … → result). The results page reads this to fill
// in findings as each source answers.
import { analyzeTarget, createAnalysisContext } from '@/lib/server/analysis';
import { prepareCheck } from '@/lib/server/analysis/guard';
import { recordCheck } from '@/lib/server/recent';
import { readJson } from '@/lib/server/http';
import type { AnalysisEvent } from '@/types';

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  const body = await readJson<{ query: string }>(request);
  const prepared = prepareCheck(request, body?.query);
  if (!prepared.ok) return prepared.response;
  const { user, validation } = prepared;

  const encoder = new TextEncoder();
  let closed = false;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: AnalysisEvent) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
        } catch {
          closed = true;
        }
      };
      try {
        const ctx = createAnalysisContext(user, 'single', { onEvent: send });
        const result = await analyzeTarget(validation, ctx);
        if (user) recordCheck(user.id, result.query, result.type);
        send({ type: 'result', result });
      } catch (error) {
        console.error('Streaming analysis error:', error);
        send({ type: 'error', error: 'Analysis failed' });
      } finally {
        if (!closed) {
          closed = true;
          controller.close();
        }
      }
    },
    cancel() {
      closed = true;
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-store, no-transform',
      'X-Accel-Buffering': 'no',
    },
  });
}
