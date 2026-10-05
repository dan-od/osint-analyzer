import { NextResponse } from 'next/server';
import { analyzeTarget, createAnalysisContext } from '@/lib/server/analysis';
import { prepareCheck } from '@/lib/server/analysis/guard';
import { recordCheck } from '@/lib/server/recent';

// ============================================
// API ROUTE HANDLERS
// ============================================
// Plain JSON version of a single lookup. The results page uses /api/analyze/stream.
export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    const prepared = prepareCheck(request, body?.query);
    if (!prepared.ok) return prepared.response;

    const { user, validation } = prepared;
    const result = await analyzeTarget(validation, createAnalysisContext(user, 'single'));
    if (user) recordCheck(user.id, result.query, result.type);

    return NextResponse.json({
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Analysis API error:', error);
    return NextResponse.json(
      { success: false, error: 'Analysis failed' },
      { status: 500 }
    );
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'OSINT Analyzer API',
    version: '3.0.0',
    endpoints: {
      analyze: {
        method: 'POST',
        body: { query: 'string' },
        description: 'Analyze an email, domain, IP address (login required), phone number, or crypto wallet'
      },
      stream: {
        method: 'POST',
        path: '/api/analyze/stream',
        body: { query: 'string' },
        description: 'Same, streamed as newline-delimited JSON events while sources answer'
      }
    }
  });
}
