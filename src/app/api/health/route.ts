// Liveness for the deploy workflow: answers once the server is up and the
// SQLite database has opened (which also runs any pending schema migration).
import { NextResponse } from 'next/server';
import { getDb } from '@/lib/server/db';

export const dynamic = 'force-dynamic';

export function GET() {
  try {
    getDb().prepare('SELECT 1').get();
    return NextResponse.json({ ok: true }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (error) {
    console.error('Health check: database not ready:', (error as Error).message);
    return NextResponse.json({ ok: false }, { status: 503, headers: { 'Cache-Control': 'no-store' } });
  }
}
