import { getCurrentUser } from '@/lib/server/auth/session';
import { jsonOk } from '@/lib/server/http';

export const dynamic = 'force-dynamic';

export async function GET() {
  return jsonOk({ user: getCurrentUser() }, { headers: { 'Cache-Control': 'no-store' } });
}
