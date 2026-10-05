import { isEncryptionConfigured } from '@/lib/server/keys/crypto';
import { keyStatusesFor } from '@/lib/server/keys/status';
import { jsonOk, requireApiUser } from '@/lib/server/http';
import type { ApiKeysOverview } from '@/types/account';

export const dynamic = 'force-dynamic';

export async function GET() {
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;

  const overview: ApiKeysOverview = {
    encryptionReady: isEncryptionConfigured(),
    keys: keyStatusesFor(auth.user.id),
  };
  return jsonOk(overview, { headers: { 'Cache-Control': 'no-store' } });
}
