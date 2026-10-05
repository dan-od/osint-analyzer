import { clearSessionCookie, deleteSession, getSessionToken } from '@/lib/server/auth/session';
import { checkSameOrigin, jsonOk } from '@/lib/server/http';

export async function POST(request: Request) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;

  const token = getSessionToken();
  if (token) deleteSession(token);
  const res = jsonOk({ loggedOut: true });
  clearSessionCookie(res);
  return res;
}
