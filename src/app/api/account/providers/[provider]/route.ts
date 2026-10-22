// Unlink Google or GitHub from the signed-in account. The last way to sign in
// (password or provider) can't be removed.
import { signInMethodCount, unlinkProvider } from '@/lib/server/auth/users';
import { checkSameOrigin, jsonError, jsonOk, requireApiUser } from '@/lib/server/http';

export const dynamic = 'force-dynamic';

export async function DELETE(request: Request, { params }: { params: { provider: string } }) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;

  if (signInMethodCount(auth.user.id) <= 1) {
    return jsonError('This is your only way to sign in. Add a password or link another account first.', 409);
  }
  if (!unlinkProvider(auth.user.id, params.provider)) return jsonError('That account is not linked', 404);
  return jsonOk({ unlinked: params.provider });
}
