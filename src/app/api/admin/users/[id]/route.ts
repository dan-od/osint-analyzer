// Admin actions on one account: raise (or reset) its bulk cap, disable or
// re-enable it, or delete it. Admins can't disable or delete an admin
// (including themselves), so the site can't be locked out of its own admin page.
import { BULK_MAX_TARGETS } from '@/lib/bulk-input';
import { deleteUser, findAnyUserById, setBulkCap, setDisabled } from '@/lib/server/auth/users';
import { checkSameOrigin, jsonError, jsonOk, readJson, requireApiAdmin } from '@/lib/server/http';

export const dynamic = 'force-dynamic';

function target(params: { id: string }) {
  const id = Number(params.id);
  return Number.isInteger(id) && id > 0 ? findAnyUserById(id) : null;
}

export async function PATCH(request: Request, { params }: { params: { id: string } }) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiAdmin();
  if ('response' in auth) return auth.response;
  const user = target(params);
  if (!user) return jsonError('Account not found', 404);

  const body = await readJson<{ bulkCap: number | null; disabled: boolean }>(request);
  if (!body) return jsonError('Nothing to change', 400);

  if (body.bulkCap !== undefined) {
    const cap = body.bulkCap;
    if (cap !== null && !(Number.isInteger(cap) && cap >= 1 && cap <= BULK_MAX_TARGETS)) {
      return jsonError(`Bulk cap must be a whole number from 1 to ${BULK_MAX_TARGETS}`, 400);
    }
    setBulkCap(user.id, cap);
  }
  if (body.disabled !== undefined) {
    if (typeof body.disabled !== 'boolean') return jsonError('disabled must be true or false', 400);
    if (user.role === 'admin') return jsonError('Admin accounts can’t be disabled', 400);
    setDisabled(user.id, body.disabled);
  }
  return jsonOk({ user: findAnyUserById(user.id) });
}

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiAdmin();
  if ('response' in auth) return auth.response;
  const user = target(params);
  if (!user) return jsonError('Account not found', 404);
  if (user.role === 'admin') return jsonError('Admin accounts can’t be deleted', 400);
  deleteUser(user.id);
  return jsonOk({ deleted: user.id });
}
