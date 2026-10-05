import { getService } from '@/lib/services';
import { EncryptionConfigError } from '@/lib/server/keys/crypto';
import { deleteUserKey, saveUserKey } from '@/lib/server/keys/store';
import { keyStatusesFor } from '@/lib/server/keys/status';
import { checkSameOrigin, jsonError, jsonOk, readJson, requireApiUser } from '@/lib/server/http';

export const dynamic = 'force-dynamic';

type Params = { params: { service: string } };

export async function PUT(request: Request, { params }: Params) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;

  const service = getService(params.service);
  if (!service) return jsonError('Unknown service', 404);

  const body = await readJson<{ key: string }>(request);
  const key = typeof body?.key === 'string' ? body.key.trim() : '';
  if (!service.keyPattern.test(key)) {
    return jsonError(`That doesn't look like a valid ${service.name} key (${service.keyHint})`, 400);
  }

  try {
    saveUserKey(auth.user.id, service.id, key);
  } catch (error) {
    if (error instanceof EncryptionConfigError) return jsonError(error.message, 503);
    throw error;
  }
  return jsonOk(keyStatusesFor(auth.user.id, service.id)[0]);
}

export async function DELETE(request: Request, { params }: Params) {
  const blocked = checkSameOrigin(request);
  if (blocked) return blocked;
  const auth = requireApiUser();
  if ('response' in auth) return auth.response;

  const service = getService(params.service);
  if (!service) return jsonError('Unknown service', 404);

  deleteUserKey(auth.user.id, service.id);
  return jsonOk(keyStatusesFor(auth.user.id, service.id)[0]);
}
