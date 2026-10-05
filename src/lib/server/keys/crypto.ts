// AES-256-GCM encryption for stored API keys. The 256-bit key is derived from
// KEY_ENCRYPTION_SECRET with HKDF; each value gets a random 96-bit IV and is
// bound (as AAD) to its owner and service so ciphertexts can't be swapped
// between rows.
import crypto from 'crypto';

const FORMAT_VERSION = 'v1';
const MIN_SECRET_LENGTH = 32;

export class EncryptionConfigError extends Error {}

let cached: { secret: string; key: Buffer } | null = null;

function encryptionKey(): Buffer {
  const secret = process.env.KEY_ENCRYPTION_SECRET ?? '';
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new EncryptionConfigError(
      `KEY_ENCRYPTION_SECRET must be set to at least ${MIN_SECRET_LENGTH} characters to store API keys`
    );
  }
  if (cached?.secret !== secret) {
    const derived = crypto.hkdfSync('sha256', secret, 'osint-analyzer/api-keys', 'aes-256-gcm v1', 32);
    cached = { secret, key: Buffer.from(derived) };
  }
  return cached.key;
}

export function isEncryptionConfigured(): boolean {
  return (process.env.KEY_ENCRYPTION_SECRET ?? '').length >= MIN_SECRET_LENGTH;
}

export function encryptSecret(plaintext: string, aad: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [FORMAT_VERSION, iv.toString('base64'), tag.toString('base64'), ciphertext.toString('base64')].join(':');
}

export function decryptSecret(payload: string, aad: string): string {
  const [version, iv, tag, ciphertext] = payload.split(':');
  if (version !== FORMAT_VERSION || !iv || !tag || !ciphertext) {
    throw new Error('Unrecognised encrypted key format');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(iv, 'base64'));
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]).toString('utf8');
}
