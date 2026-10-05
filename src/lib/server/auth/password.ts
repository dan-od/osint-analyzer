import bcrypt from 'bcryptjs';

const BCRYPT_COST = 12;
export const PASSWORD_MIN_LENGTH = 10;
// bcrypt silently ignores everything after 72 bytes, so reject longer input
const PASSWORD_MAX_BYTES = 72;

export function validatePassword(password: string): string | null {
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  }
  if (Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) {
    return `Password must be at most ${PASSWORD_MAX_BYTES} bytes`;
  }
  return null;
}

export function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_COST);
}

export function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// Used when the email doesn't exist so login takes the same time either way
let dummyHash: string | null = null;
export async function burnPasswordCheck(password: string): Promise<void> {
  dummyHash ??= await bcrypt.hash('timing-equalizer-not-a-real-password', BCRYPT_COST);
  await bcrypt.compare(password, dummyHash);
}
