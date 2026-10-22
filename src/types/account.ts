// Account types shared by the server and the browser

export type UserRole = 'user' | 'admin';

export interface PublicUser {
  id: number;
  name: string;
  email: string;
  createdAt: string;
  role: UserRole;
  /** Most targets this account can queue in one bulk job */
  bulkCap: number;
}

/** A row on the /admin accounts page */
export interface AdminUserRow extends PublicUser {
  disabled: boolean;
  /** null: never seen since the column was added */
  lastActiveAt: string | null;
  lookups: number;
  /** The cap an admin set, or null for the new-account default */
  customBulkCap: number | null;
  /** False for a password signup that hasn't confirmed its email yet */
  emailVerified: boolean;
}

export interface ApiKeyStatus {
  service: import('@/lib/services').ServiceId;
  /** e.g. "••••a3f9" – the full key never leaves the server */
  maskedKey: string | null;
  updatedAt: string | null;
  /** The server has its own key this service falls back to for single lookups */
  serverFallback: boolean;
  usage: {
    userToday: number;
    serverToday: number;
    quota: {
      limit: number;
      period: 'day' | 'week' | 'month';
      used: number;
      remaining: number;
      /** Per-day cap inside a weekly/monthly allowance */
      dailyCap: { limit: number; used: number; remaining: number } | null;
    } | null;
  };
}

export interface ApiKeysOverview {
  encryptionReady: boolean;
  keys: ApiKeyStatus[];
}
