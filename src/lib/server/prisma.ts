// Prisma client for the Auth.js adapter. It opens the same SQLite file as
// db.ts; getDb() runs first so the tables exist and are migrated.
import { PrismaClient } from '@prisma/client';
import { getDb, resolveDbPath } from './db';

const globalForPrisma = globalThis as unknown as { __osintPrisma?: PrismaClient };

export function getPrisma(): PrismaClient {
  if (!globalForPrisma.__osintPrisma) {
    getDb();
    // Prisma resolves relative SQLite paths against prisma/, not the app root,
    // so hand it the absolute path db.ts uses
    const datasourceUrl = `file:${resolveDbPath().split('\\').join('/')}`;
    globalForPrisma.__osintPrisma = new PrismaClient({ datasourceUrl });
  }
  return globalForPrisma.__osintPrisma;
}
