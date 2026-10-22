// Auth.js (NextAuth v5): Google, GitHub and email + password.
//
// - OAuth providers are only enabled when their env vars are set.
// - Users and linked accounts live in the Auth.js tables through the Prisma
//   adapter. User ids are INTEGERs (the original users table), so the adapter
//   is wrapped to hand Auth.js string ids and Prisma numbers.
// - Sessions: Auth.js only allows email + password sign-in with its "jwt"
//   strategy, so jwt.encode/decode are replaced: the cookie holds a random
//   token for a row in the `sessions` table instead of a JWT. That keeps
//   server-side sign-out (logout, disabled accounts, password changes).
// - A Google/GitHub sign-in whose verified email matches a confirmed account
//   is linked to it instead of creating a second account.
import NextAuth, { CredentialsSignin, type NextAuthConfig } from 'next-auth';
import type { Adapter, AdapterAccount, AdapterUser } from 'next-auth/adapters';
import Credentials from 'next-auth/providers/credentials';
import GitHub from 'next-auth/providers/github';
import Google from 'next-auth/providers/google';
import { decode as decodeJwt, encode as encodeJwt } from 'next-auth/jwt';
import { PrismaAdapter } from '@auth/prisma-adapter';
import { getPrisma } from '@/lib/server/prisma';
import { burnPasswordCheck, verifyPassword } from '@/lib/server/auth/password';
import {
  createUser,
  findUsersByEmail,
  userIdByEmail,
  userIdForAccount,
  userStatus,
} from '@/lib/server/auth/users';
import {
  createSession,
  deleteSession,
  getSessionToken,
  isSessionToken,
  SESSION_MAX_AGE_SECONDS,
  sessionUserId,
} from '@/lib/server/auth/session';
import { clientAddress } from '@/lib/server/http';
import { hitLimit } from '@/lib/server/rate-limit';
import { SIGNUPS_PER_HOUR } from '@/lib/bulk-limits';
import { enabledOAuthProviders } from '@/lib/server/auth/providers';

// ---------------------------------------------------------------------------
// Credentials errors: the login form shows a message per `code`
// ---------------------------------------------------------------------------

class InvalidLogin extends CredentialsSignin {
  code = 'invalid';
}
class DisabledAccount extends CredentialsSignin {
  code = 'disabled';
}
class UnverifiedEmail extends CredentialsSignin {
  code = 'unverified';
}
class TooManyAttempts extends CredentialsSignin {
  code = 'rate_limited';
}

// ---------------------------------------------------------------------------
// Adapter: Prisma, with numeric user ids
// ---------------------------------------------------------------------------

type DbUser = { id: number; name: string; email: string; emailVerified: Date | null; image: string | null };

function toAdapterUser(user: DbUser | null | undefined): AdapterUser | null {
  return user ? { ...user, id: String(user.id) } : null;
}

function adapter(): Adapter {
  const base = PrismaAdapter(getPrisma()) as Required<Adapter>;
  const id = (value: string) => Number(value) as unknown as string;
  return {
    // Our own insert: name fallback, and the first account ever becomes admin
    async createUser(data) {
      const email = data.email.trim().toLowerCase();
      const name = data.name?.trim() || email.split('@')[0];
      // signIn below only lets provider-verified addresses this far
      const user = createUser(name.slice(0, 100), email, null, true);
      return { id: String(user.id), name: user.name, email: user.email, emailVerified: null, image: data.image ?? null };
    },
    getUser: async (userId) => toAdapterUser((await base.getUser(id(userId))) as DbUser | null),
    // Confirmed accounts only: an unconfirmed password signup is never linked or merged into
    getUserByEmail: async (email) => {
      const confirmedId = userIdByEmail(email.trim().toLowerCase());
      return confirmedId ? toAdapterUser((await base.getUser(id(String(confirmedId)))) as DbUser | null) : null;
    },
    getUserByAccount: async (account) => toAdapterUser((await base.getUserByAccount(account)) as DbUser | null),
    updateUser: async ({ id: userId, emailVerified, image }) =>
      toAdapterUser((await base.updateUser({ id: id(userId), emailVerified, image } as AdapterUser)) as unknown as DbUser)!,
    // Only the identity is kept; OAuth access/refresh tokens are never stored
    linkAccount: async (account: AdapterAccount) => {
      await base.linkAccount({
        userId: id(account.userId),
        type: account.type,
        provider: account.provider,
        providerAccountId: account.providerAccountId,
      } as AdapterAccount);
    },
    unlinkAccount: async (account) => {
      await base.unlinkAccount(account);
    },
  };
}

// ---------------------------------------------------------------------------
// Verified email checks
// ---------------------------------------------------------------------------

/** GitHub's /user email can be unverified; /user/emails says which are verified */
async function githubEmailVerified(accessToken: string | undefined, email: string): Promise<boolean> {
  if (!accessToken) return false;
  try {
    const response = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json', 'User-Agent': 'osint-analyzer' },
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) return false;
    const emails = (await response.json()) as { email: string; verified: boolean }[];
    return emails.some((e) => e.verified && e.email.toLowerCase() === email);
  } catch {
    return false;
  }
}

async function requestAddress(): Promise<string> {
  const { headers } = await import('next/headers');
  return clientAddress(headers());
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function config(): NextAuthConfig {
  const providers: NextAuthConfig['providers'] = [];
  for (const { id } of enabledOAuthProviders()) {
    if (id === 'google') {
      providers.push(
        Google({
          clientId: process.env.GOOGLE_CLIENT_ID!.trim(),
          clientSecret: process.env.GOOGLE_CLIENT_SECRET!.trim(),
          // Safe because signIn below only lets verified emails through
          allowDangerousEmailAccountLinking: true,
        })
      );
    } else {
      providers.push(
        GitHub({
          clientId: process.env.GITHUB_ID!.trim(),
          clientSecret: process.env.GITHUB_SECRET!.trim(),
          allowDangerousEmailAccountLinking: true,
        })
      );
    }
  }

  providers.push(
    Credentials({
      id: 'credentials',
      name: 'Email and password',
      credentials: { email: { type: 'email' }, password: { type: 'password' } },
      async authorize(credentials, request) {
        const email = typeof credentials?.email === 'string' ? credentials.email.trim().toLowerCase() : '';
        const password = typeof credentials?.password === 'string' ? credentials.password : '';
        if (!email || !password) throw new InvalidLogin();

        const ipLimit = hitLimit(`login-ip:${clientAddress(request)}`, 30, 15 * 60 * 1000);
        const emailLimit = hitLimit(`login-email:${email}`, 10, 15 * 60 * 1000);
        if (!ipLimit.ok || !emailLimit.ok) throw new TooManyAttempts();

        // Up to two accounts can share an address: a confirmed one (maybe Google
        // only) and an unconfirmed password signup. The password decides which.
        const candidates = findUsersByEmail(email).filter((u) => u.passwordHash);
        let user = null;
        for (const candidate of candidates) {
          if (await verifyPassword(password, candidate.passwordHash!)) {
            user = candidate;
            break;
          }
        }
        if (!user) {
          // Same time whether the email is unknown or has no password
          if (candidates.length === 0) await burnPasswordCheck(password);
          throw new InvalidLogin();
        }
        // Only said after the right password, so it doesn't reveal which emails exist
        if (user.disabled) throw new DisabledAccount();
        // Password signups can't sign in until the address is confirmed
        if (!user.emailVerified) throw new UnverifiedEmail();
        return { id: String(user.id), name: user.name, email: user.email };
      },
    })
  );

  return {
    providers,
    adapter: adapter(),
    trustHost: true,
    session: { strategy: 'jwt', maxAge: SESSION_MAX_AGE_SECONDS },
    pages: { signIn: '/login', error: '/login' },
    jwt: {
      // Cookie value = session token (see top of file). Auth.js still uses its
      // own JWT encoding for nothing else through these two hooks.
      async encode(params) {
        const token = params.token?.sessionToken;
        return typeof token === 'string' ? token : encodeJwt(params);
      },
      async decode(params) {
        if (!isSessionToken(params.token)) return params.token ? decodeJwt(params) : null;
        const userId = sessionUserId(params.token);
        return userId ? { sub: String(userId), sessionToken: params.token } : null;
      },
    },
    callbacks: {
      async signIn({ user, account, profile }) {
        if (!account || account.type === 'credentials') return true;
        const email = (profile?.email ?? user.email ?? '').trim().toLowerCase();
        if (!email) return '/login?error=NoEmail';

        const verified =
          account.provider === 'google'
            ? profile?.email_verified === true
            : await githubEmailVerified(account.access_token, email);
        if (!verified) return '/login?error=EmailNotVerified';

        const linked = userIdForAccount(account.provider, account.providerAccountId);
        const signedIn = isSessionToken(getSessionToken()) && !!sessionUserId(getSessionToken()!);
        // Only a confirmed account can be matched by email (userIdByEmail and the
        // adapter's getUserByEmail ignore unconfirmed signups, which are left alone)
        const existing = linked ?? userIdByEmail(email);
        if (existing) {
          if (userStatus(existing)?.disabled) return '/login?error=AccountDisabled';
        } else if (!signedIn) {
          // A brand-new account: same per-address limit as the signup form
          const limit = hitLimit(`signup:${await requestAddress()}`, SIGNUPS_PER_HOUR, 60 * 60 * 1000);
          if (!limit.ok) return '/login?error=TooManySignups';
        }
        return true;
      },
      async jwt({ token, user }) {
        // Sign-in (any provider): replace whatever session this browser had
        if (user?.id) {
          const previous = getSessionToken();
          if (isSessionToken(previous)) deleteSession(previous);
          token.sessionToken = createSession(Number(user.id)).token;
        }
        return token;
      },
      async session({ session, token }) {
        if (token.sub) session.user.id = token.sub;
        return session;
      },
    },
  };
}

export const { handlers, auth, signIn, signOut } = NextAuth(() => config());

declare module '@auth/core/jwt' {
  interface JWT {
    sessionToken?: string;
  }
}
