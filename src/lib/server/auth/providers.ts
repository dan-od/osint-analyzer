// Which Google/GitHub sign-in buttons exist: a provider is on only when both
// of its env vars are set.
export type OAuthProviderId = 'google' | 'github';

export interface OAuthProviderInfo {
  id: OAuthProviderId;
  name: string;
}

export function enabledOAuthProviders(): OAuthProviderInfo[] {
  const list: OAuthProviderInfo[] = [];
  if (process.env.GOOGLE_CLIENT_ID?.trim() && process.env.GOOGLE_CLIENT_SECRET?.trim()) list.push({ id: 'google', name: 'Google' });
  if (process.env.GITHUB_ID?.trim() && process.env.GITHUB_SECRET?.trim()) list.push({ id: 'github', name: 'GitHub' });
  return list;
}

/** Messages for Auth.js's ?error= codes and our own sign-in refusals */
export const AUTH_ERRORS: Record<string, string> = {
  OAuthAccountNotLinked: 'That Google or GitHub account is already linked to a different account here.',
  EmailNotVerified: 'Your Google or GitHub email address isn’t verified yet. Verify it there, then try again.',
  NoEmail: 'Your Google or GitHub account didn’t share an email address, so we can’t sign you in with it.',
  AccountDisabled: 'This account has been disabled. Contact the administrator.',
  TooManySignups: 'Too many new accounts from your network. Try again later.',
  AccessDenied: 'Sign-in was cancelled or refused.',
};
export const AUTH_ERROR_FALLBACK = 'Sign-in didn’t work. Try again, or use another way to sign in.';
