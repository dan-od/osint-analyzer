import { apiRequest } from './http';
import type { PublicUser } from '@/types/account';

export interface SignupInput {
  name: string;
  email: string;
  password: string;
  inviteCode: string;
}

export async function fetchCurrentUser(): Promise<PublicUser | null> {
  const data = await apiRequest<{ user: PublicUser | null }>('/api/auth/me', { cache: 'no-store' });
  return data.user;
}

export async function login(email: string, password: string): Promise<PublicUser> {
  const data = await apiRequest<{ user: PublicUser }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  return data.user;
}

export async function signup(input: SignupInput): Promise<PublicUser> {
  const data = await apiRequest<{ user: PublicUser }>('/api/auth/signup', {
    method: 'POST',
    body: JSON.stringify(input),
  });
  return data.user;
}

export async function logout(): Promise<void> {
  await apiRequest('/api/auth/logout', { method: 'POST' });
}
