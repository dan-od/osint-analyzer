// Auth.js endpoints: /api/auth/signin, /callback/{google,github,credentials},
// /csrf, /providers, /session. Our own /api/auth/{signup,logout,me} routes are
// static and take precedence over this catch-all.
import { handlers } from '@/auth';

export const { GET, POST } = handlers;
