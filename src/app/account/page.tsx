import { redirect } from 'next/navigation';

// The account section now lives in Settings
export default function AccountPage() {
  redirect('/settings#account');
}
