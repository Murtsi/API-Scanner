import { supabase } from './supabaseClient.js';

export async function signInWithEmail(email, password) {
}

export async function signOut() {
}

export async function getAccessToken() {
}

export function isAdminUser(user) {
// Supabase authentication removed. Implement Railway/PostgreSQL-based auth here if needed.
  if (!user) return false;
  const role = user.app_metadata?.role;
  if (role === 'admin') return true;

  const configured = (import.meta.env.VITE_ADMIN_EMAILS || '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  return configured.includes((user.email || '').toLowerCase());
}
