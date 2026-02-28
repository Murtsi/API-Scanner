import { supabase } from './supabaseClient.js';

export async function signInWithEmail(email, password) {
  return supabase.auth.signInWithPassword({ email, password });
}

export async function signOut() {
  return supabase.auth.signOut();
}

export async function getAccessToken() {
  const { data, error } = await supabase.auth.getSession();
  if (error) return null;
  return data.session?.access_token ?? null;
}

export function isAdminUser(user) {
  if (!user) return false;
  const role = user.app_metadata?.role;
  if (role === 'admin') return true;

  const configured = (import.meta.env.VITE_ADMIN_EMAILS || '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  return configured.includes((user.email || '').toLowerCase());
}
