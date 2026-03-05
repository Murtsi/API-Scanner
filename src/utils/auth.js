// Secure cookie-based session manager for API Scanner Pro
export async function signInWithEmail(email, password, csrfToken) {
  const res = await fetch('/api/auth/set-cookie', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    },
    credentials: 'include',
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) throw new Error('Login failed');
  return await res.json();
}

export async function signOut(csrfToken) {
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken },
    credentials: 'include'
  });
}

export async function getSession() {
  const res = await fetch('/api/auth/session', { credentials: 'include' });
  if (!res.ok) return null;
  return await res.json();
}

export function isAdminUser(user) {
  if (!user) return false;
  const configured = (import.meta.env.VITE_ADMIN_EMAILS || '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  return configured.includes((user.email || '').toLowerCase());
}
