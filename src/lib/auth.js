
// POST to /api/auth/login, store JWT in localStorage
export async function signInWithEmail(email, password) {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) throw new Error('Login failed');
  const { token, user } = await res.json();
  localStorage.setItem('token', token);
  localStorage.setItem('user', JSON.stringify(user));
  return user;
}

// Remove JWT and user from localStorage
export function signOut() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  return null;
}

// Get JWT from localStorage
export function getAccessToken() {
  return localStorage.getItem('token');
}

// Get user object from localStorage
export function getSession() {
  const user = localStorage.getItem('user');
  if (!user) return null;
  return { user: JSON.parse(user) };
}

// Check if user is admin
export function isAdminUser(user) {
  if (!user) return false;
  const configured = (import.meta.env.VITE_ADMIN_EMAILS || '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  return configured.includes((user.email || '').toLowerCase());
}
