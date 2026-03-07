import { getAccessToken } from './auth.js';

const API_BASE = import.meta.env.VITE_API_URL || ''

async function request(path, options = {}) {
  const token = await getAccessToken();
  if (!token) {
    throw new Error('Not authenticated');
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed (${response.status})`);
  }

  return payload;
}

export async function listManagedUsers() {
  const payload = await request('/api/admin/list-users');
  return payload.users || [];
}

export async function createManagedUser({ email, password, role = 'user' }) {
  const payload = await request('/api/admin/create-user', {
    method: 'POST',
    body: JSON.stringify({ email, password, role }),
  });
  return payload.user;
}

export async function setManagedUserDisabled({ userId, disabled }) {
  const payload = await request('/api/admin/set-user-status', {
    method: 'POST',
    body: JSON.stringify({ userId, disabled }),
  });
  return payload.user;
}
