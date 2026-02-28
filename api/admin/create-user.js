import { methodNotAllowed, serverError } from '../_http.js';
import { requireAdmin } from '../_supabase.js';

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      return methodNotAllowed(res);
    }

    const auth = await requireAdmin(req, res);
    if (!auth) return;

    const { adminClient } = auth;
    const { email, password, role = 'user' } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    if (String(password).length < 8) {
      return res.status(400).json({ error: 'password must be at least 8 characters' });
    }

    const normalizedRole = role === 'admin' ? 'admin' : 'user';

    const { data, error } = await adminClient.auth.admin.createUser({
      email: String(email).trim(),
      password: String(password),
      email_confirm: true,
      app_metadata: {
        role: normalizedRole,
      },
    });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(201).json({
      user: {
        id: data.user?.id,
        email: data.user?.email,
        role: data.user?.app_metadata?.role || 'user',
      },
    });
  } catch (error) {
    return serverError(res, error, 'Create user failed');
  }
}
