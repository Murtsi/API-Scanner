import { methodNotAllowed, serverError } from '../_http.js';
// Supabase admin removed. Implement Railway/PostgreSQL-based admin logic here if needed.

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      return methodNotAllowed(res);
    }

    const auth = await requireAdmin(req, res);
    if (!auth) return;

    const { adminClient } = auth;
    const { userId, disabled } = req.body || {};

    if (!userId || typeof disabled !== 'boolean') {
      return res.status(400).json({ error: 'userId and disabled(boolean) are required' });
    }

    const payload = disabled
      ? { ban_duration: '876000h' }
      : { ban_duration: 'none' };

    const { data, error } = await adminClient.auth.admin.updateUserById(userId, payload);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    return res.status(200).json({
      user: {
        id: data.user?.id,
        email: data.user?.email,
        banned_until: data.user?.banned_until,
      },
    });
  } catch (error) {
    return serverError(res, error, 'Update user status failed');
  }
}
