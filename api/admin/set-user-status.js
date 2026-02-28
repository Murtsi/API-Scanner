import { requireAdmin } from '../_supabase.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
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
}
