import { requireAdmin } from '../_supabase.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const auth = await requireAdmin(req, res);
  if (!auth) return;

  const { adminClient } = auth;
  const { data, error } = await adminClient.auth.admin.listUsers();

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  const users = (data?.users || []).map((user) => ({
    id: user.id,
    email: user.email,
    created_at: user.created_at,
    last_sign_in_at: user.last_sign_in_at,
    banned_until: user.banned_until,
    app_metadata: user.app_metadata,
  }));

  return res.status(200).json({ users });
}
