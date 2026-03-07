import { methodNotAllowed, serverError } from '../_http.js';
import { requireAdmin } from '../_requireAdmin.js';

export default async function handler(req, res) {
  try {
    if (req.method !== 'GET') {
      return methodNotAllowed(res);
    }

    const auth = await requireAdmin(req, res);
    if (!auth) return;

    // User management has not yet been migrated from Supabase.
    // Implement PostgreSQL-based user listing here once a users table is added.
    return res.status(501).json({
      error: 'User management is not yet implemented. The Supabase migration is incomplete.',
    });
  } catch (error) {
    return serverError(res, error, 'List users failed');
  }
}
