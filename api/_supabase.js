import { createClient } from '@supabase/supabase-js';

function parseAdminEmails() {
  return (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}

export function getAdminClient() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured');
  }

  return createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

function getBearerToken(req) {
  const header = req.headers.authorization || req.headers.Authorization;
  if (!header || !header.toLowerCase().startsWith('bearer ')) {
    return null;
  }
  return header.slice(7).trim();
}

export async function requireAdmin(req, res) {
  const token = getBearerToken(req);
  if (!token) {
    res.status(401).json({ error: 'Missing bearer token' });
    return null;
  }

  let adminClient;
  try {
    adminClient = getAdminClient();
  } catch (error) {
    res.status(500).json({ error: error.message || 'Admin API is not configured' });
    return null;
  }

  const { data, error } = await adminClient.auth.getUser(token);

  if (error || !data?.user) {
    res.status(401).json({ error: 'Invalid token' });
    return null;
  }

  const user = data.user;
  const email = (user.email || '').toLowerCase();
  const emails = parseAdminEmails();
  const role = user.app_metadata?.role;

  const allowed = role === 'admin' || emails.includes(email);
  if (!allowed) {
    res.status(403).json({ error: 'Admin access required' });
    return null;
  }

  return { adminClient, user };
}
