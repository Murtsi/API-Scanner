import { verifyToken } from './authRoutes.js';

export function requireAuth(req, res, next) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    return res.status(503).json({ error: 'Auth not configured' });
  }

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized — Bearer token required' });
  }

  try {
    req.user = verifyToken(token, secret);
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
