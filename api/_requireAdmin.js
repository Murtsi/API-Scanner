import { createHmac, timingSafeEqual } from 'node:crypto';

function b64url(buf) {
  return (Buffer.isBuffer(buf) ? buf : Buffer.from(buf)).toString('base64url');
}

function verifyToken(token, secret) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const [header, body, sig] = parts;
  const expected = b64url(createHmac('sha256', secret).update(`${header}.${body}`).digest());
  const sigBuf = Buffer.from(sig, 'base64url');
  const expBuf = Buffer.from(expected, 'base64url');
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    throw new Error('Invalid signature');
  }
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }
  return payload;
}

/**
 * Verify the request carries a valid admin JWT.
 * Returns the token payload on success, or sends a 401/403 and returns null.
 */
export async function requireAdmin(req, res) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    res.status(503).json({ error: 'Auth not configured' });
    return null;
  }

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    res.status(401).json({ error: 'Unauthorized — Bearer token required' });
    return null;
  }

  try {
    const payload = verifyToken(token, secret);
    if (payload.role !== 'admin') {
      res.status(403).json({ error: 'Forbidden — admin role required' });
      return null;
    }
    return { user: payload };
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
    return null;
  }
}
