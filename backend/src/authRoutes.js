import express from 'express';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { findUser, verifyPassword } from './userStore.js';

const router = express.Router();

// ── Minimal JWT (HS256) using built-in crypto ─────────────────────────────────

function b64url(buf) {
  return (Buffer.isBuffer(buf) ? buf : Buffer.from(buf)).toString('base64url');
}

export function signToken(payload, secret, expiresInSec = 86400) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresInSec,
  }));
  const sig = b64url(createHmac('sha256', secret).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

export function verifyToken(token, secret) {
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

// ── Timing-safe string comparison ────────────────────────────────────────────

function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a));
  const bBuf = Buffer.from(String(b));
  const max = Math.max(aBuf.length, bBuf.length);
  const pa = Buffer.concat([aBuf, Buffer.alloc(max - aBuf.length)]);
  const pb = Buffer.concat([bBuf, Buffer.alloc(max - bBuf.length)]);
  return timingSafeEqual(pa, pb) && aBuf.length === bBuf.length;
}

// ── Auth routes ───────────────────────────────────────────────────────────────

router.post('/api/auth/login', async (req, res) => {
  const secret = process.env.AUTH_SECRET;

  if (!secret) {
    return res.status(503).json({
      error: 'Auth not configured — set AUTH_SECRET in environment',
    });
  }

  const { email = '', password = '' } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const user = findUser(email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = signToken({ userId: user.email, email: user.email, role: user.role }, secret);
  return res.json({ token, user: { email: user.email, role: user.role } });
});

router.post('/api/auth/logout', (_req, res) => {
  return res.json({ ok: true });
});

router.get('/api/auth/session', (req, res) => {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return res.status(503).json({ error: 'Auth not configured' });

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No session' });

  try {
    const payload = verifyToken(token, secret);
    return res.json({ user: { email: payload.email, role: payload.role } });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
});

export default router;
