import DOMPurify from 'dompurify';

export function sanitizeInput(input) {
  return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
}

export function getCSRFToken() {
  let token = sessionStorage.getItem('csrfToken');
  if (!token) {
    token = crypto.randomUUID();
    sessionStorage.setItem('csrfToken', token);
  }
  return token;
}

export function rateLimit(key, maxPerMinute = 10) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const history = JSON.parse(localStorage.getItem(key) || '[]').filter(ts => now - ts < windowMs);
  if (history.length >= maxPerMinute) return false;
  history.push(now);
  localStorage.setItem(key, JSON.stringify(history));
  return true;
}
