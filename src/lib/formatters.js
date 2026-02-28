export function formatDateTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString();
}

export function isUserDisabled(user) {
  if (!user?.banned_until) return false;
  const until = new Date(user.banned_until);
  return until.getTime() > Date.now();
}
