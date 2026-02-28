export function methodNotAllowed(res) {
  return res.status(405).json({ error: 'Method not allowed' });
}

export function serverError(res, error, fallbackMessage) {
  return res.status(500).json({
    error: error?.message || fallbackMessage,
  });
}
