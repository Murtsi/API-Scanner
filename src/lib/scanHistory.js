import { query } from './db.js';

export async function createScanRun({ userId, targets, options, result }) {
  const insertQuery = `
    INSERT INTO scan_runs (owner_id, targets, options, result, created_at)
    VALUES ($1, $2, $3, $4, NOW())
    RETURNING id, created_at
  `;
  const params = [userId, JSON.stringify(targets), JSON.stringify(options), JSON.stringify(result)];
  try {
    const { rows } = await query(insertQuery, params);
    return rows[0];
  } catch (err) {
    throw new Error(err.message || 'Failed to save scan run');
  }
}

export async function listScanRuns(userId, limit = 20) {
  const selectQuery = `
    SELECT id, targets, options, result, created_at
    FROM scan_runs
    WHERE owner_id = $1
    ORDER BY created_at DESC
    LIMIT $2
  `;
  try {
    const { rows } = await query(selectQuery, [userId, limit]);
    return rows;
  } catch (err) {
    throw new Error(err.message || 'Failed to fetch scan history');
  }
}

export async function deleteScanRun(runId) {
  const deleteQuery = `DELETE FROM scan_runs WHERE id = $1`;
  try {
    await query(deleteQuery, [runId]);
  } catch (err) {
    throw new Error(err.message || 'Failed to delete scan run');
  }
}
