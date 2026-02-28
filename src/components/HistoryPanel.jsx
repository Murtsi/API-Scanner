import { useEffect, useState } from 'react';
import { deleteScanRun, listScanRuns } from '../lib/scanHistory.js';
import { formatDateTime } from '../lib/formatters.js';

function summarize(run) {
  const targets = Array.isArray(run.targets) ? run.targets.length : 0;
  const resultTargets = Array.isArray(run.result?.results) ? run.result.results.length : 0;
  const findingTypes = (run.result?.results || []).reduce((sum, item) => sum + (item.findings?.length || 0), 0);

  return {
    targets: Math.max(targets, resultTargets),
    findingTypes,
  };
}

export default function HistoryPanel({ refreshToken, onLoadRun }) {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchRuns = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await listScanRuns(30);
      setRuns(data);
    } catch (err) {
      setError(err.message || 'Failed to load history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
  }, [refreshToken]);

  const handleDelete = async (runId) => {
    setError('');
    try {
      await deleteScanRun(runId);
      await fetchRuns();
    } catch (err) {
      setError(err.message || 'Failed to delete run');
    }
  };

  return (
    <section className="card history-card">
      <div className="history-head">
        <h2>History</h2>
        <button type="button" className="btn-secondary" onClick={fetchRuns} disabled={loading}>
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <p className="muted small">Saved scans for your account. New scans are stored automatically.</p>

      {error ? <div className="auth-error">{error}</div> : null}

      <div className="history-list">
        {runs.map((run) => {
          const info = summarize(run);

          return (
            <div key={run.id} className="history-item">
              <div>
                <div className="history-title">{formatDateTime(run.created_at)}</div>
                <div className="muted small">
                  {info.targets} target(s) · {info.findingTypes} finding type(s)
                </div>
              </div>
              <div className="history-actions">
                <button type="button" className="btn-secondary" onClick={() => onLoadRun(run)}>
                  Load
                </button>
                <button type="button" className="btn-secondary" onClick={() => handleDelete(run.id)}>
                  Delete
                </button>
              </div>
            </div>
          );
        })}

        {!loading && runs.length === 0 ? (
          <p className="muted small">No saved scans yet.</p>
        ) : null}
      </div>
    </section>
  );
}
