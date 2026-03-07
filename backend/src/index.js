import express from 'express';
import cors from 'cors';
import { createJob, getJob, listJobs, updateJob, appendJobLog } from './jobStore.js';
import { enqueue } from './queue.js';
import { runScanJob } from './scannerService.js';
import authRouter from './authRoutes.js';
import { requireAuth } from './authMiddleware.js';

const app = express();
const port = Number.parseInt(process.env.PORT || '8787', 10);

// ── CORS — restrict to the configured frontend origin ─────────────────────────
const allowedOrigin = process.env.FRONTEND_ORIGIN;
if (!allowedOrigin) {
  console.warn('WARNING: FRONTEND_ORIGIN is not set — CORS is disabled. Set it to your frontend URL.');
}
app.use(cors({
  origin: allowedOrigin || false,
  credentials: true,
}));

app.use(express.json({ limit: '1mb' }));

// ── Auth routes (public — no token required) ──────────────────────────────────
app.use(authRouter);

// ── SSRF blocklist ────────────────────────────────────────────────────────────
const PRIVATE_HOST_RE = /^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|::1$|0\.0\.0\.0|metadata\.google\.internal)$/i;

function isSsrfTarget(urlStr) {
  try {
    const { hostname } = new URL(urlStr);
    return PRIVATE_HOST_RE.test(hostname);
  } catch {
    return true;
  }
}

// ── Health (public) ───────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'api-scanner-backend' });
});

// ── Scan endpoints (protected) ────────────────────────────────────────────────
app.get('/api/v1/scans', requireAuth, (req, res) => {
  const limit = Number.parseInt(req.query.limit || '20', 10);
  const jobs = listJobs(Number.isFinite(limit) ? Math.min(limit, 100) : 20);
  res.json({ jobs });
});

app.get('/api/v1/scans/:id', requireAuth, (req, res) => {
  const job = getJob(req.params.id);
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }

  return res.json({ job });
});

app.post('/api/v1/scans/:id/cancel', requireAuth, (req, res) => {
  const job = getJob(req.params.id);
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }

  if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
    return res.status(409).json({ error: `Cannot cancel a ${job.status} job` });
  }

  const updated = updateJob(job.id, { status: 'cancelled', completedAt: new Date().toISOString() });
  appendJobLog(job.id, 'Job cancelled by user', 'warn');

  return res.json({ job: updated });
});

app.post('/api/v1/scans', requireAuth, (req, res) => {
  const { targets, options = {} } = req.body ?? {};

  if (!Array.isArray(targets) || targets.length === 0) {
    return res.status(400).json({ error: 'targets must be a non-empty array of URLs' });
  }

  const cleanedTargets = targets
    .map((target) => (typeof target === 'string' ? target.trim() : ''))
    .filter(Boolean)
    .filter((target) => /^https?:\/\//i.test(target))
    .filter((target) => {
      if (isSsrfTarget(target)) {
        console.warn(`[SSRF] Blocked private/internal target: ${target}`);
        return false;
      }
      return true;
    });

  if (cleanedTargets.length === 0) {
    return res.status(400).json({ error: 'No valid public http/https targets provided' });
  }

  const job = createJob({
    targets: [...new Set(cleanedTargets)].slice(0, 20),
    options,
  });

  appendJobLog(job.id, `Job queued with ${job.targets.length} target(s)`);

  enqueue(async () => {
    const latest = getJob(job.id);
    if (!latest || latest.status === 'cancelled') return;

    updateJob(job.id, {
      status: 'running',
      startedAt: new Date().toISOString(),
    });

    appendJobLog(job.id, 'Job started');

    try {
      const result = await runScanJob(job, {
        shouldCancel: () => {
          const current = getJob(job.id);
          return !current || current.status === 'cancelled';
        },
        onProgress: (progressPatch) => {
          updateJob(job.id, {
            progress: {
              ...progressPatch,
              totalTargets: job.targets.length,
            },
          });
        },
        onLog: (message, type = 'info') => {
          appendJobLog(job.id, message, type);
        },
      });

      const latestAfterRun = getJob(job.id);
      if (!latestAfterRun || latestAfterRun.status === 'cancelled') {
        return;
      }

      updateJob(job.id, {
        status: 'completed',
        completedAt: new Date().toISOString(),
        result,
      });
      appendJobLog(job.id, 'Job completed', 'success');
    } catch (error) {
      const latestFailed = getJob(job.id);
      if (!latestFailed || latestFailed.status === 'cancelled') {
        return;
      }

      updateJob(job.id, {
        status: 'failed',
        completedAt: new Date().toISOString(),
        error: error?.message || 'Job failed',
      });
      appendJobLog(job.id, `Job failed: ${error?.message || 'unknown error'}`, 'error');
    }
  });

  return res.status(202).json({ jobId: job.id });
});

app.listen(port, () => {
  console.log(`API Scanner backend listening on http://localhost:${port}`);
});
