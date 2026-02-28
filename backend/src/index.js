import express from 'express';
import cors from 'cors';
import { createJob, getJob, listJobs, updateJob, appendJobLog } from './jobStore.js';
import { enqueue } from './queue.js';
import { runScanJob } from './scannerService.js';

const app = express();
const port = Number.parseInt(process.env.PORT || '8787', 10);

app.use(cors());
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'api-scanner-backend' });
});

app.get('/api/v1/scans', (req, res) => {
  const limit = Number.parseInt(req.query.limit || '20', 10);
  const jobs = listJobs(Number.isFinite(limit) ? Math.min(limit, 100) : 20);
  res.json({ jobs });
});

app.get('/api/v1/scans/:id', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }

  return res.json({ job });
});

app.post('/api/v1/scans/:id/cancel', (req, res) => {
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

app.post('/api/v1/scans', (req, res) => {
  const { targets, options = {} } = req.body ?? {};

  if (!Array.isArray(targets) || targets.length === 0) {
    return res.status(400).json({ error: 'targets must be a non-empty array of URLs' });
  }

  const cleanedTargets = targets
    .map((target) => (typeof target === 'string' ? target.trim() : ''))
    .filter(Boolean)
    .filter((target) => /^https?:\/\//i.test(target));

  if (cleanedTargets.length === 0) {
    return res.status(400).json({ error: 'No valid http/https targets provided' });
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
