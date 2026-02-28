const jobs = new Map();

function nowIso() {
  return new Date().toISOString();
}

export function createJob({ targets, options }) {
  const id = crypto.randomUUID();
  const createdAt = nowIso();

  const job = {
    id,
    status: 'queued',
    targets,
    options,
    createdAt,
    updatedAt: createdAt,
    startedAt: null,
    completedAt: null,
    progress: {
      totalTargets: targets.length,
      completedTargets: 0,
      currentTarget: null,
    },
    log: [],
    result: null,
    error: null,
  };

  jobs.set(id, job);
  return job;
}

export function listJobs(limit = 20) {
  return [...jobs.values()]
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, limit);
}

export function getJob(id) {
  return jobs.get(id) ?? null;
}

export function updateJob(id, patch) {
  const existing = jobs.get(id);
  if (!existing) return null;

  const updated = {
    ...existing,
    ...patch,
    progress: {
      ...existing.progress,
      ...(patch.progress ?? {}),
    },
    updatedAt: nowIso(),
  };

  jobs.set(id, updated);
  return updated;
}

export function appendJobLog(id, message, type = 'info') {
  const existing = jobs.get(id);
  if (!existing) return null;

  const updated = {
    ...existing,
    log: [
      ...existing.log,
      {
        id: `${Date.now()}-${Math.random()}`,
        ts: nowIso(),
        type,
        message,
      },
    ],
    updatedAt: nowIso(),
  };

  jobs.set(id, updated);
  return updated;
}
