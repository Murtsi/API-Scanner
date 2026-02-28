import { supabase } from './supabaseClient.js';

export async function createScanRun({ userId, targets, options, result }) {
  const payload = {
    owner_id: userId,
    targets,
    options,
    result,
  };

  const { data, error } = await supabase
    .from('scan_runs')
    .insert(payload)
    .select('id, created_at')
    .single();

  if (error) {
    throw new Error(error.message || 'Failed to save scan run');
  }

  return data;
}

export async function listScanRuns(limit = 20) {
  const { data, error } = await supabase
    .from('scan_runs')
    .select('id, targets, options, result, created_at')
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) {
    throw new Error(error.message || 'Failed to fetch scan history');
  }

  return data || [];
}

export async function deleteScanRun(runId) {
  const { error } = await supabase
    .from('scan_runs')
    .delete()
    .eq('id', runId);

  if (error) {
    throw new Error(error.message || 'Failed to delete scan run');
  }
}
