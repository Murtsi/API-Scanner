-- Run in Supabase SQL Editor
-- Basic auth user access is handled by Supabase Auth itself.
-- This table is optional for future scan history persistence.

create table if not exists public.scan_runs (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  targets jsonb not null,
  options jsonb not null,
  result jsonb not null,
  created_at timestamptz not null default now()
);

alter table public.scan_runs enable row level security;

drop policy if exists "scan_runs_select_own" on public.scan_runs;
create policy "scan_runs_select_own"
on public.scan_runs
for select
using (auth.uid() = owner_id);

drop policy if exists "scan_runs_insert_own" on public.scan_runs;
create policy "scan_runs_insert_own"
on public.scan_runs
for insert
with check (auth.uid() = owner_id);

drop policy if exists "scan_runs_delete_own" on public.scan_runs;
create policy "scan_runs_delete_own"
on public.scan_runs
for delete
using (auth.uid() = owner_id);
