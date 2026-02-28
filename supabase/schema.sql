-- Run in Supabase SQL Editor
-- Basic auth user access is handled by Supabase Auth itself.
-- This table stores per-user scan history.
-- Cleanup additions in this script:
--   1) JSON shape constraints
--   2) Query index for history lists
--   3) Auto-prune to keep latest 100 scans per user

create table if not exists public.scan_runs (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  targets jsonb not null,
  options jsonb not null,
  result jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_scan_runs_owner_created_at
on public.scan_runs (owner_id, created_at desc);

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'scan_runs_targets_is_array'
  ) then
    alter table public.scan_runs
      add constraint scan_runs_targets_is_array
      check (jsonb_typeof(targets) = 'array');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'scan_runs_options_is_object'
  ) then
    alter table public.scan_runs
      add constraint scan_runs_options_is_object
      check (jsonb_typeof(options) = 'object');
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'scan_runs_result_is_object'
  ) then
    alter table public.scan_runs
      add constraint scan_runs_result_is_object
      check (jsonb_typeof(result) = 'object');
  end if;
end $$;

create or replace function public.prune_scan_runs_after_insert()
returns trigger
language plpgsql
as $$
begin
  delete from public.scan_runs
  where id in (
    select id
    from public.scan_runs
    where owner_id = new.owner_id
    order by created_at desc
    offset 100
  );

  return new;
end;
$$;

drop trigger if exists trg_prune_scan_runs_after_insert on public.scan_runs;
create trigger trg_prune_scan_runs_after_insert
after insert on public.scan_runs
for each row
execute function public.prune_scan_runs_after_insert();

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
