-- Keep Muscle cloud save
-- Run this once in Supabase: SQL Editor → New query → paste → Run

create table if not exists public.km_state (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.km_state enable row level security;

drop policy if exists "km_state_select_own" on public.km_state;
drop policy if exists "km_state_insert_own" on public.km_state;
drop policy if exists "km_state_update_own" on public.km_state;

create policy "km_state_select_own"
  on public.km_state for select
  using (auth.uid() = user_id);

create policy "km_state_insert_own"
  on public.km_state for insert
  with check (auth.uid() = user_id);

create policy "km_state_update_own"
  on public.km_state for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
