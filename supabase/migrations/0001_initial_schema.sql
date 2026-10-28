-- Run in a dedicated PhishGuard Supabase project.
create extension if not exists pgcrypto;

do $$ begin create type public.app_role as enum ('user','admin');
exception when duplicate_object then null; end $$;
do $$ begin create type public.scan_input_type as enum ('url','email','message');
exception when duplicate_object then null; end $$;
do $$ begin create type public.risk_level as enum ('low','medium','high');
exception when duplicate_object then null; end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role public.app_role not null default 'user',
  created_at timestamptz not null default now()
);
create table if not exists public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  input_type public.scan_input_type not null,
  input_fingerprint text,
  input_excerpt text,
  risk_score smallint not null check (risk_score between 0 and 100),
  risk_level public.risk_level not null,
  ml_probability real check (ml_probability between 0 and 1),
  model_version text,
  created_at timestamptz not null default now()
);
create table if not exists public.scan_indicators (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans(id) on delete cascade,
  code text not null,
  category text not null,
  severity text not null check (severity in ('info','low','medium','high')),
  weight smallint not null default 0,
  evidence text not null,
  explanation text not null,
  source text not null check (source in ('rule','ml'))
);
create table if not exists public.legitimate_domains (
  id uuid primary key default gen_random_uuid(),
  domain text not null unique,
  organization text not null,
  category text not null,
  status text not null default 'active' check (status in ('active','inactive')),
  created_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);
create table if not exists public.blocked_domains (
  id uuid primary key default gen_random_uuid(),
  domain text not null unique,
  reason text not null,
  source text not null default 'admin',
  status text not null default 'active' check (status in ('active','inactive')),
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);
create table if not exists public.quiz_questions (
  id uuid primary key default gen_random_uuid(),
  language text not null check (language in ('bn','en','both')),
  scenario_type text not null,
  message_text text not null,
  is_phishing boolean not null,
  explanation text not null,
  indicators jsonb not null default '[]'::jsonb,
  active boolean not null default true
);
create table if not exists public.quiz_attempts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  score int not null check (score >= 0),
  total_questions int not null check (total_questions > 0),
  completed_at timestamptz not null default now()
);
create table if not exists public.quiz_answers (
  id uuid primary key default gen_random_uuid(),
  attempt_id uuid not null references public.quiz_attempts(id) on delete cascade,
  question_id uuid not null references public.quiz_questions(id),
  selected_answer boolean not null,
  is_correct boolean not null,
  answered_at timestamptz not null default now()
);
create table if not exists public.model_evaluations (
  id uuid primary key default gen_random_uuid(),
  model_version text not null,
  dataset_name text not null,
  split_method text not null,
  accuracy real not null check (accuracy between 0 and 1),
  precision real not null check (precision between 0 and 1),
  recall real not null check (recall between 0 and 1),
  f1 real not null check (f1 between 0 and 1),
  evaluated_at timestamptz not null default now(),
  notes text
);

create index if not exists scans_user_created_idx on public.scans(user_id, created_at desc);
create index if not exists scan_indicators_code_idx on public.scan_indicators(code);
create index if not exists quiz_attempts_user_idx on public.quiz_attempts(user_id, completed_at desc);

alter table public.profiles enable row level security;
alter table public.scans enable row level security;
alter table public.scan_indicators enable row level security;
alter table public.legitimate_domains enable row level security;
alter table public.blocked_domains enable row level security;
alter table public.quiz_questions enable row level security;
alter table public.quiz_attempts enable row level security;
alter table public.quiz_answers enable row level security;
alter table public.model_evaluations enable row level security;

drop policy if exists profiles_select_own on public.profiles;
create policy profiles_select_own on public.profiles for select to authenticated using (id = auth.uid());

drop policy if exists scans_select_own on public.scans;
create policy scans_select_own on public.scans for select to authenticated using (user_id = auth.uid());

drop policy if exists scan_indicators_select_owner on public.scan_indicators;
create policy scan_indicators_select_owner on public.scan_indicators for select to authenticated using (
  exists (select 1 from public.scans s where s.id = scan_id and s.user_id = auth.uid())
);

-- Intentionally no direct client SELECT policy for quiz_questions: the table contains
-- answer keys. Later, serve quiz prompts through an API/view that omits is_phishing
-- and reveal feedback only after the user submits an answer.

drop policy if exists quiz_attempts_select_own on public.quiz_attempts;
create policy quiz_attempts_select_own on public.quiz_attempts for select to authenticated using (user_id = auth.uid());

drop policy if exists quiz_answers_select_own on public.quiz_answers;
create policy quiz_answers_select_own on public.quiz_answers for select to authenticated using (
  exists (select 1 from public.quiz_attempts a where a.id = attempt_id and a.user_id = auth.uid())
);

-- No client policies for domain lists or model_evaluations. Admin/server-only.
-- Do not let users update profiles.role. Add column-level grants and admin authorization
-- before enabling profile edits or writing admin data.
