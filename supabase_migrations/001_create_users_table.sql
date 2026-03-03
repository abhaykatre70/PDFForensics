-- ============================================================
-- Supabase SQL Migration: create the `users` table
-- Run this once in the Supabase SQL Editor:
--   https://supabase.com/dashboard/project/kzrkrzzdntbgmpzblhmj/sql
-- ============================================================

-- Enable the pgcrypto extension for gen_random_uuid() (already enabled in
-- most Supabase projects; safe to run twice).
create extension if not exists "pgcrypto";

-- Create the users table
create table if not exists public.users (
    id         uuid        primary key default gen_random_uuid(),
    name       text        not null,
    email      text        not null unique,
    created_at timestamptz not null default now()
);

-- Optional: index on email for fast lookup
create index if not exists users_email_idx on public.users (email);

-- Row-Level Security (RLS) — mandatory for production-readiness.
-- The anon key is used server-side only; disable RLS bypass for anon.
alter table public.users enable row level security;

-- Allow the service role full access (used by backend/server-side calls).
-- The anon role is intentionally restricted; adjust policies as needed.
create policy "Service role has full access"
    on public.users
    as permissive
    for all
    to service_role
    using (true)
    with check (true);

-- If you want the anon key (public) to be able to INSERT (e.g. for sign-up):
-- Uncomment the block below. Remove it if you only insert from your backend.
/*
create policy "Anon can insert users"
    on public.users
    as permissive
    for insert
    to anon
    with check (true);

create policy "Anon can select all users"
    on public.users
    as permissive
    for select
    to anon
    using (true);
*/
