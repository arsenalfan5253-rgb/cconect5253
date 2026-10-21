-- ccconnect database setup for Supabase (Firebase-free).
-- Run this entire file once in Supabase Dashboard > SQL Editor.
-- It creates protected tables, Row Level Security policies, a DM RPC, and realtime publication entries.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  display_name text not null default '',
  is_admin boolean not null default false,
  dm_admin_only boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  type text not null check (type in ('dm', 'group')),
  name text,
  created_by uuid not null references public.profiles(id) on delete cascade,
  dm_key text unique,
  created_at timestamptz not null default now(),
  constraint group_name_required check (type = 'dm' or nullif(trim(name), '') is not null),
  constraint dm_key_only_for_dm check ((type = 'dm' and dm_key is not null) or (type = 'group' and dm_key is null))
);

create table if not exists public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  text text not null check (length(trim(text)) between 1 and 4000),
  created_at timestamptz not null default now()
);

create index if not exists conversation_members_user_id_idx on public.conversation_members(user_id);
create index if not exists messages_conversation_created_idx on public.messages(conversation_id, created_at);
create index if not exists conversations_created_by_idx on public.conversations(created_by);

-- Automatically create a profile for each account added in Supabase Authentication.
create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    lower(new.email),
    coalesce(nullif(trim(new.raw_user_meta_data ->> 'display_name'), ''), split_part(lower(new.email), '@', 1))
  )
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists ccconnect_auth_user_created on auth.users;
create trigger ccconnect_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_auth_user();

-- SECURITY DEFINER avoids recursive RLS checks when policies verify membership.
create or replace function public.is_conversation_member(_conversation_id uuid, _user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = _conversation_id and cm.user_id = _user_id
  );
$$;
revoke all on function public.is_conversation_member(uuid, uuid) from public, anon;
grant execute on function public.is_conversation_member(uuid, uuid) to authenticated;

-- Security-definer helper lets the creator add members before the first member
-- row exists, without weakening the conversation-membership RLS policy.
create or replace function public.can_add_group_member(_conversation_id uuid, _member_id uuid, _actor_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.conversations c
    join public.profiles actor on actor.id = _actor_id
    join public.profiles target on target.id = _member_id
    where c.id = _conversation_id
      and c.type = 'group'
      and c.created_by = _actor_id
      and actor.is_admin
      and not target.dm_admin_only
  );
$$;
revoke all on function public.can_add_group_member(uuid, uuid, uuid) from public, anon;
grant execute on function public.can_add_group_member(uuid, uuid, uuid) to authenticated;

-- Create/find a DM on the server. The caller must be one of the two participants.
-- dm_admin_only accounts can DM only the admin; only the admin can start a DM with them.
create or replace function public.get_or_create_dm(other_user_id uuid)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  caller_id uuid := auth.uid();
  new_conversation_id uuid;
  dm_pair_key text;
  caller_admin boolean;
  caller_restricted boolean;
  other_admin boolean;
  other_restricted boolean;
begin
  if caller_id is null then
    raise exception 'You must be signed in.';
  end if;
  if other_user_id is null or other_user_id = caller_id then
    raise exception 'Choose another user.';
  end if;

  select is_admin, dm_admin_only into caller_admin, caller_restricted
  from public.profiles where id = caller_id;
  select is_admin, dm_admin_only into other_admin, other_restricted
  from public.profiles where id = other_user_id;

  if caller_admin is null or other_admin is null then
    raise exception 'User not found.';
  end if;
  if (caller_restricted and not other_admin) or (other_restricted and not caller_admin) then
    raise exception 'This direct message is not available for this account.';
  end if;

  dm_pair_key := least(caller_id::text, other_user_id::text) || ':' || greatest(caller_id::text, other_user_id::text);

  insert into public.conversations (type, created_by, dm_key)
  values ('dm', caller_id, dm_pair_key)
  on conflict (dm_key) do update set dm_key = excluded.dm_key
  returning id into new_conversation_id;

  insert into public.conversation_members (conversation_id, user_id)
  values (new_conversation_id, caller_id), (new_conversation_id, other_user_id)
  on conflict (conversation_id, user_id) do nothing;

  return new_conversation_id;
end;
$$;
revoke all on function public.get_or_create_dm(uuid) from public, anon;
grant execute on function public.get_or_create_dm(uuid) to authenticated;

-- Enable Row Level Security on every exposed table.
alter table public.profiles enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;

-- Remove/recreate named policies so re-running the setup file doesn't fail.
drop policy if exists profiles_read_signed_in on public.profiles;
create policy profiles_read_signed_in on public.profiles
for select to authenticated using (auth.uid() is not null);

drop policy if exists profiles_update_own_display_name on public.profiles;
create policy profiles_update_own_display_name on public.profiles
for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

-- A conversation is visible only to its members.
drop policy if exists conversations_read_member on public.conversations;
create policy conversations_read_member on public.conversations
for select to authenticated using (public.is_conversation_member(id, auth.uid()));

-- Only a profile marked is_admin can create group conversations.
drop policy if exists conversations_admin_create_group on public.conversations;
create policy conversations_admin_create_group on public.conversations
for insert to authenticated with check (
  type = 'group'
  and created_by = auth.uid()
  and exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin)
);

-- Membership lists are visible only to people who belong to the same conversation.
drop policy if exists members_read_same_conversation on public.conversation_members;
create policy members_read_same_conversation on public.conversation_members
for select to authenticated using (public.is_conversation_member(conversation_id, auth.uid()));

-- Group membership is managed only by the admin who created that group.
drop policy if exists members_admin_add_to_owned_group on public.conversation_members;
create policy members_admin_add_to_owned_group on public.conversation_members
for insert to authenticated with check (
  public.can_add_group_member(conversation_id, user_id, auth.uid())
);

-- Messages can only be read and sent by conversation members; the sender id must be the signed-in user.
drop policy if exists messages_read_member on public.messages;
create policy messages_read_member on public.messages
for select to authenticated using (public.is_conversation_member(conversation_id, auth.uid()));

drop policy if exists messages_insert_member on public.messages;
create policy messages_insert_member on public.messages
for insert to authenticated with check (
  sender_id = auth.uid() and public.is_conversation_member(conversation_id, auth.uid())
);

-- Table grants are required in addition to RLS. Profiles allow only display_name changes from the browser.
revoke all on public.profiles from anon, authenticated;
revoke all on public.conversations from anon, authenticated;
revoke all on public.conversation_members from anon, authenticated;
revoke all on public.messages from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (display_name) on public.profiles to authenticated;
grant select, insert on public.conversations to authenticated;
grant select, insert on public.conversation_members to authenticated;
grant select, insert on public.messages to authenticated;

-- Realtime must be enabled for these tables so live message and sidebar updates reach other browsers.
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages') then
    execute 'alter publication supabase_realtime add table public.messages';
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'conversations') then
    execute 'alter publication supabase_realtime add table public.conversations';
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'conversation_members') then
    execute 'alter publication supabase_realtime add table public.conversation_members';
  end if;
end;
$$;

-- After creating the user accounts in Authentication, use Table Editor > profiles to:
--   1. Set is_admin = true for the account allowed to create groups (normally your account).
--   2. Set dm_admin_only = true for any accounts that should only be able to DM the admin.
--   3. Replace the email-derived display_name values with the intended display names.
-- Do NOT enable public sign-ups for this invite-only app.
