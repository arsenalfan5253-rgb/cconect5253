-- CCConnect Supabase setup and privacy hardening
-- Project: bclhrmwrkwrvzgufrmdy
-- Run in Supabase Dashboard > SQL Editor AFTER inviting/creating all 7 approved Auth users.
-- Safe to re-run. Does not delete existing messages or conversations.
-- Keep schema "ccconnect_private" OUT of the Data API's exposed schemas.

begin;

create schema if not exists ccconnect_private;
revoke all on schema ccconnect_private from public, anon;
grant usage on schema ccconnect_private to authenticated;

-- 1. Synchronize the approved Auth users into profiles.
-- Users must exist in Authentication > Users first; this query cannot invite/create Auth users.
insert into public.profiles (id, email, display_name, is_admin, dm_admin_only)
select
  u.id,
  lower(u.email),
  case lower(u.email)
    when 'musti2152@gmail.com' then 'Mustafa'
    when 'mchiba@gmail.com' then 'Abba'
    when 'sschiba786@gmail.com' then 'Mom'
    when 'abdulqadir@gmail.com' then 'Abdulqadir'
    when 'ajaby786@gmail.com' then 'Ajab'
    when 'zahrahalai296@gmail.com' then 'Zahra'
    when 'arsenalfan5253@gmail.com' then 'ArsenalFan'
  end,
  lower(u.email) = 'musti2152@gmail.com',
  lower(u.email) in ('zahrahalai296@gmail.com', 'arsenalfan5253@gmail.com')
from auth.users u
where lower(u.email) = any (array[
  'musti2152@gmail.com',
  'mchiba@gmail.com',
  'sschiba786@gmail.com',
  'abdulqadir@gmail.com',
  'ajaby786@gmail.com',
  'zahrahalai296@gmail.com',
  'arsenalfan5253@gmail.com'
]::text[])
on conflict (id) do update set
  email = excluded.email,
  display_name = excluded.display_name,
  is_admin = excluded.is_admin,
  dm_admin_only = excluded.dm_admin_only;

-- 2. Internal authorization helpers. This schema should not be exposed by the Data API.
create or replace function ccconnect_private.user_is_whitelisted(_user_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $function$
  select exists (
    select 1 from public.profiles p
    where p.id = _user_id
      and lower(p.email) = any (array[
        'musti2152@gmail.com',
        'mchiba@gmail.com',
        'sschiba786@gmail.com',
        'abdulqadir@gmail.com',
        'ajaby786@gmail.com',
        'zahrahalai296@gmail.com',
        'arsenalfan5253@gmail.com'
      ]::text[])
  );
$function$;

create or replace function ccconnect_private.user_is_admin(_user_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $function$
  select coalesce((select p.is_admin from public.profiles p where p.id = _user_id), false);
$function$;

create or replace function ccconnect_private.user_is_restricted(_user_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $function$
  select coalesce((select p.dm_admin_only from public.profiles p where p.id = _user_id), false);
$function$;

create or replace function ccconnect_private.is_conversation_member(_conversation_id uuid, _user_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $function$
  select coalesce((
    select
      case
        when _user_id is distinct from (select auth.uid()) then false
        when not ccconnect_private.user_is_whitelisted(_user_id) then false
        when c.type = 'group' then
          not coalesce(me.dm_admin_only, false)
          and not exists (
            select 1
            from public.conversation_members cmx
            join public.profiles px on px.id = cmx.user_id
            where cmx.conversation_id = c.id
              and coalesce(px.dm_admin_only, false)
          )
        when c.type = 'dm' then
          case
            when coalesce(me.is_admin, false) then true
            when coalesce(me.dm_admin_only, false) then
              (select count(*)
               from public.conversation_members cmn
               where cmn.conversation_id = c.id) = 2
              and exists (
                select 1
                from public.conversation_members cma
                join public.profiles pa on pa.id = cma.user_id
                where cma.conversation_id = c.id
                  and cma.user_id <> _user_id
                  and coalesce(pa.is_admin, false)
              )
            else
              not exists (
                select 1
                from public.conversation_members cmx
                join public.profiles px on px.id = cmx.user_id
                where cmx.conversation_id = c.id
                  and coalesce(px.dm_admin_only, false)
              )
          end
        else false
      end
    from public.conversations c
    join public.conversation_members cm
      on cm.conversation_id = c.id and cm.user_id = _user_id
    join public.profiles me on me.id = _user_id
    where c.id = _conversation_id
  ), false);
$function$;

create or replace function ccconnect_private.can_add_group_member(
  _conversation_id uuid, _member_id uuid, _actor_id uuid
)
returns boolean
language sql stable security definer
set search_path = ''
as $function$
  select exists (
    select 1
    from public.conversations c
    join public.profiles actor on actor.id = _actor_id
    join public.profiles target on target.id = _member_id
    where c.id = _conversation_id
      and c.type = 'group'
      and c.created_by = _actor_id
      and _actor_id = (select auth.uid())
      and coalesce(actor.is_admin, false)
      and not coalesce(target.dm_admin_only, false)
      and ccconnect_private.user_is_whitelisted(_member_id)
  );
$function$;

create or replace function ccconnect_private.get_or_create_dm(_other_user_id uuid)
returns uuid
language plpgsql security definer
set search_path = ''
as $function$
declare
  caller_id uuid := auth.uid();
  caller_email text;
  other_email text;
  caller_admin boolean;
  caller_restricted boolean;
  other_admin boolean;
  other_restricted boolean;
  pair_key text;
  conversation_id uuid;
begin
  if caller_id is null then
    raise exception 'You must be signed in.';
  end if;
  if _other_user_id is null or _other_user_id = caller_id then
    raise exception 'Choose another user.';
  end if;

  select lower(p.email), coalesce(p.is_admin, false), coalesce(p.dm_admin_only, false)
    into caller_email, caller_admin, caller_restricted
    from public.profiles p where p.id = caller_id;
  select lower(p.email), coalesce(p.is_admin, false), coalesce(p.dm_admin_only, false)
    into other_email, other_admin, other_restricted
    from public.profiles p where p.id = _other_user_id;

  if caller_email is null or other_email is null
     or not ccconnect_private.user_is_whitelisted(caller_id)
     or not ccconnect_private.user_is_whitelisted(_other_user_id) then
    raise exception 'This user is not on the CCConnect family access list.';
  end if;

  if (caller_restricted and not other_admin)
     or (other_restricted and not caller_admin) then
    raise exception 'This direct message is not available for this account.';
  end if;

  pair_key := least(caller_id::text, _other_user_id::text)
              || ':' ||
              greatest(caller_id::text, _other_user_id::text);

  insert into public.conversations(type, created_by, dm_key)
  values ('dm', caller_id, pair_key)
  on conflict (dm_key) do update set dm_key = excluded.dm_key
  returning id into conversation_id;

  insert into public.conversation_members(conversation_id, user_id)
  values (conversation_id, caller_id), (conversation_id, _other_user_id)
  on conflict do nothing;

  return conversation_id;
end;
$function$;

-- Calls made through PostgREST must go through this invoker wrapper; the privileged
-- implementation is in the non-exposed schema and validates auth.uid() itself.
create or replace function public.get_or_create_dm(other_user_id uuid)
returns uuid
language sql
security invoker
set search_path = ''
as $function$
  select ccconnect_private.get_or_create_dm(other_user_id);
$function$;

revoke all on function ccconnect_private.user_is_whitelisted(uuid) from public, anon;
revoke all on function ccconnect_private.user_is_admin(uuid) from public, anon;
revoke all on function ccconnect_private.user_is_restricted(uuid) from public, anon;
revoke all on function ccconnect_private.is_conversation_member(uuid, uuid) from public, anon;
revoke all on function ccconnect_private.can_add_group_member(uuid, uuid, uuid) from public, anon;
revoke all on function ccconnect_private.get_or_create_dm(uuid) from public, anon;
grant execute on function ccconnect_private.user_is_whitelisted(uuid) to authenticated;
grant execute on function ccconnect_private.user_is_admin(uuid) to authenticated;
grant execute on function ccconnect_private.user_is_restricted(uuid) to authenticated;
grant execute on function ccconnect_private.is_conversation_member(uuid, uuid) to authenticated;
grant execute on function ccconnect_private.can_add_group_member(uuid, uuid, uuid) to authenticated;
grant execute on function ccconnect_private.get_or_create_dm(uuid) to authenticated;

revoke all on function public.get_or_create_dm(uuid) from public, anon;
grant execute on function public.get_or_create_dm(uuid) to authenticated;

-- 3. Ensure client roles have only the table operations the app needs. RLS below
-- still determines which rows each signed-in person may read or change.
grant select on public.profiles, public.conversations, public.conversation_members,
  public.messages, public.contact_nicknames to authenticated;
grant insert on public.conversations, public.conversation_members, public.messages to authenticated;
grant insert, update, delete on public.contact_nicknames to authenticated;

alter table public.profiles enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;
alter table public.contact_nicknames enable row level security;

-- Profile rows: restricted users see only themselves and the administrator;
-- regular family members never see restricted profiles; the admin sees the whitelist.
drop policy if exists profiles_read_signed_in on public.profiles;
drop policy if exists profiles_update_own_display_name on public.profiles;
drop policy if exists profiles_read_allowed_family on public.profiles;
drop policy if exists profiles_update_own_display_name on public.profiles;

create policy profiles_read_allowed_family
on public.profiles for select to authenticated
using (
  id = (select auth.uid())
  or (
    ccconnect_private.user_is_admin((select auth.uid()))
    and ccconnect_private.user_is_whitelisted(id)
  )
  or ccconnect_private.user_is_admin(id)
  or (
    ccconnect_private.user_is_whitelisted(id)
    and not ccconnect_private.user_is_restricted((select auth.uid()))
    and not ccconnect_private.user_is_restricted(id)
  )
);

create policy profiles_update_own_display_name
on public.profiles for update to authenticated
using (id = (select auth.uid()))
with check (id = (select auth.uid()));

-- Prevent a normal signed-in user from promoting themselves to admin or changing
-- the restriction flag; only display_name remains client-updatable.
revoke update on public.profiles from anon, authenticated;
grant update (display_name) on public.profiles to authenticated;

-- Membership decisions enforce privacy even if a user guesses a conversation UUID.
drop policy if exists members_admin_add_to_owned_group on public.conversation_members;
drop policy if exists members_read_same_conversation on public.conversation_members;
drop policy if exists conversations_read_member on public.conversations;
drop policy if exists messages_insert_member on public.messages;
drop policy if exists messages_read_member on public.messages;

create policy members_admin_add_to_owned_group
on public.conversation_members for insert to authenticated
with check (
  ccconnect_private.can_add_group_member(conversation_id, user_id, (select auth.uid()))
);

create policy members_read_same_conversation
on public.conversation_members for select to authenticated
using (ccconnect_private.is_conversation_member(conversation_id, (select auth.uid())));

-- Admin can read its own newly-created group before its membership rows are inserted;
-- all subsequent group and DM access is membership-checked by the helper function.
create policy conversations_read_member
on public.conversations for select to authenticated
using (
  ccconnect_private.is_conversation_member(id, (select auth.uid()))
  or (
    type = 'group'
    and created_by = (select auth.uid())
    and ccconnect_private.user_is_admin((select auth.uid()))
  )
);

create policy messages_insert_member
on public.messages for insert to authenticated
with check (
  sender_id = (select auth.uid())
  and ccconnect_private.is_conversation_member(conversation_id, (select auth.uid()))
);

create policy messages_read_member
on public.messages for select to authenticated
using (ccconnect_private.is_conversation_member(conversation_id, (select auth.uid())));

-- Media bucket is private. Apply the same conversation access check when uploading
-- or creating signed URLs, so the old restricted-to-restricted DM cannot leak media.
drop policy if exists ccconnect_media_read_members on storage.objects;
drop policy if exists ccconnect_media_upload_members on storage.objects;

create policy ccconnect_media_read_members
on storage.objects for select to authenticated
using (
  bucket_id = 'ccconnect-media'
  and ccconnect_private.is_conversation_member(
    ((storage.foldername(name))[1])::uuid,
    (select auth.uid())
  )
);

create policy ccconnect_media_upload_members
on storage.objects for insert to authenticated
with check (
  bucket_id = 'ccconnect-media'
  and ((storage.foldername(name))[2]) = ((select auth.uid())::text)
  and ccconnect_private.is_conversation_member(
    ((storage.foldername(name))[1])::uuid,
    (select auth.uid())
  )
);

-- Public implementations are no longer needed; all policies now use the internal
-- equivalents. The public DM RPC name remains as an invoker wrapper above.
drop function if exists public.can_add_group_member(uuid, uuid, uuid);
drop function if exists public.is_conversation_member(uuid, uuid);

commit;

-- After this runs, verify profiles:
-- select email, display_name, is_admin, dm_admin_only from public.profiles order by email;
