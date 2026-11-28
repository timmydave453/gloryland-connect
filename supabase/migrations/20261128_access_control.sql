-- Gloryland Connect: staged access-control foundation.
begin;
create table public.gl_team (
 user_id uuid primary key references auth.users(id) on delete restrict,
 display_name text not null check (char_length(display_name) between 1 and 120),
 role text not null check (role in ('super_admin','admin','media','welfare','pastor','viewer')),
 active boolean not null default true,
 created_at timestamptz not null default now()
);
create table public.gl_activity (
 id bigint generated always as identity primary key,
 actor uuid references auth.users(id) on delete set null,
 action text not null, target uuid, created_at timestamptz not null default now()
);
alter table public.gl_team enable row level security;
alter table public.gl_activity enable row level security;
revoke all on public.gl_team,public.gl_activity from anon,authenticated;
grant select on public.gl_team,public.gl_activity to authenticated;
create function public.gl_is_super_admin() returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from public.gl_team where user_id=auth.uid() and active and role='super_admin');
$$;
revoke all on function public.gl_is_super_admin() from public;
grant execute on function public.gl_is_super_admin() to authenticated;
create policy gl_team_read on public.gl_team for select to authenticated using (user_id=auth.uid() or public.gl_is_super_admin());
create policy gl_activity_read on public.gl_activity for select to authenticated using (public.gl_is_super_admin());
create function public.gl_set_team_member(p_user uuid,p_name text,p_role text,p_active boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
 perform pg_catalog.pg_advisory_xact_lock(735102);
 if not public.gl_is_super_admin() then raise exception 'Access denied' using errcode='42501'; end if;
 if p_user is null or p_active is null or p_role is null or p_name is null then raise exception 'Missing fields'; end if;
 if not exists(select 1 from auth.users where id=p_user) then raise exception 'Account does not exist'; end if;
 insert into public.gl_team(user_id,display_name,role,active) values(p_user,p_name,p_role,p_active)
 on conflict(user_id) do update set display_name=excluded.display_name,role=excluded.role,active=excluded.active;
 if not exists(select 1 from public.gl_team where active and role='super_admin') then raise exception 'At least one active Super Admin is required'; end if;
 insert into public.gl_activity(actor,action,target) values(auth.uid(),'team_member_changed',p_user);
end;
$$;
revoke all on function public.gl_set_team_member(uuid,text,text,boolean) from public;
grant execute on function public.gl_set_team_member(uuid,text,text,boolean) to authenticated;
commit;
-- Bootstrap the initial owner only in SQL Editor AFTER creating and verifying their Auth account:
-- insert into public.gl_team(user_id,display_name,role) values ('OWNER_AUTH_UUID','Owner','super_admin');
-- Do not expose the service role key or allow anonymous account creation.
