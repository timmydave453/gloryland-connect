alter table public.gl_team add column credential_ready boolean not null default true;
create or replace function public.gl_is_super_admin() returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from public.gl_team where user_id=auth.uid() and active and credential_ready and role='super_admin');
$$;
create or replace function public.gl_set_team_member(p_user uuid,p_name text,p_role text,p_active boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
 perform pg_catalog.pg_advisory_xact_lock(735102);
 if not public.gl_is_super_admin() then raise exception 'Access denied' using errcode='42501'; end if;
 if p_user is null or p_active is null or p_role is null or p_name is null then raise exception 'Missing fields'; end if;
 if not exists(select 1 from public.gl_team where user_id=p_user) then raise exception 'Use the account approval workflow'; end if;
 update public.gl_team set display_name=p_name,role=p_role,active=p_active where user_id=p_user;
 if not exists(select 1 from public.gl_team where active and credential_ready and role='super_admin') then raise exception 'At least one active Super Admin is required'; end if;
 insert into public.gl_activity(actor,action,target) values(auth.uid(),'team_member_changed',p_user);
end;
$$;