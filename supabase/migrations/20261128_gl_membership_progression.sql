create table public.gl_membership_events (
 id bigint generated always as identity primary key,
 submission_id text not null check (char_length(submission_id) between 1 and 160),
 stage text not null check (stage in ('interested','contacted','orientation','confirmed','closed')),
 actor uuid not null default auth.uid() references auth.users(id) on delete restrict,
 created_at timestamptz not null default now()
);
create index gl_membership_events_latest on public.gl_membership_events(submission_id,id desc);
alter table public.gl_membership_events enable row level security;
revoke all on public.gl_membership_events from public,anon,authenticated;
grant select on public.gl_membership_events to authenticated;
grant insert(submission_id,stage) on public.gl_membership_events to authenticated;
grant usage on sequence public.gl_membership_events_id_seq to authenticated;
create policy gl_membership_read on public.gl_membership_events for select to authenticated using (
 exists(select 1 from public.gl_team t where t.user_id=(select auth.uid()) and t.active and t.credential_ready and t.role in ('super_admin','admin'))
);
create policy gl_membership_append on public.gl_membership_events for insert to authenticated with check (
 actor=(select auth.uid()) and exists(select 1 from public.gl_team t where t.user_id=(select auth.uid()) and t.active and t.credential_ready and (t.role='super_admin' or (t.role='admin' and stage<>'confirmed')))
);
create view public.gl_membership_current with (security_invoker=true) as
 select distinct on (submission_id) submission_id,stage,actor,created_at,id
 from public.gl_membership_events order by submission_id,id desc;
revoke all on public.gl_membership_current from public,anon,authenticated;
grant select on public.gl_membership_current to authenticated;