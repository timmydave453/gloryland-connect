create table public.gl_enrollment (
 email text primary key check (email=lower(email) and char_length(email)<=254),
 username text unique not null check (username ~ '^[a-z0-9_]{3,32}$'),
 display_name text not null check (char_length(display_name) between 1 and 120),
 role text not null check (role in ('super_admin','admin','media','welfare','pastor','viewer')),
 user_id uuid unique references auth.users(id) on delete restrict,
 activation_hash text unique check (activation_hash is null or activation_hash ~ '^[a-f0-9]{64}$'),
 expires_at timestamptz,
 activated_at timestamptz,
 created_at timestamptz not null default now()
);
alter table public.gl_enrollment enable row level security;
revoke all on public.gl_enrollment from public,anon,authenticated;
grant select,insert,update,delete on public.gl_enrollment to service_role;
