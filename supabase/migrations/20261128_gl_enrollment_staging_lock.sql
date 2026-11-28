-- Keep enrollment disabled until activation checks and the UI are validated.
revoke all on public.gl_enrollment from service_role;
alter table public.gl_team alter column credential_ready set default false;
