# Gloryland Connect authentication handover

## Current release
Production remains on the existing Google Sheets/Apps Script administration workflow. The access-control preview is on `v3.5-access-control`. Do not merge it into production until the acceptance tests below pass.

## Components
- `admin.html`: administrator login and role-dependent navigation.
- `api/admin.js`: validates the Supabase user and current active, credential-ready team membership before sending authorized requests to Apps Script.
- `supabase/migrations/`: database schema, team policies, enrollment schema and staging lock.
- `supabase/functions/gl-approval/index.ts`: unfinished enrollment service source; not approved for production use.
- Supabase project: gloryland-connect (odbyijwovivsqdbsgyfd).
- Vercel environment variable names: GAS_ENDPOINT, GAS_SHARED_SECRET. Existing production shared-password login also needs ADMIN_PASSWORD. Never put their values into Git.

## Account model
Super Admin approves identities and roles. Activation must bind a high-entropy, expiring, single-use credential to an approved identity. Do not treat knowledge of an email address as ownership. A new account must remain credential-not-ready until successful password setup. The last active, credential-ready Super Admin must never be removed.

## Staging status
Enrollment table access is intentionally revoked from service_role, anon and authenticated while activation is unfinished. Do not lift the staging lock until the activation implementation has been reviewed and verified. Existing authenticated accounts retain their current roles. No passwords are stored in the enrollment table.

## Required acceptance tests before release
1. Confirm unknown, inactive and not-ready accounts cannot access protected endpoints.
2. Confirm ordinary Admin cannot manage team permissions or communications settings.
3. Confirm only the Super Admin can approve a verified identity and issue activation credentials.
4. Confirm expired, incorrect and reused activation credentials fail; concurrent claims cannot both succeed.
5. Confirm failed activation remains fail-closed and can be safely recovered by an authorized owner.
6. Confirm email and username password login work, and passwords and activation credentials never appear in logs.
7. Confirm role changes and suspension are enforced on subsequent requests and cannot remove the last ready Super Admin.
8. Verify guest registration, dashboard data, and follow-ups are unchanged.
9. Confirm source, migrations, environment-variable names and owner-controlled deployment access are available independent of ChatGPT.

## Ownership
Maintain GitHub, Supabase, Vercel and Google Apps Script access from owner-controlled accounts. Store recovery information and secrets in a private password manager. A second authorized maintainer can use ordinary Git and the platform dashboards without this chat.
