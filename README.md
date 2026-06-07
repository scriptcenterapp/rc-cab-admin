# RC CAB Admin

A simple web dashboard for managing the **RC CAB** iOS app's content, backed by Supabase.

## What it does
- **Events** — admins add / edit / delete events.
- **Announcements** — admins post the in-app banner alerts and turn them on/off.
- **Off-Season** — admins flip the app to the "We're on break" screen and set the message + return date.
- **Team** — admins create login accounts. **Editor** accounts can *only add events*; **admin** accounts can do everything.

## Roles & security
- The public iOS app uses Supabase's **read-only** publishable key (Row-Level Security blocks all writes).
- All writing happens here, behind a Supabase Auth **login**.
- Row-Level Security enforces the rules server-side: editors can only insert events; admins manage everything.
- New accounts are created by an admin-only **Edge Function** (`admin-create-user`) that holds the privileged
  service-role key on the server — it is never exposed in this page.
- Public sign-ups are disabled, so only admin-created accounts can log in.

## Hosting
This page is a single static `index.html`. It's published on GitHub Pages, but it can run from anywhere
(open the file locally, or host it on any static host) — it only talks to Supabase over HTTPS.

> Note: Supabase Storage / Edge Functions intentionally refuse to serve executable HTML
> (CSP `sandbox` + forced `text/plain`), so the static page is hosted on GitHub Pages while
> everything else (auth, database, the user-creation function) runs on Supabase.

## Supabase pieces
- `supabase/functions/admin-create-user` — admin-only account creation (service role).
- `supabase/functions/admin-site` — serves this page from Supabase (kept for reference; blocked by CSP, see above).
- Database: `events`, `announcements`, `app_status`, `user_roles` tables with role-based RLS.

## Config
`index.html` embeds the Supabase project URL and the **publishable** (public, safe-to-share) key only.
The service-role key and any personal access tokens are never stored here.
