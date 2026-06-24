-- Let the admin web app edit the app's "Info / About" section live.
--
-- Background: info_content already has an ANON read policy (the iOS app reads it
-- with the publishable key), but no policy let a logged-in admin READ it while
-- authenticated, and none let anyone WRITE it. These three policies fix that:
--   1. authenticated users can SELECT  (so the admin page can load + confirm saves)
--   2. admins can UPDATE                (edit the existing row)
--   3. admins can INSERT                (create the first row if the table is empty)
-- Admin-only, mirroring the events policy style (public.user_roles + auth.uid()).
--
-- Run once in the Supabase Dashboard -> SQL Editor (project tswffszxrhzonaetwldv):
-- click into the editor, select all (Cmd/Ctrl+A), then Run. Safe to re-run.

alter table public.info_content enable row level security;

drop policy if exists "Authenticated can read info" on public.info_content;
create policy "Authenticated can read info" on public.info_content
for select to authenticated
using (true);

drop policy if exists "Admins can update info" on public.info_content;
create policy "Admins can update info" on public.info_content
for update to authenticated
using      (exists (select 1 from public.user_roles ur where ur.user_id = auth.uid() and ur.role = 'admin'))
with check (exists (select 1 from public.user_roles ur where ur.user_id = auth.uid() and ur.role = 'admin'));

drop policy if exists "Admins can insert info" on public.info_content;
create policy "Admins can insert info" on public.info_content
for insert to authenticated
with check (exists (select 1 from public.user_roles ur where ur.user_id = auth.uid() and ur.role = 'admin'));
