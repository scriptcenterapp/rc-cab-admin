-- Allow editors (and admins) to UPDATE events.
-- Editors still CANNOT delete: no delete policy is granted to them, so the
-- existing admin-only delete rules remain the only way to remove an event.
--
-- Run this once in the Supabase Dashboard -> SQL Editor (project tswffszxrhzonaetwldv):
-- click into the editor, select all (Cmd/Ctrl+A), then Run.
-- Safe to re-run: it drops the policy first if it already exists.
--
-- Note: an UPDATE policy with no WITH CHECK clause reuses the USING expression
-- as the check, so this single condition covers both existing and new rows.

drop policy if exists "Editors can update events" on public.events;

create policy "Editors can update events" on public.events
for update to authenticated
using (exists (select 1 from public.user_roles ur where ur.user_id = auth.uid() and ur.role in ('editor','admin')));
