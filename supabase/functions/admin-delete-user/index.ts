// admin-delete-user
//
// Lets an authenticated ADMIN delete another login account (and its role row).
// The privileged service-role key never leaves the server — it's read from the
// function's environment, which Supabase populates automatically. An admin can
// NOT delete their own account.
//
// Request (POST, JSON):  { "user_id": "..." }
// Auth:                  Authorization: Bearer <caller's Supabase access token>
// Response:              { ok: true }  or  { error: "..." }

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
  const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
  const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  // 1. Identify the caller from their bearer token.
  const authHeader = req.headers.get("Authorization") ?? "";
  const caller = createClient(SUPABASE_URL, ANON_KEY, {
    global: { headers: { Authorization: authHeader } },
  });
  const {
    data: { user },
    error: userErr,
  } = await caller.auth.getUser();
  if (userErr || !user) return json({ error: "Not signed in." }, 401);

  // 2. Confirm the caller is an admin.
  const { data: roleRow } = await caller
    .from("user_roles")
    .select("role")
    .eq("user_id", user.id)
    .maybeSingle();
  if (!roleRow || roleRow.role !== "admin") {
    return json({ error: "Admins only." }, 403);
  }

  // 3. Validate input.
  let payload: { user_id?: string };
  try {
    payload = await req.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }
  const userId = (payload.user_id ?? "").trim();
  if (!userId) return json({ error: "user_id is required." }, 400);
  if (userId === user.id) {
    return json({ error: "You can't delete your own account." }, 400);
  }

  // 4. Delete the role row + the auth user with the service-role key.
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  await admin.from("user_roles").delete().eq("user_id", userId);
  const { error: delErr } = await admin.auth.admin.deleteUser(userId);
  if (delErr) return json({ error: delErr.message }, 400);

  return json({ ok: true });
});
