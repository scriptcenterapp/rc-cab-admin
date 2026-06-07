// admin-create-user
//
// Lets an authenticated ADMIN create another login account (editor or admin).
// The privileged service-role key never leaves the server — it's read from the
// function's environment, which Supabase populates automatically.
//
// Request (POST, JSON):  { "email": "...", "password": "...", "role": "editor" | "admin" }
// Auth:                  Authorization: Bearer <caller's Supabase access token>
// Response:              { ok: true, user: { id, email, role } }  or  { error: "..." }

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

  // 2. Confirm the caller is an admin (reads their own user_roles row under RLS).
  const { data: roleRow } = await caller
    .from("user_roles")
    .select("role")
    .eq("user_id", user.id)
    .maybeSingle();
  if (!roleRow || roleRow.role !== "admin") {
    return json({ error: "Admins only." }, 403);
  }

  // 3. Validate input.
  let payload: { email?: string; password?: string; role?: string };
  try {
    payload = await req.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }
  const email = (payload.email ?? "").trim().toLowerCase();
  const password = payload.password ?? "";
  const role = payload.role === "admin" ? "admin" : "editor";
  if (!email || !password) {
    return json({ error: "Email and password are required." }, 400);
  }
  if (password.length < 6) {
    return json({ error: "Password must be at least 6 characters." }, 400);
  }

  // 4. Create the account with the service-role key, then assign the role.
  const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: created, error: createErr } = await admin.auth.admin.createUser(
    { email, password, email_confirm: true },
  );
  if (createErr || !created?.user) {
    return json({ error: createErr?.message ?? "Could not create user." }, 400);
  }

  const { error: roleErr } = await admin
    .from("user_roles")
    .upsert({ user_id: created.user.id, role });
  if (roleErr) {
    // Roll back the auth user so we don't leave a roleless account behind.
    await admin.auth.admin.deleteUser(created.user.id);
    return json({ error: roleErr.message }, 400);
  }

  return json({
    ok: true,
    user: { id: created.user.id, email: created.user.email, role },
  });
});
