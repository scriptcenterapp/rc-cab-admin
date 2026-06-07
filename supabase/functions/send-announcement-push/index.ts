// send-announcement-push
//
// Admin-only. Signs an APNs JWT with the project's .p8 key and pushes a banner
// alert to every registered device token. Called by the admin site after an
// announcement is posted.
//
// Request (POST, JSON): { "title"?: string, "body": string }
// Secrets required: APNS_KEY (.p8 PEM), APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { APNS } from "./_apns.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });
}

const TEAM_ID = Deno.env.get("APNS_TEAM_ID") ?? APNS.teamId;
const KEY_ID = Deno.env.get("APNS_KEY_ID") ?? APNS.keyId;
const TOPIC = Deno.env.get("APNS_TOPIC") ?? APNS.topic;
const P8 = Deno.env.get("APNS_KEY") ?? APNS.key;

function b64url(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function makeAPNsJWT(): Promise<string> {
  const pem = P8.replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
  );
  const header = b64url(JSON.stringify({ alg: "ES256", kid: KEY_ID }));
  const payload = b64url(JSON.stringify({ iss: TEAM_ID, iat: Math.floor(Date.now() / 1000) }));
  const input = `${header}.${payload}`;
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(input));
  return `${input}.${b64url(new Uint8Array(sig))}`;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
  const ANON = Deno.env.get("SUPABASE_ANON_KEY")!;
  const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  // 1. Caller must be an admin.
  const caller = createClient(SUPABASE_URL, ANON, {
    global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
  });
  const { data: { user } } = await caller.auth.getUser();
  if (!user) return json({ error: "Not signed in." }, 401);
  const { data: roleRow } = await caller.from("user_roles").select("role").eq("user_id", user.id).maybeSingle();
  if (roleRow?.role !== "admin") return json({ error: "Admins only." }, 403);

  // 2. Payload.
  let input: { title?: string; body?: string };
  try { input = await req.json(); } catch { return json({ error: "Invalid JSON." }, 400); }
  const body = (input.body ?? "").trim();
  if (!body) return json({ error: "body is required." }, 400);
  const title = (input.title ?? "RC CAB").trim();

  // 3. All registered tokens (service role bypasses RLS).
  const admin = createClient(SUPABASE_URL, SERVICE, { auth: { persistSession: false } });
  const { data: tokens } = await admin.from("device_tokens").select("token");
  if (!tokens || tokens.length === 0) return json({ ok: true, sent: 0, devices: 0, note: "No devices registered." });

  // 4. Sign once, push to every device (try production then sandbox).
  const jwt = await makeAPNsJWT();
  const apnsBody = JSON.stringify({ aps: { alert: { title, body }, sound: "default" } });
  const hosts = ["https://api.push.apple.com", "https://api.sandbox.push.apple.com"];

  let sent = 0;
  const errors: Record<string, number> = {};
  await Promise.all(tokens.map(async ({ token }: { token: string }) => {
    for (const host of hosts) {
      try {
        const r = await fetch(`${host}/3/device/${token}`, {
          method: "POST",
          headers: {
            authorization: `bearer ${jwt}`,
            "apns-topic": TOPIC,
            "apns-push-type": "alert",
            "apns-priority": "10",
            "content-type": "application/json",
          },
          body: apnsBody,
        });
        if (r.status === 200) { sent++; return; }
        const reason = (await r.json().catch(() => ({}))).reason ?? `http_${r.status}`;
        errors[reason] = (errors[reason] ?? 0) + 1;
      } catch (e) {
        errors[String(e).slice(0, 40)] = (errors[String(e).slice(0, 40)] ?? 0) + 1;
      }
    }
  }));

  return json({ ok: true, sent, devices: tokens.length, errors });
});
