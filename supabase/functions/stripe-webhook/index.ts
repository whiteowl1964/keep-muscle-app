// Supabase Edge Function: stripe-webhook
// Deploy: supabase functions deploy stripe-webhook --no-verify-jwt
// Secrets required (set in Dashboard > Edge Functions > Secrets, never in code):
//   STRIPE_WEBHOOK_SECRET  — from Stripe Dashboard > Webhooks > your endpoint > Signing secret
//   SERVICE_ROLE_KEY — from Supabase Settings > API Keys > service_role / secret

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = "https://efmpsyvxzbkmwsypzbqs.supabase.co";

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyStripe(raw: string, header: string | null, secret: string): Promise<boolean> {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(
    header.split(",").map((p) => {
      const i = p.indexOf("=");
      return [p.slice(0, i).trim(), p.slice(i + 1).trim()];
    })
  );
  const t = parts.t;
  const v1 = parts.v1;
  if (!t || !v1) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signed = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${t}.${raw}`));
  return hex(signed) === v1;
}

async function findUserByEmail(sb: ReturnType<typeof createClient>, email: string): Promise<string | null> {
  if (!email) return null;
  const { data, error } = await sb.auth.admin.listUsers({ page: 1, perPage: 200 });
  if (error || !data?.users) return null;
  const hit = data.users.find((u) => (u.email || "").toLowerCase() === email.toLowerCase());
  return hit?.id || null;
}

async function setPaid(
  sb: ReturnType<typeof createClient>,
  userId: string,
  paid: boolean,
  extra: Record<string, unknown> = {}
) {
  const { data: row } = await sb.from("km_state").select("data").eq("user_id", userId).maybeSingle();
  const current = (row && row.data && typeof row.data === "object") ? row.data : {};
  const data = { ...current, ...extra, paid };
  const payload = { user_id: userId, data, updated_at: new Date().toISOString() };
  const { error } = await sb.from("km_state").upsert(payload, { onConflict: "user_id" });
  if (error) throw new Error(error.message);
  return data;
}

async function storePendingPaid(
  sb: ReturnType<typeof createClient>,
  email: string,
  extra: Record<string, unknown> = {}
) {
  const payload = {
    email: email.toLowerCase(),
    paid: true,
    stripe_customer_id: extra.stripeCustomerId || null,
    stripe_email: email,
    created_at: new Date().toISOString(),
  };
  const { error } = await sb.from("pending_paid").upsert(payload, { onConflict: "email" });
  if (error) throw new Error(error.message);
}

serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const secret = Deno.env.get("STRIPE_WEBHOOK_SECRET");
  const serviceKey = Deno.env.get("SERVICE_ROLE_KEY");
  if (!secret) {
    console.error("Missing STRIPE_WEBHOOK_SECRET");
    return new Response("Server missing STRIPE_WEBHOOK_SECRET", { status: 500 });
  }
  if (!serviceKey) {
    console.error("Missing SERVICE_ROLE_KEY");
    return new Response("Server missing SERVICE_ROLE_KEY", { status: 500 });
  }

  const raw = await req.text();
  const sig = req.headers.get("stripe-signature");
  const ok = await verifyStripe(raw, sig, secret);
  if (!ok) {
    console.error("Invalid Stripe signature");
    return new Response("Invalid signature", { status: 400 });
  }

  let event: any;
  try {
    event = JSON.parse(raw);
  } catch {
    return new Response("Bad JSON", { status: 400 });
  }

  const sb = createClient(SUPABASE_URL, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const obj = event.data?.object || {};
  let userId: string | null = null;
  let outcome = "ignored";

  try {
    if (event.type === "checkout.session.completed") {
      const status = obj.payment_status || obj.status;
      const subStatus = obj.subscription ? "paid" : status;
      // Trialing and paid both count. Checkout completed with a subscription is enough.
      const counts = status === "paid" || status === "complete" || obj.mode === "subscription" || !!obj.subscription;
      if (counts) {
        userId = obj.client_reference_id || null;
        const email = obj.customer_details?.email || null;
        if (!userId && email) {
          userId = await findUserByEmail(sb, email);
        }
        if (userId) {
          await setPaid(sb, userId, true, {
            stripeCustomerId: obj.customer || null,
            stripeEmail: email,
          });
          outcome = "paid=true";
        } else if (email) {
          // No matching Supabase user yet — store paid status keyed by email.
          // afterLogin will pick it up the moment they create an account with that email.
          await storePendingPaid(sb, email, { stripeCustomerId: obj.customer || null });
          outcome = "pending-by-email";
        } else {
          outcome = "no-user-no-email";
        }
      } else {
        outcome = "not-paid-status";
      }
    }

    if (event.type === "charge.refunded") {
      const email = obj.billing_details?.email || obj.receipt_email || null;
      if (obj.customer) {
        const { data: rows } = await sb
          .from("km_state")
          .select("user_id")
          .eq("data->>stripeCustomerId", obj.customer)
          .limit(1);
        userId = rows?.[0]?.user_id || null;
      }
      if (!userId && email) userId = await findUserByEmail(sb, email);
      if (userId) {
        await setPaid(sb, userId, false, { stripeCustomerId: obj.customer || null });
        outcome = "paid=false-refund";
      } else {
        outcome = "refund-no-user";
      }
    }

    if (event.type === "customer.subscription.deleted") {
      if (obj.customer) {
        const { data: rows } = await sb
          .from("km_state")
          .select("user_id")
          .eq("data->>stripeCustomerId", obj.customer)
          .limit(1);
        userId = rows?.[0]?.user_id || null;
      }
      if (userId) {
        await setPaid(sb, userId, false, { stripeCustomerId: obj.customer || null });
        outcome = "paid=false-canceled";
      } else {
        outcome = "cancel-no-user";
      }
    }

    console.log(JSON.stringify({
      event_id: event.id,
      type: event.type,
      user_id: userId,
      outcome,
    }));

    return new Response(JSON.stringify({ received: true, outcome }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error(JSON.stringify({
      event_id: event?.id,
      type: event?.type,
      user_id: userId,
      outcome: "error",
      error: String(err?.message || err),
    }));
    return new Response("Handler error", { status: 500 });
  }
});
