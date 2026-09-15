export const config = { api: { bodyParser: false } };

const SUPABASE_URL = 'https://efmpsyvxzbkmwsypzbqs.supabase.co';

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(Buffer.from(c)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifyStripeSignature(rawBody, header, secret) {
  if (!header || !secret) return false;
  const items = header.split(',').map((p) => p.trim());
  const t = (items.find((p) => p.startsWith('t=')) || '').slice(2);
  const v1s = items.filter((p) => p.startsWith('v1=')).map((p) => p.slice(3));
  if (!t || !v1s.length) return false;
  const crypto = require('crypto');
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${t}.${rawBody}`)
    .digest('hex');
  return v1s.some((sig) => {
    try {
      return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    } catch {
      return false;
    }
  });
}

async function sb(path, method, body) {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Prefer: 'return=representation',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

async function setPaid(userId, paid, extra) {
  if (!userId) return false;
  const rows = await sb(`km_state?user_id=eq.${userId}`, 'GET');
  const current = (rows && rows[0] && rows[0].data) || {};
  const data = Object.assign({}, current, extra || {}, { paid: !!paid });
  if (rows && rows[0]) {
    await sb(`km_state?user_id=eq.${userId}`, 'PATCH', {
      data,
      updated_at: new Date().toISOString(),
    });
  } else {
    await sb('km_state', 'POST', {
      user_id: userId,
      data,
      updated_at: new Date().toISOString(),
    });
  }
  return true;
}

async function findUserByCustomer(customerId) {
  if (!customerId) return null;
  const rows = await sb(
    `km_state?data->>stripeCustomerId=eq.${encodeURIComponent(customerId)}`,
    'GET'
  );
  return rows && rows[0] ? rows[0].user_id : null;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed');
    return;
  }
  try {
    const rawBuf = await readRawBody(req);
    const raw = rawBuf.toString('utf8');
    const ok = verifyStripeSignature(
      raw,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET
    );
    if (!ok) {
      res.status(400).send('Invalid signature');
      return;
    }
    const event = JSON.parse(raw);
    const obj = event.data && event.data.object ? event.data.object : {};

    if (event.type === 'checkout.session.completed') {
      const userId = obj.client_reference_id;
      const customer = obj.customer || null;
      const email = obj.customer_details && obj.customer_details.email;
      if (userId) {
        await setPaid(userId, true, {
          stripeCustomerId: customer,
          stripeEmail: email || null,
        });
      }
    }

    if (event.type === 'invoice.paid') {
      const customer = obj.customer;
      const userId = await findUserByCustomer(customer);
      if (userId) await setPaid(userId, true, { stripeCustomerId: customer });
    }

    if (event.type === 'customer.subscription.deleted') {
      const customer = obj.customer;
      const userId = await findUserByCustomer(customer);
      if (userId) await setPaid(userId, false, { stripeCustomerId: customer });
    }

    res.status(200).json({ received: true });
  } catch (err) {
    res.status(500).send(err.message || 'Webhook error');
  }
}
