// Vercel Edge Function — POST password, get HttpOnly signed cookie if correct
// Verifies plaintext password against SITE_PASSWORD env var (constant-time compare).
// Sets `mdc_auth` cookie signed with HMAC-SHA256(JWT_SECRET).

export const config = { runtime: 'edge' };

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

async function signTimestamp(timestamp, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(timestamp));
  return Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export default async function handler(request) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'content-type': 'application/json' },
    });
  }

  const sitePassword = process.env.SITE_PASSWORD;
  const jwtSecret = process.env.JWT_SECRET;
  if (!sitePassword || !jwtSecret) {
    return new Response(
      JSON.stringify({
        error:
          'Server auth misconfigured. Set SITE_PASSWORD and JWT_SECRET as Vercel environment variables.',
      }),
      { status: 500, headers: { 'content-type': 'application/json' } }
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Bad request body' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
  }

  const submitted = (body && body.password) || '';
  if (!submitted || !constantTimeEqual(submitted, sitePassword)) {
    return new Response(JSON.stringify({ error: 'Incorrect password' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });
  }

  // Issue cookie: HMAC(timestamp, secret).timestamp — 30-day expiry
  const timestamp = String(Date.now());
  const signature = await signTimestamp(timestamp, jwtSecret);
  const cookieValue = `${signature}.${timestamp}`;

  const cookie = [
    `mdc_auth=${encodeURIComponent(cookieValue)}`,
    'Path=/',
    `Max-Age=${60 * 60 * 24 * 30}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
  ].join('; ');

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'set-cookie': cookie,
    },
  });
}
