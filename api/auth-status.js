// Diagnostic endpoint — returns auth state from the server's perspective.
// Useful for figuring out why middleware is redirecting. Doesn't leak secrets.

export const config = { runtime: 'edge' };

async function verifySignature(value, secret) {
  const dot = value.lastIndexOf('.');
  if (dot < 1) return { ok: false, reason: 'malformed_no_dot' };
  const signature = value.slice(0, dot);
  const timestamp = value.slice(dot + 1);
  const ts = parseInt(timestamp, 10);
  if (!Number.isFinite(ts)) return { ok: false, reason: 'malformed_ts' };
  const ageMs = Date.now() - ts;
  if (ageMs > 1000 * 60 * 60 * 24 * 30) return { ok: false, reason: 'expired', ageMs };

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const expectedBuf = await crypto.subtle.sign('HMAC', key, enc.encode(timestamp));
  const expectedHex = Array.from(new Uint8Array(expectedBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  if (expectedHex.length !== signature.length) return { ok: false, reason: 'sig_length' };
  let mismatch = 0;
  for (let i = 0; i < expectedHex.length; i++) {
    mismatch |= expectedHex.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return { ok: mismatch === 0, reason: mismatch === 0 ? 'ok' : 'sig_mismatch', ageMs };
}

export default async function handler(request) {
  const sitePassword = process.env.SITE_PASSWORD;
  const jwtSecret = process.env.JWT_SECRET;

  const status = {
    env: {
      SITE_PASSWORD_set: Boolean(sitePassword),
      SITE_PASSWORD_length: sitePassword ? sitePassword.length : 0,
      JWT_SECRET_set: Boolean(jwtSecret),
      JWT_SECRET_length: jwtSecret ? jwtSecret.length : 0,
    },
    request: {
      method: request.method,
      hasCookieHeader: Boolean(request.headers.get('cookie')),
    },
    cookie: {
      present: false,
    },
  };

  const cookieHeader = request.headers.get('cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)mdc_auth=([^;]+)/);
  if (match) {
    status.cookie.present = true;
    status.cookie.length = match[1].length;
    if (jwtSecret) {
      const result = await verifySignature(decodeURIComponent(match[1]), jwtSecret);
      status.cookie.verifies = result.ok;
      status.cookie.verifyReason = result.reason;
      if (result.ageMs !== undefined) status.cookie.ageHours = +(result.ageMs / 1000 / 60 / 60).toFixed(2);
    }
  }

  return new Response(JSON.stringify(status, null, 2), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}
