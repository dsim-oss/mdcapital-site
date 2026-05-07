// Vercel Edge Middleware — server-side auth gate for MD Capital site.
// Protected: /MD_Capital_*.html and /demo/*.
// Public: everything else (/, /weekly.html, /letters/*, /api/*, static assets).
//
// Redirects to /?auth=<reason> when blocked so we can diagnose in the URL bar.

export const config = {
  // Run on every request; we filter inside the function.
  // Static assets (images, fonts) are excluded so we don't waste cycles.
  matcher: '/((?!_next|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|woff|woff2|ttf|css|js|map)$).*)',
};

const PROTECTED_PATTERNS = [/^\/MD_Capital_/i, /^\/demo\//i];

function isProtectedPath(pathname) {
  return PROTECTED_PATTERNS.some((re) => re.test(pathname));
}

async function verifySignature(value, secret) {
  // Cookie format: <hex hmac>.<timestamp>
  const dot = value.lastIndexOf('.');
  if (dot < 1) return { ok: false, reason: 'malformed_no_dot' };
  const signature = value.slice(0, dot);
  const timestamp = value.slice(dot + 1);
  const ts = parseInt(timestamp, 10);
  if (!Number.isFinite(ts)) return { ok: false, reason: 'malformed_ts' };
  if (Date.now() - ts > 1000 * 60 * 60 * 24 * 30) return { ok: false, reason: 'expired' };

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
  return { ok: mismatch === 0, reason: mismatch === 0 ? 'ok' : 'sig_mismatch' };
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // Only enforce on explicitly protected paths
  if (!isProtectedPath(pathname)) return;

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return Response.redirect(new URL('/?auth=no_secret', request.url), 302);
  }

  const cookieHeader = request.headers.get('cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)mdc_auth=([^;]+)/);
  if (!match) {
    return Response.redirect(
      new URL('/?auth=no_cookie&next=' + encodeURIComponent(pathname), request.url),
      302
    );
  }

  const result = await verifySignature(decodeURIComponent(match[1]), secret);
  if (!result.ok) {
    return Response.redirect(
      new URL('/?auth=' + encodeURIComponent(result.reason) + '&next=' + encodeURIComponent(pathname), request.url),
      302
    );
  }

  // Authenticated — continue
  return;
}
