// Vercel Edge Middleware — server-side auth gate for MD Capital site
// Protects all dashboard pages with an HMAC-signed cookie.
// Public paths (no auth required): /, /weekly.html, /letters/*, /api/*, static assets.

export const config = {
  matcher: [
    // Run on every request EXCEPT the ones explicitly skipped via excluded prefixes.
    // The path-level allow/deny logic is in the function below.
    '/((?!_next/static|_next/image|favicon|robots\\.txt|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|woff2?)$).*)',
  ],
};

const PROTECTED_PATTERNS = [
  /^\/MD_Capital_/i,
  /^\/demo\//i,
];

const PUBLIC_PATHS = new Set([
  '/',
  '/index.html',
  '/weekly.html',
  '/robots.txt',
  '/favicon.svg',
]);

function isPublicPath(pathname) {
  if (PUBLIC_PATHS.has(pathname)) return true;
  if (pathname.startsWith('/letters/')) return true;
  if (pathname.startsWith('/api/')) return true;
  return false;
}

function isProtectedPath(pathname) {
  return PROTECTED_PATTERNS.some((re) => re.test(pathname));
}

async function verifySignature(value, secret) {
  // Cookie format: <hex hmac>.<timestamp>
  const parts = value.split('.');
  if (parts.length !== 2) return false;
  const [signature, timestamp] = parts;
  const ts = parseInt(timestamp, 10);
  if (!Number.isFinite(ts)) return false;
  // 30-day expiry
  if (Date.now() - ts > 1000 * 60 * 60 * 24 * 30) return false;
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
  // constant-time compare
  if (expectedHex.length !== signature.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expectedHex.length; i++) {
    mismatch |= expectedHex.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return mismatch === 0;
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // Allow public paths through
  if (isPublicPath(pathname)) return;

  // Only enforce on explicitly protected paths; everything else passes through
  if (!isProtectedPath(pathname)) return;

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    // Misconfigured deployment — fail closed with a clear message
    return new Response('Server auth misconfigured: JWT_SECRET not set on Vercel.', {
      status: 500,
    });
  }

  // Read cookie
  const cookieHeader = request.headers.get('cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)mdc_auth=([^;]+)/);
  if (!match) {
    return Response.redirect(new URL('/?next=' + encodeURIComponent(pathname), request.url), 302);
  }

  const ok = await verifySignature(decodeURIComponent(match[1]), secret);
  if (!ok) {
    return Response.redirect(new URL('/?next=' + encodeURIComponent(pathname), request.url), 302);
  }

  // Authenticated — continue
  return;
}
