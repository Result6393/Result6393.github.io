// Work settings sync Worker.
//
// Stores one encrypted settings blob per app in KV. The browser encrypts before
// upload, so this Worker never sees readable settings. Access needs the auth
// token derived from your password (see ../../settings/sync.js); only its
// SHA-256 hash is kept here, as the AUTH_HASH secret.
//
// Routes (all JSON):
//   POST /auth        -> 204 if the token is right (used at sign-in)
//   GET  /s/:app      -> { iv, ct, updated } or 404
//   PUT  /s/:app      <- { iv, ct, updated }  -> 204
//
// Wrong tokens are counted per IP; after MAX_FAILS in LOCK_SECONDS the IP is locked out.

const MAX_FAILS = 10;
const LOCK_SECONDS = 15 * 60;
const MAX_BODY = 64 * 1024;
const APP_RE = /^[a-z0-9-]{1,40}$/;

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = allowedOrigin(origin, env);
    const cors = allowed
      ? {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Authorization, Content-Type',
          'Access-Control-Max-Age': '86400',
          Vary: 'Origin',
        }
      : { Vary: 'Origin' };

    const reply = (status, body) =>
      new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });

    if (request.method === 'OPTIONS') return new Response(null, { status: allowed ? 204 : 403, headers: cors });

    const url = new URL(request.url);
    if (url.pathname === '/' && request.method === 'GET') return reply(200, { ok: true, service: 'work-settings' });
    if (!allowed) return reply(403, { error: 'origin not allowed' });
    if (!env.AUTH_HASH) return reply(500, { error: 'AUTH_HASH secret not set' });

    // --- authentication with per-IP lockout ---
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const failKey = `fail:${ip}`;
    const fails = Number((await env.SETTINGS.get(failKey)) || 0);
    if (fails >= MAX_FAILS) return reply(429, { error: 'too many wrong passwords; try again in 15 minutes' });

    const auth = request.headers.get('Authorization') || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    if (!(await tokenMatches(token, env.AUTH_HASH))) {
      await env.SETTINGS.put(failKey, String(fails + 1), { expirationTtl: LOCK_SECONDS });
      return reply(401, { error: 'wrong password' });
    }

    // --- routes ---
    if (url.pathname === '/auth' && request.method === 'POST') return reply(204);

    const m = url.pathname.match(/^\/s\/([^/]+)$/);
    if (!m || !APP_RE.test(m[1])) return reply(404, { error: 'not found' });
    const key = `app:${m[1]}`;

    if (request.method === 'GET') {
      const value = await env.SETTINGS.get(key);
      return value ? new Response(value, { status: 200, headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }) : reply(404, { error: 'no settings saved yet' });
    }

    if (request.method === 'PUT') {
      const text = await request.text();
      if (text.length > MAX_BODY) return reply(413, { error: 'settings too large' });
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        return reply(400, { error: 'invalid JSON' });
      }
      if (typeof data?.iv !== 'string' || typeof data?.ct !== 'string' || typeof data?.updated !== 'number') {
        return reply(400, { error: 'expected { iv, ct, updated }' });
      }
      await env.SETTINGS.put(key, JSON.stringify({ iv: data.iv, ct: data.ct, updated: data.updated }));
      return reply(204);
    }

    return reply(405, { error: 'method not allowed' });
  },
};

function allowedOrigin(origin, env) {
  const list = (env.ALLOWED_ORIGINS || 'https://result6393.github.io').split(',').map((s) => s.trim());
  return list.includes(origin);
}

async function tokenMatches(token, expectedHex) {
  if (!/^[0-9a-f]{64}$/.test(token)) return false;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
  const expected = hexToBytes(expectedHex.trim().toLowerCase());
  if (!expected || expected.length !== digest.length) return false;
  return crypto.subtle.timingSafeEqual(digest, expected);
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
