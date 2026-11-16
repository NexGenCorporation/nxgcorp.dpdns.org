// Cloudflare Worker API for updates.html. Bind an encrypted-at-rest KV namespace as UPDATES.
// Configure ADMIN_PASS and SESSION_SECRET as Worker secrets (never commit their values).
const COOKIE = '__Host-nxg_updates_session';
const SESSION_SECONDS = 8 * 60 * 60;
const MAX_UPDATES = 500;
const MAX_BODY = 5000;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers } });
}
function cookie(value, maxAge) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
function b64url(bytes) {
  let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
async function sign(payload, secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))));
}
async function validSession(request, env) {
  const value = request.headers.get('Cookie')?.split('; ').find(x => x.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
  if (!value || !env.SESSION_SECRET) return false;
  const [payload, signature] = value.split('.'); if (!payload || !signature) return false;
  try { const expected = await sign(payload, env.SESSION_SECRET); if (expected !== signature) return false; const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))); return claims.exp > Math.floor(Date.now() / 1000); } catch { return false; }
}
async function readUpdates(env) { try { return JSON.parse(await env.UPDATES.get('all')) || []; } catch { return []; } }
function cleanText(value, max) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
export default {
  async fetch(request, env) {
    const url = new URL(request.url); if (!url.pathname.startsWith('/api/updates')) return new Response('Not found', { status: 404 });
    if (!env.UPDATES || !env.ADMIN_PASS || !env.SESSION_SECRET) return json({ error: 'Updates service is not configured.' }, 503);
    if (request.method === 'GET' && url.pathname === '/api/updates') return json(await readUpdates(env));
    if (request.method === 'POST' && url.pathname === '/api/updates/login') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown'; const key = `login:${ip}`; const record = JSON.parse(await env.UPDATES.get(key) || '{"count":0,"start":0}'); const now = Date.now();
      if (now - record.start > 15 * 60 * 1000) { record.count = 0; record.start = now; }
      if (record.count >= 5) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
      let input = ''; try { input = cleanText((await request.json()).password, 256); } catch {}
      const a = new TextEncoder().encode(input), b = new TextEncoder().encode(env.ADMIN_PASS); let diff = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] || 0) ^ (b[i] || 0);
      if (diff !== 0 || !input) { record.count++; await env.UPDATES.put(key, JSON.stringify(record), { expirationTtl: 900 }); return json({ error: 'Incorrect password.' }, 401); }
      await env.UPDATES.delete(key); const payload = b64url(new TextEncoder().encode(JSON.stringify({ exp: Math.floor(now / 1000) + SESSION_SECONDS })));
      return json({ ok: true }, 200, { 'set-cookie': cookie(`${payload}.${await sign(payload, env.SESSION_SECRET)}`, SESSION_SECONDS) });
    }
    if (request.method === 'POST' && url.pathname === '/api/updates/logout') return json({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
    if (!await validSession(request, env)) return json({ error: 'Sign in required.' }, 401);
    const items = await readUpdates(env);
    if (request.method === 'POST' && url.pathname === '/api/updates') {
      let data; try { data = await request.json(); } catch { return json({ error: 'Invalid JSON.' }, 400); }
      const title = cleanText(data.title, 160), body = cleanText(data.body, MAX_BODY); if (!title || !body) return json({ error: 'Title and contents are required.' }, 400);
      if (items.length >= MAX_UPDATES) return json({ error: 'Update limit reached.' }, 400);
      const update = { id: crypto.randomUUID(), title, body, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }; items.push(update); await env.UPDATES.put('all', JSON.stringify(items)); return json(update, 201);
    }
    const id = decodeURIComponent(url.pathname.slice('/api/updates/'.length)); const index = items.findIndex(item => item.id === id); if (index < 0) return json({ error: 'Update not found.' }, 404);
    if (request.method === 'POST') { let data; try { data = await request.json(); } catch { return json({ error: 'Invalid JSON.' }, 400); } const title = cleanText(data.title, 160), body = cleanText(data.body, MAX_BODY); if (!title || !body) return json({ error: 'Title and contents are required.' }, 400); items[index] = { ...items[index], title, body, updatedAt: new Date().toISOString() }; await env.UPDATES.put('all', JSON.stringify(items)); return json(items[index]); }
    if (request.method === 'DELETE') { items.splice(index, 1); await env.UPDATES.put('all', JSON.stringify(items)); return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } }); }
    return json({ error: 'Method not allowed.' }, 405, { allow: 'GET, POST, DELETE' });
  }
};
