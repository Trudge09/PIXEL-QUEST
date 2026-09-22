const CLIENT_ID = '497307024897-p1t3fjm3cpjvj6t7r7lhp870b9iljaa5.apps.googleusercontent.com';
const encoder = new TextEncoder();
const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra } });
const b64 = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
const unb64 = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
async function signingKey(secret) { return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']); }
async function sign(value, secret) { return b64(new Uint8Array(await crypto.subtle.sign('HMAC', await signingKey(secret), encoder.encode(value)))); }
async function session(request, secret) {
  const token = (request.headers.get('cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith('pq_session='))?.slice(11);
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2 || !/^[\w-]+$/.test(parts[0]) || !/^[\w-]+$/.test(parts[1])) return null;
  try {
    const valid = await crypto.subtle.verify('HMAC', await signingKey(secret), unb64(parts[1]), encoder.encode(parts[0]));
    if (!valid) return null;
    const value = JSON.parse(new TextDecoder().decode(unb64(parts[0])));
    return value && typeof value.sub === 'string' && value.exp > Math.floor(Date.now() / 1000) ? value : null;
  } catch { return null; }
}
function cookie(token, maxAge) { return `pq_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`; }
function validData(data) { return data && typeof data === 'object' && !Array.isArray(data) && Array.isArray(data.tasks) && Array.isArray(data.rewards) && Array.isArray(data.log) && Array.isArray(data.purchases) && data.memos && typeof data.memos === 'object' && !Array.isArray(data.memos) && data.finishes && typeof data.finishes === 'object' && !Array.isArray(data.finishes); }
async function readJson(request) {
  if (Number(request.headers.get('content-length') || 0) > 262144) throw new Error('요청 데이터가 너무 커.');
  const text = await request.text();
  if (encoder.encode(text).length > 262144) throw new Error('요청 데이터가 너무 커.');
  return JSON.parse(text);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
    if (!env.DB || !env.SESSION_SECRET) return json({ error: '서버 설정이 완료되지 않았어. DB 바인딩과 SESSION_SECRET을 확인해 줘.' }, 503);
    if (request.method !== 'GET') {
      if (request.headers.get('origin') !== url.origin || request.headers.get('x-pixel-quest') !== '1' || !request.headers.get('content-type')?.startsWith('application/json')) return json({ error: '허용되지 않은 요청이야.' }, 403);
    }
    try {
      if (url.pathname === '/api/auth/google' && request.method === 'POST') {
        const { credential } = await readJson(request);
        if (typeof credential !== 'string' || credential.length > 10000) return json({ error: 'Google 로그인 정보가 올바르지 않아.' }, 400);
        const verify = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(credential));
        if (!verify.ok) return json({ error: 'Google 로그인 확인에 실패했어.' }, 401);
        const profile = await verify.json();
        const now = Math.floor(Date.now() / 1000);
        if (profile.aud !== CLIENT_ID || (profile.azp && profile.azp !== CLIENT_ID) || !['accounts.google.com', 'https://accounts.google.com'].includes(profile.iss) || !profile.sub || !/^\d+$/.test(String(profile.exp)) || Number(profile.exp) <= now || String(profile.email_verified) !== 'true') return json({ error: 'Google 로그인 검증에 실패했어.' }, 401);
        const user = { sub: profile.sub, name: String(profile.name || '').slice(0, 100), email: String(profile.email || '').slice(0, 254) };
        await env.DB.prepare('CREATE TABLE IF NOT EXISTS deletion_guards (user_key TEXT PRIMARY KEY, deleted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)').run();
        const key = await sign('deleted-user:' + user.sub, env.SESSION_SECRET);
        const previous = await env.DB.prepare('SELECT deleted_at FROM deletion_guards WHERE user_key = ? AND expires_at > ?').bind(key, Date.now()).first();
        const payload = b64(encoder.encode(JSON.stringify({ ...user, iat: Math.max(Date.now(), (previous?.deleted_at || 0) + 1), exp: now + 60 * 60 * 24 * 30 })));
        return json({ user }, 200, { 'set-cookie': cookie(payload + '.' + await sign(payload, env.SESSION_SECRET), 60 * 60 * 24 * 30) });
      }
      if (url.pathname === '/api/logout' && request.method === 'POST') return json({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
      const user = await session(request, env.SESSION_SECRET);
      if (url.pathname === '/api/me' && request.method === 'GET') return json({ user: user ? { sub: user.sub, name: user.name, email: user.email } : null });
      if (!user) return json({ error: '로그인이 필요해.' }, 401);
      await env.DB.prepare('CREATE TABLE IF NOT EXISTS deletion_guards (user_key TEXT PRIMARY KEY, deleted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)').run();
      await env.DB.prepare('DELETE FROM deletion_guards WHERE expires_at <= ?').bind(Date.now()).run();
      const userKey = await sign('deleted-user:' + user.sub, env.SESSION_SECRET);
      const guard = await env.DB.prepare('SELECT deleted_at FROM deletion_guards WHERE user_key = ? AND expires_at > ?').bind(userKey, Date.now()).first();
      if (guard && (!Number.isSafeInteger(user.iat) || user.iat <= guard.deleted_at)) return json({ error: '이 계정의 이전 로그인은 만료되었습니다. 다시 로그인해 주세요.' }, 401, { 'set-cookie': cookie('', 0) });
      await env.DB.prepare('CREATE TABLE IF NOT EXISTS user_states (user_id TEXT PRIMARY KEY, data TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();
      if (url.pathname === '/api/account/data' && request.method === 'DELETE') {
        const body = await readJson(request);
        if (body.confirm !== 'DELETE') return json({ error: '삭제 확인 정보가 올바르지 않아.' }, 400);
        const deletedAt = Date.now();
        await env.DB.batch([
          env.DB.prepare('INSERT INTO deletion_guards (user_key, deleted_at, expires_at) VALUES (?, ?, ?) ON CONFLICT(user_key) DO UPDATE SET deleted_at = excluded.deleted_at, expires_at = excluded.expires_at').bind(userKey, deletedAt, deletedAt + 31 * 86400000),
          env.DB.prepare('DELETE FROM user_states WHERE user_id = ?').bind(user.sub)
        ]);
        return json({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
      }
      if (url.pathname !== '/api/state') return json({ error: '요청한 API가 없어.' }, 404);
      if (request.method === 'GET') {
        const row = await env.DB.prepare('SELECT data, version FROM user_states WHERE user_id = ?').bind(user.sub).first();
        return json({ data: row ? JSON.parse(row.data) : null, version: row ? row.version : 0, previouslyDeleted: !row && !!guard });
      }
      if (request.method === 'PUT') {
        const body = await readJson(request);
        if (!validData(body.data) || !Number.isSafeInteger(body.version) || body.version < 0) return json({ error: '저장 데이터 형식이 올바르지 않아.' }, 400);
        const data = JSON.stringify(body.data);
        if (encoder.encode(data).length > 250000) return json({ error: '저장 용량 한도(250KB)를 초과했어.' }, 413);
        if (body.version === 0) {
          const result = await env.DB.prepare('INSERT INTO user_states (user_id, data, version) SELECT ?, ?, 1 WHERE NOT EXISTS (SELECT 1 FROM deletion_guards WHERE user_key = ? AND deleted_at >= ? AND expires_at > ?) ON CONFLICT(user_id) DO NOTHING').bind(user.sub, data, userKey, Number(user.iat) || 0, Date.now()).run();
          return result.meta.changes ? json({ version: 1 }) : json({ error: '다른 기기에서 먼저 기록을 저장했어.' }, 409);
        }
        const result = await env.DB.prepare('UPDATE user_states SET data = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND version = ? AND NOT EXISTS (SELECT 1 FROM deletion_guards WHERE user_key = ? AND deleted_at >= ? AND expires_at > ?)').bind(data, user.sub, body.version, userKey, Number(user.iat) || 0, Date.now()).run();
        return result.meta.changes ? json({ version: body.version + 1 }) : json({ error: '다른 기기에서 기록이 변경됐어.' }, 409);
      }
      return json({ error: '지원하지 않는 요청이야.' }, 405);
    } catch (error) {
      console.error('PIXEL QUEST API error:', error);
      return json({ error: error instanceof SyntaxError ? 'JSON 형식이 올바르지 않아.' : error.message === '요청 데이터가 너무 커.' ? error.message : '서버 처리 중 문제가 발생했어.' }, error instanceof SyntaxError ? 400 : error.message === '요청 데이터가 너무 커.' ? 413 : 500);
    }
  }
};
