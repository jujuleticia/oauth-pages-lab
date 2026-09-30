import { getCookie, clearCookie } from '../_shared/cookies.js';
import { sha256 } from '../_shared/crypto.js';

export async function onRequestPost(context) {
  const origin = context.request.headers.get('Origin');
  if (origin !== context.env.PUBLIC_BASE_URL) return new Response('Forbidden', {status: 403, headers: {'Cache-Control': 'no-store'}});
  const cookie = getCookie(context.request, '__Host-session');
  if (cookie) await context.env.DB.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(await sha256(cookie)).run();
  return new Response(null, {status: 204, headers: {'Set-Cookie': clearCookie('__Host-session', 'Strict'), 'Cache-Control': 'no-store'}});
}
