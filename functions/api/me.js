import { getCookie } from '../_shared/cookies.js';
import { sha256 } from '../_shared/crypto.js';

export async function onRequestGet(context) {
  const cookie = getCookie(context.request, '__Host-session');
  if (!cookie) return Response.json({error: 'unauthorized'}, {status: 401, headers: {'Cache-Control': 'no-store'}});
  const idHash = await sha256(cookie);
  const row = await context.env.DB.prepare(
    'SELECT issuer, subject, email, display_name, expires_at FROM sessions WHERE id_hash = ? AND expires_at > ?'
  ).bind(idHash, Math.floor(Date.now()/1000)).first();
  if (!row) return Response.json({error: 'unauthorized'}, {status: 401, headers: {'Cache-Control': 'no-store'}});
  return Response.json({issuer: row.issuer, subject: row.subject, email: row.email, displayName: row.display_name}, {headers: {'Cache-Control': 'no-store'}});
}
