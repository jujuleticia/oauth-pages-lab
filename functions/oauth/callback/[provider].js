import { PROVIDERS, redirectUri } from '../../_shared/providers.js';
import { getCookie, clearCookie, sessionCookie } from '../../_shared/cookies.js';
import { randomToken, sha256 } from '../../_shared/crypto.js';
import { exchangeGoogle, validateGoogle, exchangeGitHub, getGitHubUser, revokeGitHub } from '../../_shared/oidc.js';

function fail(message = 'Authentication failed', status = 400) {
  return new Response(message, {status, headers: {'Cache-Control': 'no-store'}});
}

export async function onRequestGet(context) {
  const provider = context.params.provider;
  if (!PROVIDERS[provider]) return fail('Not Found', 404);
  const url = new URL(context.request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (url.searchParams.get('error') || !code || !state) return fail();
  const txCookie = getCookie(context.request, '__Host-oauth-tx');
  if (!txCookie) return fail();
  const txHash = await sha256(txCookie);
  const tx = await context.env.DB.prepare('SELECT * FROM oauth_transactions WHERE id_hash = ? AND expires_at > ?').bind(txHash, Math.floor(Date.now()/1000)).first();
  if (!tx || tx.provider !== provider || tx.state_hash !== await sha256(state)) return fail();
  await context.env.DB.prepare('DELETE FROM oauth_transactions WHERE id_hash = ?').bind(txHash).run();

  let profile;
  if (provider === 'google') {
    const token = await exchangeGoogle(code, tx.code_verifier, context.env, redirectUri(context.env, provider));
    if (!token.id_token) return fail();
    profile = await validateGoogle(token.id_token, context.env, tx.nonce);
  } else {
    const token = await exchangeGitHub(code, tx.code_verifier, context.env, redirectUri(context.env, provider));
    const user = await getGitHubUser(token.access_token);
    await revokeGitHub(context.env.GITHUB_CLIENT_ID, context.env.GITHUB_CLIENT_SECRET, token.access_token);
    profile = {issuer: 'https://github.com', subject: String(user.id), email: typeof user.email === 'string' ? user.email : null, displayName: typeof user.name === 'string' && user.name ? user.name : (typeof user.login === 'string' ? user.login : null)};
  }

  const session = randomToken();
  const now = Math.floor(Date.now()/1000);
  await context.env.DB.prepare('INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(await sha256(session), profile.issuer, profile.subject, profile.email, profile.displayName, now + 28800, now).run();
  const headers = new Headers();
  headers.set('Location', context.env.PUBLIC_BASE_URL);
  headers.append('Set-Cookie', clearCookie('__Host-oauth-tx'));
  headers.append('Set-Cookie', sessionCookie(session));
  headers.set('Cache-Control', 'no-store');
  return new Response(null, {status: 302, headers});
}
