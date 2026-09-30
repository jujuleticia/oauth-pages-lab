import { PROVIDERS, redirectUri } from '../../_shared/providers.js';
import { randomToken, sha256, codeChallenge } from '../../_shared/crypto.js';
import { transactionCookie } from '../../_shared/cookies.js';

export async function onRequestGet(context) {
  const provider = context.params.provider;
  if (!PROVIDERS[provider]) return new Response('Not Found', {status: 404});
  const state = randomToken();
  const verifier = randomToken();
  const nonce = provider === 'google' ? randomToken() : null;
  const txCookie = randomToken();
  const now = Math.floor(Date.now()/1000);
  await context.env.DB.prepare(
    'INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(await sha256(txCookie), provider, await sha256(state), nonce, verifier, now + 600).run();

  const params = new URLSearchParams({client_id: context.env[provider === 'google' ? 'GOOGLE_CLIENT_ID' : 'GITHUB_CLIENT_ID'], redirect_uri: redirectUri(context.env, provider), response_type: 'code', state, code_challenge: await codeChallenge(verifier), code_challenge_method: 'S256'});
  if (provider === 'google') {
    params.set('scope', 'openid email profile');
    params.set('nonce', nonce);
  }
  return new Response(null, {status: 302, headers: {'Location': `${PROVIDERS[provider].authorization}?${params}`, 'Set-Cookie': transactionCookie(txCookie), 'Cache-Control': 'no-store'}});
}
