import { decodeJsonPart } from './crypto.js';

async function verifyGoogleIdToken(idToken, env, expectedNonce) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('invalid_id_token');
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = decodeJsonPart(encodedHeader);
  const claims = decodeJsonPart(encodedPayload);
  if (header.alg !== 'RS256' || !header.kid) throw new Error('invalid_id_token_header');

  const discoveryResponse = await fetch('https://accounts.google.com/.well-known/openid-configuration');
  if (!discoveryResponse.ok) throw new Error('oidc_discovery_failed');
  const discovery = await discoveryResponse.json();
  if (discovery.issuer !== 'https://accounts.google.com') throw new Error('invalid_issuer');

  const jwksResponse = await fetch(discovery.jwks_uri);
  if (!jwksResponse.ok) throw new Error('jwks_failed');
  const jwks = await jwksResponse.json();
  const jwk = jwks.keys.find((key) => key.kid === header.kid);
  if (!jwk) throw new Error('unknown_key');

  const key = await crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['verify']
  );
  const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
  const signature = Uint8Array.from(atob(encodedSignature.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(encodedSignature.length / 4) * 4, '=')), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
  if (!valid) throw new Error('invalid_signature');

  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== 'https://accounts.google.com') throw new Error('invalid_issuer');
  if (claims.aud !== env.GOOGLE_CLIENT_ID) throw new Error('invalid_audience');
  if (!Number.isInteger(claims.exp) || claims.exp <= now) throw new Error('expired_token');
  if (!Number.isInteger(claims.iat) || claims.iat > now + 300) throw new Error('invalid_iat');
  if (claims.nonce !== expectedNonce) throw new Error('invalid_nonce');
  if (!claims.sub) throw new Error('missing_subject');

  return {
    issuer: 'https://accounts.google.com',
    subject: String(claims.sub),
    email: typeof claims.email === 'string' ? claims.email : null,
    displayName: typeof claims.name === 'string' ? claims.name : null
  };
}

export async function exchangeGoogle(code, verifier, env, redirectUri) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      code,
      code_verifier: verifier,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri
    })
  });
  if (!response.ok) throw new Error('google_token_exchange_failed');
  return response.json();
}

export async function validateGoogle(idToken, env, nonce) {
  return verifyGoogleIdToken(idToken, env, nonce);
}

export async function exchangeGitHub(code, verifier, env, redirectUri) {
  const response = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      code_verifier: verifier,
      redirect_uri: redirectUri
    })
  });
  if (!response.ok) throw new Error('github_token_exchange_failed');
  const data = await response.json();
  if (!data.access_token || String(data.token_type || '').toLowerCase() !== 'bearer') throw new Error('invalid_github_token');
  return data;
}

export async function getGitHubUser(accessToken) {
  const response = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2026-03-10'
    }
  });
  if (!response.ok) throw new Error('github_user_failed');
  const user = await response.json();
  if (!Number.isInteger(user.id)) throw new Error('invalid_github_user');
  return user;
}

export async function revokeGitHub(clientId, clientSecret, accessToken) {
  const credentials = btoa(`${clientId}:${clientSecret}`);
  const response = await fetch(`https://api.github.com/applications/${encodeURIComponent(clientId)}/grant`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2026-03-10',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({access_token: accessToken})
  });
  if (response.status !== 204) throw new Error('github_revoke_failed');
}
