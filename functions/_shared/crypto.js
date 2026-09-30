const encoder = new TextEncoder();

export function randomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function randomToken() {
  return base64Url(randomBytes(32));
}

export async function sha256(value) {
  const data = typeof value === 'string' ? encoder.encode(value) : value;
  return base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', data)));
}

export async function codeChallenge(verifier) {
  return sha256(verifier);
}

export function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(normalized);
  return new Uint8Array([...binary].map((c) => c.charCodeAt(0)));
}

export function decodeJsonPart(value) {
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
}
