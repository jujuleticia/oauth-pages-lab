export const PROVIDERS = {
  google: {
    authorization: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    issuer: 'https://accounts.google.com'
  },
  github: {
    authorization: 'https://github.com/login/oauth/authorize',
    token: 'https://github.com/login/oauth/access_token',
    issuer: 'https://github.com'
  }
};

export function redirectUri(env, provider) {
  return `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
}
