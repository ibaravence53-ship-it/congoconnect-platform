const crypto = require('crypto');
const config = require('../config/env');

const SIGNING_SECRET = config.tokenSecret;
const DEFAULT_TTL_SECONDS = 300; // 5 minutes

function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(str) {
  const padded = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + '='.repeat(padLen), 'base64').toString('utf8');
}

function signPayload(encodedPayload) {
  return crypto
    .createHmac('sha256', SIGNING_SECRET)
    .update(encodedPayload)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function issueToken({ subject, scope = 'identity:verify', ttlSeconds = DEFAULT_TTL_SECONDS }) {
  const cleanSubject = typeof subject === 'string' ? subject.trim().replace(/[\s-]/g, '') : '';
  if (!cleanSubject || cleanSubject.length < 4 || cleanSubject.length > 40) {
    return { ok: false, error: 'Sujet (identifiant) invalide pour l emission du jeton' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const safeTtl = Number.isFinite(Number(ttlSeconds))
    ? Math.max(30, Math.min(3600, Number(ttlSeconds)))
    : DEFAULT_TTL_SECONDS;

  const payload = {
    iss: 'CongoConnect-PKI-Sim',
    sub: cleanSubject,
    scope: String(scope || 'identity:verify'),
    jti: crypto.randomUUID(),
    iat: nowSec,
    exp: nowSec + safeTtl
  };

  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = signPayload(encodedPayload);
  const token = `cc1.${encodedPayload}.${signature}`;

  return {
    ok: true,
    token,
    expiresInSeconds: safeTtl,
    expiresAt: new Date((nowSec + safeTtl) * 1000).toISOString(),
    claims: payload
  };
}

function verifyToken(token) {
  if (typeof token !== 'string' || !token.trim()) {
    return { ok: false, error: 'Jeton manquant' };
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'cc1') {
    return { ok: false, error: 'Format de jeton invalide' };
  }

  const [, encodedPayload, providedSig] = parts;
  const expectedSig = signPayload(encodedPayload);

  const bufA = Buffer.from(providedSig, 'utf8');
  const bufB = Buffer.from(expectedSig, 'utf8');
  if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
    return { ok: false, error: 'Signature du jeton invalide' };
  }

  let claims;
  try {
    claims = JSON.parse(base64UrlDecode(encodedPayload));
  } catch (_) {
    return { ok: false, error: 'Payload du jeton illisible' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (!claims.exp || nowSec >= claims.exp) {
    return { ok: false, error: 'Jeton expire', claims };
  }

  return {
    ok: true,
    valid: true,
    claims
  };
}

module.exports = {
  issueToken,
  verifyToken
};
