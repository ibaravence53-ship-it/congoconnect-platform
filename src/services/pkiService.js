const crypto = require('crypto');
const config = require('../config/env');
const redisStore = require('../storage/redisStore');

const SIGNING_SECRET = config.tokenSecret;
const DEFAULT_TTL_SECONDS = 300; // 5 minutes
const revokedTokens = new Map(); // jti -> expiresAtMs

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

function cleanupExpiredRevocations(nowMs = Date.now()) {
  for (const [jti, expMs] of revokedTokens.entries()) {
    if (nowMs >= expMs) {
      revokedTokens.delete(jti);
    }
  }
}

function parseScopes(scopeValue) {
  if (Array.isArray(scopeValue)) {
    return scopeValue.map((s) => String(s).trim()).filter(Boolean);
  }
  if (typeof scopeValue === 'string') {
    return scopeValue.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  }
  return [];
}

function hasRequiredScope(tokenScope, requiredScope) {
  if (!requiredScope) return true;
  const granted = parseScopes(tokenScope);
  const needed = parseScopes(requiredScope);
  if (!needed.length) return true;
  if (granted.includes('*') || granted.includes('admin:*')) return true;
  return needed.every((reqScope) => granted.includes(reqScope));
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

function decodeAndVerifySignature(token) {
  if (typeof token !== 'string' || !token.trim()) {
    return { ok: false, status: 400, error: 'Jeton manquant' };
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'cc1') {
    return { ok: false, status: 400, error: 'Format de jeton invalide' };
  }

  const [, encodedPayload, providedSig] = parts;
  const expectedSig = signPayload(encodedPayload);

  const bufA = Buffer.from(providedSig, 'utf8');
  const bufB = Buffer.from(expectedSig, 'utf8');
  if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
    return { ok: false, status: 401, error: 'Signature du jeton invalide' };
  }

  let claims;
  try {
    claims = JSON.parse(base64UrlDecode(encodedPayload));
  } catch (_) {
    return { ok: false, status: 400, error: 'Payload du jeton illisible' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (!claims.exp || nowSec >= claims.exp) {
    return { ok: false, status: 401, error: 'Jeton expire', claims };
  }

  return { ok: true, claims };
}

function isTokenRevokedSync(jti) {
  if (!jti) return false;
  cleanupExpiredRevocations();
  const expMs = revokedTokens.get(jti);
  return typeof expMs === 'number' && Date.now() < expMs;
}

async function isTokenRevokedAsync(jti) {
  if (!jti) return false;
  if (isTokenRevokedSync(jti)) return true;

  if (typeof redisStore.getJson === 'function') {
    try {
      const record = await redisStore.getJson(`revoked:${jti}`);
      if (record && record.revoked) return true;
    } catch (_) {
      // Repli memoire silencieux
    }
  }
  return false;
}

async function revokeToken(token, reason = 'manual_revocation') {
  const checked = decodeAndVerifySignature(token);
  if (!checked.ok) {
    return { ok: false, status: checked.status || 400, error: checked.error, claims: checked.claims };
  }

  const { claims } = checked;
  const jti = claims.jti || crypto.createHash('sha256').update(token).digest('hex');
  const nowSec = Math.floor(Date.now() / 1000);
  const remainingSec = Math.max(1, Number(claims.exp) - nowSec);
  const expMs = Number(claims.exp) * 1000;

  revokedTokens.set(jti, expMs);

  if (typeof redisStore.setJsonWithTtl === 'function') {
    try {
      await redisStore.setJsonWithTtl(`revoked:${jti}`, { revoked: true, reason, revokedAt: new Date().toISOString() }, remainingSec);
    } catch (_) {
      // Repli memoire silencieux
    }
  }

  return {
    ok: true,
    revoked: true,
    jti,
    reason,
    expiresAt: new Date(expMs).toISOString(),
    claims
  };
}

function verifyToken(token, options = {}) {
  const checked = decodeAndVerifySignature(token);
  if (!checked.ok) {
    return {
      ok: false,
      valid: false,
      status: checked.status || 400,
      error: checked.error,
      claims: checked.claims
    };
  }

  const { claims } = checked;

  if (isTokenRevokedSync(claims.jti)) {
    return {
      ok: false,
      valid: false,
      status: 401,
      error: 'Jeton revoque',
      claims
    };
  }

  const requiredScope = options.requiredScope || options.scope || '';
  if (!hasRequiredScope(claims.scope, requiredScope)) {
    return {
      ok: false,
      valid: false,
      status: 403,
      error: `Scope insuffisant (requis: ${requiredScope})`,
      claims
    };
  }

  return {
    ok: true,
    valid: true,
    claims
  };
}

module.exports = {
  issueToken,
  verifyToken,
  revokeToken,
  isTokenRevokedSync,
  isTokenRevokedAsync,
  hasRequiredScope
};
