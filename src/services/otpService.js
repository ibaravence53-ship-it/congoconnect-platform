const crypto = require('crypto');

const otpStore = new Map();
const OTP_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_VERIFY_ATTEMPTS = 4;

function normalizeIdentifier(raw) {
  if (typeof raw !== 'string') return '';
  return raw.trim().replace(/[\s-]/g, '');
}

function generateSixDigitCode() {
  const num = crypto.randomInt(0, 1000000);
  return String(num).padStart(6, '0');
}

function requestOtp(rawIdentifier) {
  const identifier = normalizeIdentifier(rawIdentifier);
  if (!identifier || identifier.length < 4 || identifier.length > 40) {
    return { ok: false, error: 'Identifiant invalide' };
  }

  const code = generateSixDigitCode();
  const expiresInSeconds = Math.floor(OTP_TTL_MS / 1000);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString();

  otpStore.set(identifier, {
    code,
    expiresAtMs: Date.now() + OTP_TTL_MS,
    attempts: 0
  });

  return {
    ok: true,
    identifier,
    code,
    expiresInSeconds,
    expiresAt
  };
}

function verifyOtp(rawIdentifier, rawCode) {
  const identifier = normalizeIdentifier(rawIdentifier);
  const code = typeof rawCode === 'string' ? rawCode.trim() : '';

  if (!identifier || !/^\d{6}$/.test(code)) {
    return { ok: false, error: 'Identifiant ou code OTP (6 chiffres) invalide' };
  }

  const entry = otpStore.get(identifier);
  if (!entry) {
    return { ok: false, error: 'Aucun code OTP actif pour cet identifiant' };
  }

  if (Date.now() > entry.expiresAtMs) {
    otpStore.delete(identifier);
    return { ok: false, error: 'Code OTP expire' };
  }

  if (entry.code !== code) {
    entry.attempts += 1;
    if (entry.attempts >= MAX_VERIFY_ATTEMPTS) {
      otpStore.delete(identifier);
      return { ok: false, error: 'Trop de tentatives echouees. Demandez un nouveau code OTP.' };
    }
    const remaining = MAX_VERIFY_ATTEMPTS - entry.attempts;
    return {
      ok: false,
      error: `Code OTP incorrect (${remaining} tentative(s) restante(s))`
    };
  }

  // Usage unique : suppression immediate apres validation
  otpStore.delete(identifier);

  return {
    ok: true,
    identifier,
    verified: true
  };
}

module.exports = {
  requestOtp,
  verifyOtp,
  normalizeIdentifier
};
