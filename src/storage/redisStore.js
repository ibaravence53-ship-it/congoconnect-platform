const config = require('../config/env');

const memoryStore = new Map();

function getRedisKeySpec() {
  return {
    enabled: Boolean(config.redisUrl),
    otpKeyPrefix: 'cc:otp:',
    rateLimitPrefix: 'cc:rl:otp:'
  };
}

function purgeExpired() {
  const now = Date.now();
  for (const [key, entry] of memoryStore.entries()) {
    if (entry.expiresAt && entry.expiresAt <= now) {
      memoryStore.delete(key);
    }
  }
}

async function setJsonWithTtl(key, value, ttlSeconds) {
  purgeExpired();
  const expiresAt = ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null;
  memoryStore.set(key, { value: JSON.stringify(value), expiresAt });
}

async function getJson(key) {
  purgeExpired();
  const entry = memoryStore.get(key);
  if (!entry) return null;
  try {
    return JSON.parse(entry.value);
  } catch {
    return null;
  }
}

async function incrementWithTtl(key, ttlSeconds) {
  purgeExpired();
  const current = memoryStore.get(key);
  const now = Date.now();
  if (!current || (current.expiresAt && current.expiresAt <= now)) {
    const next = { count: 1, expiresAt: now + ttlSeconds * 1000 };
    memoryStore.set(key, { value: JSON.stringify(next), expiresAt: next.expiresAt });
    return { count: 1, ttlSeconds };
  }
  const parsed = JSON.parse(current.value);
  parsed.count += 1;
  memoryStore.set(key, { value: JSON.stringify(parsed), expiresAt: current.expiresAt });
  const remainingSec = Math.max(1, Math.ceil((current.expiresAt - now) / 1000));
  return { count: parsed.count, ttlSeconds: remainingSec };
}

module.exports = {
  getRedisKeySpec,
  setJsonWithTtl,
  getJson,
  incrementWithTtl
};
