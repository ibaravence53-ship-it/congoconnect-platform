const config = require('../config/env');

const memoryStore = new Map();
let redisClient = null;
let redisConnectPromise = null;
let redisUnavailable = false;

function getRedisKeySpec() {
  return {
    enabled: Boolean(config.redisUrl),
    otpKeyPrefix: 'cc:otp:',
    rateLimitPrefix: 'cc:rl:otp:'
  };
}

async function getRedisClient() {
  if (!config.redisUrl || redisUnavailable) return null;
  if (redisClient && redisClient.isOpen) return redisClient;

  if (!redisConnectPromise) {
    redisConnectPromise = (async () => {
      try {
        const { createClient } = require('redis');
        const client = createClient({ url: config.redisUrl });
        client.on('error', () => {
          redisUnavailable = true;
        });
        await client.connect();
        redisClient = client;
        return redisClient;
      } catch (_) {
        redisUnavailable = true;
        return null;
      } finally {
        redisConnectPromise = null;
      }
    })();
  }

  return redisConnectPromise;
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
  const client = await getRedisClient();
  if (client) {
    try {
      const serialized = JSON.stringify(value);
      if (ttlSeconds > 0) {
        await client.set(key, serialized, { EX: ttlSeconds });
      } else {
        await client.set(key, serialized);
      }
      return;
    } catch (_) {
      redisUnavailable = true;
    }
  }

  purgeExpired();
  const expiresAt = ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null;
  memoryStore.set(key, { value: JSON.stringify(value), expiresAt });
}

async function getJson(key) {
  const client = await getRedisClient();
  if (client) {
    try {
      const raw = await client.get(key);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (_) {
      redisUnavailable = true;
    }
  }

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
  const client = await getRedisClient();
  if (client) {
    try {
      const count = await client.incr(key);
      if (count === 1 && ttlSeconds > 0) {
        await client.expire(key, ttlSeconds);
      }
      const ttl = ttlSeconds > 0 ? await client.ttl(key) : -1;
      return {
        count,
        ttlSeconds: ttl > 0 ? ttl : ttlSeconds
      };
    } catch (_) {
      redisUnavailable = true;
    }
  }

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
