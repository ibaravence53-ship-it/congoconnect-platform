const { getRedisKeySpec, incrementWithTtl } = require('../storage/redisStore');

const DEFAULT_WINDOW_MS = 60 * 1000;
const DEFAULT_MAX_REQUESTS = 30;
const buckets = new Map();

function buildResult(allowed, maxRequests, count, resetAtMs, nowMs) {
  const remaining = allowed ? Math.max(0, maxRequests - count) : 0;
  const result = {
    allowed,
    limit: maxRequests,
    remaining,
    resetAt: new Date(resetAtMs).toISOString()
  };

  if (!allowed) {
    result.retryAfterSeconds = Math.max(1, Math.ceil((resetAtMs - nowMs) / 1000));
  }

  return result;
}

function checkRateLimit(key, maxRequests = DEFAULT_MAX_REQUESTS, windowMs = DEFAULT_WINDOW_MS) {
  const bucketKey = typeof key === 'string' && key.trim() ? key.trim() : 'anonymous';
  const now = Date.now();
  const current = buckets.get(bucketKey);

  if (!current || now > current.resetAt) {
    const resetAt = now + windowMs;
    buckets.set(bucketKey, { count: 1, resetAt });
    return buildResult(true, maxRequests, 1, resetAt, now);
  }

  if (current.count >= maxRequests) {
    return buildResult(false, maxRequests, current.count, current.resetAt, now);
  }

  current.count += 1;
  return buildResult(true, maxRequests, current.count, current.resetAt, now);
}

async function checkRateLimitAsync(key, maxRequests = DEFAULT_MAX_REQUESTS, windowMs = DEFAULT_WINDOW_MS) {
  const bucketKey = typeof key === 'string' && key.trim() ? key.trim() : 'anonymous';
  const spec = getRedisKeySpec();
  const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000));
  const redisKey = `${spec.rateLimitPrefix}${bucketKey}`;

  try {
    const res = await incrementWithTtl(redisKey, ttlSeconds);
    const now = Date.now();
    const resetAtMs = now + (res.ttlSeconds || ttlSeconds) * 1000;
    const allowed = res.count <= maxRequests;
    return buildResult(allowed, maxRequests, res.count, resetAtMs, now);
  } catch (_) {
    return checkRateLimit(bucketKey, maxRequests, windowMs);
  }
}

module.exports = {
  checkRateLimit,
  checkRateLimitAsync
};
