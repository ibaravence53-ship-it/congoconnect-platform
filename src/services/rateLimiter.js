const DEFAULT_WINDOW_MS = 60 * 1000;
const DEFAULT_MAX_REQUESTS = 30;
const buckets = new Map();

function checkRateLimit(key, maxRequests = DEFAULT_MAX_REQUESTS, windowMs = DEFAULT_WINDOW_MS) {
  const bucketKey = typeof key === 'string' && key.trim() ? key.trim() : 'anonymous';
  const now = Date.now();
  const current = buckets.get(bucketKey);

  if (!current || now > current.resetAt) {
    const resetAt = now + windowMs;
    buckets.set(bucketKey, { count: 1, resetAt });
    return {
      allowed: true,
      limit: maxRequests,
      remaining: Math.max(0, maxRequests - 1),
      resetAt: new Date(resetAt).toISOString()
    };
  }

  if (current.count >= maxRequests) {
    const retryAfterSeconds = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
    return {
      allowed: false,
      limit: maxRequests,
      remaining: 0,
      retryAfterSeconds,
      resetAt: new Date(current.resetAt).toISOString()
    };
  }

  current.count += 1;
  return {
    allowed: true,
    limit: maxRequests,
    remaining: Math.max(0, maxRequests - current.count),
    resetAt: new Date(current.resetAt).toISOString()
  };
}

module.exports = {
  checkRateLimit
};
