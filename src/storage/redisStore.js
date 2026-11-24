// Adaptateur Redis preparatoire pour OTP et rate limiting
// Utilise la memoire locale tant que REDIS_URL n est pas connecte a un client
const config = require('../config/env');

function getRedisKeySpec() {
  return {
    enabled: Boolean(config.redisUrl),
    otpKeyPrefix: 'cc:otp:', // TTL 300s (JSON: { codeHash, attempts })
    rateLimitPrefix: 'cc:rl:otp:' // TTL 60s (INCR par IP)
  };
}

module.exports = {
  getRedisKeySpec
};
