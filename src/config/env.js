const config = {
  port: Number.parseInt(process.env.PORT || '3000', 10) || 3000,
  hideOtpInResponse: process.env.HIDE_OTP_IN_RESPONSE === 'true',
  tokenSecret: process.env.CONGOCONNECT_TOKEN_SECRET || 'dev-congoconnect-change-in-prod',
  redisUrl: (process.env.REDIS_URL || '').trim(),
  databaseUrl: (process.env.DATABASE_URL || '').trim()
};

config.storageMode = {
  otp: config.redisUrl ? 'redis' : 'memory',
  audit: config.databaseUrl ? 'postgres' : 'memory+file'
};

module.exports = config;
