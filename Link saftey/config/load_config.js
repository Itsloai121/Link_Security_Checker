function loadConfig(env = process.env) {
  const integer = (name, fallback, min, max) => {
    const raw = env[name];
    if (raw === undefined || raw === '') return fallback;
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`Invalid ${name}; expected an integer from ${min} to ${max}.`);
    return value;
  };
  const environment = env.NODE_ENV || 'development';
  if (!['development', 'test', 'production'].includes(environment)) throw new Error('NODE_ENV must be development, test, or production.');
  const projectRoot = require('node:path').resolve(__dirname, '..');
  const dbSetting = env.DATABASE_PATH || './var/link-safety.sqlite';
  return Object.freeze({
    environment,
    port: integer('PORT', 3000, 1, 65535),
    bindAddress: env.BIND_ADDRESS || '127.0.0.1',
    databasePath: dbSetting === ':memory:' ? dbSetting : require('node:path').resolve(projectRoot, dbSetting),
    maxBodyBytes: integer('MAX_BODY_BYTES', 8192, 1024, 65536),
    maxUrlLength: integer('MAX_URL_LENGTH', 4096, 128, 16384),
    rateLimitWindowMs: integer('RATE_LIMIT_WINDOW_MS', 60000, 1000, 3600000),
    rateLimitMaxRequests: integer('RATE_LIMIT_MAX_REQUESTS', 20, 1, 10000),
    dataRetentionDays: integer('DATA_RETENTION_DAYS', 30, 1, 3650),
    phishtankAppKey: env.PHISHTANK_APP_KEY || '',
    migrationDirectory: require('node:path').resolve(projectRoot, 'migrations'),
    publicDirectory: require('node:path').resolve(projectRoot, 'public')
  });
}
module.exports = { loadConfig };

