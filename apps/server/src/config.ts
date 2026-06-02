function numberEnv(name: string, fallback: number) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be a non-negative number.`);
  }
  return value;
}

function booleanEnv(name: string, fallback: boolean) {
  const raw = process.env[name];
  if (!raw) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

export const serverConfig = {
  inviteTtlSeconds: numberEnv('INVITE_TTL_SECONDS', 600),
  inviteOneTime: booleanEnv('INVITE_ONE_TIME', true),
  inviteMaxAttempts: numberEnv('INVITE_MAX_ATTEMPTS', 5),
  tokenBytes: numberEnv('TOKEN_BYTES', 32),
  hashPepper: process.env.HASH_PEPPER ?? process.env.METRICS_SALT ?? 'development-hash-pepper',
  logQueryString: booleanEnv('LOG_QUERY_STRING', false),
  messageTtlDays: numberEnv('MESSAGE_TTL_DAYS', 30),
  deliveredDeleteImmediately: booleanEnv('DELIVERED_DELETE_IMMEDIATELY', true),
  metricsRetentionDays: numberEnv('METRICS_RETENTION_DAYS', 90),
  ipLogRetentionHours: numberEnv('IP_LOG_RETENTION_HOURS', 24),
  maxWebsocketPayloadBytes: numberEnv('MAX_WEBSOCKET_PAYLOAD_BYTES', 524288),
  maxMessageBytes: numberEnv('MAX_MESSAGE_BYTES', 262144),
  maxPendingMessagesPerQueue: numberEnv('MAX_PENDING_MESSAGES_PER_QUEUE', 500),
  rateLimitWindowSeconds: numberEnv('RATE_LIMIT_WINDOW_SECONDS', 60),
  rateLimitMaxEvents: numberEnv('RATE_LIMIT_MAX_EVENTS', 120),
  adminToken: process.env.ADMIN_TOKEN,
};
