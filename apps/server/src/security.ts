import { createHash, createHmac, randomBytes } from 'node:crypto';

export function relayId(prefix: string) {
  return `${prefix}_${randomBytes(18).toString('base64url')}`;
}

export function capabilityToken() {
  return randomBytes(32).toString('base64url');
}

export function tokenHash(token: string) {
  return createHash('sha256').update(token).digest('hex');
}

export function bucketHour(date = new Date()) {
  return new Date(Math.floor(date.getTime() / 3600000) * 3600000);
}

export function metricHash(queueId: string, bucketAt: Date) {
  const salt = process.env.METRICS_SALT ?? 'development-metrics-salt';
  return createHmac('sha256', salt).update(queueId).update('|').update(bucketAt.toISOString()).digest('hex');
}

export function ciphertextHash(ciphertext: string) {
  return createHash('sha256').update(ciphertext).digest('hex');
}

