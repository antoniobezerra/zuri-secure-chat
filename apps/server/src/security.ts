import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';

export function relayId(prefix: string) {
  return `${prefix}_${randomBytes(18).toString('base64url')}`;
}

export function capabilityToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function tokenHash(token: string, pepper = '') {
  return createHash('sha256').update(pepper).update('|').update(token).digest('hex');
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

export function encryptJsonWithSecret(value: unknown, secret: string, pepper: string) {
  const key = secretKey(secret, pepper);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: Buffer.concat([encrypted, tag]).toString('base64url'),
    nonce: nonce.toString('base64url'),
  };
}

export function decryptJsonWithSecret<T>(ciphertext: string, nonce: string, secret: string, pepper: string) {
  const payload = Buffer.from(ciphertext, 'base64url');
  const tag = payload.subarray(payload.length - 16);
  const encrypted = payload.subarray(0, payload.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', secretKey(secret, pepper), Buffer.from(nonce, 'base64url'));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  return JSON.parse(plaintext) as T;
}

function secretKey(secret: string, pepper: string) {
  return createHash('sha256').update(pepper).update('|').update(secret).digest();
}
