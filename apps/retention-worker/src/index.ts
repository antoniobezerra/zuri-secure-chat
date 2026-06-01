import { createHmac } from 'node:crypto';
import { Pool } from 'pg';

type ExpiredRow = {
  id: string;
  queue_id: string;
  created_at: Date | string;
};

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL is required for retention worker.');
}

const pool = new Pool({ connectionString });
const intervalMs = Number(process.env.RETENTION_INTERVAL_MS ?? 60000);

await expireOnce();
setInterval(() => {
  expireOnce().catch((error) => {
    console.error('Retention worker failed.', error);
  });
}, intervalMs);

process.once('SIGTERM', async () => {
  await pool.end();
  process.exit(0);
});

async function expireOnce() {
  const result = await pool.query<ExpiredRow>(
    `DELETE FROM queued_messages
     WHERE expires_at <= now()
     RETURNING id, queue_id, created_at`,
  );

  for (const row of result.rows) {
    const bucketAt = bucketHour(new Date(row.created_at));
    await incrementExpired(row.queue_id, bucketAt);
  }

  if (result.rowCount && result.rowCount > 0) {
    console.log(`Expired ${result.rowCount} queued ciphertext envelope(s).`);
  }
}

async function incrementExpired(queueId: string, bucketAt: Date) {
  const hashed = metricHash(queueId, bucketAt);
  await pool.query(
    `INSERT INTO hourly_metrics (id, bucket_at, metric_hash, expired_count)
     VALUES ($1, $2, $3, 1)
     ON CONFLICT (bucket_at, metric_hash) DO UPDATE
     SET expired_count = hourly_metrics.expired_count + 1,
         updated_at = now()`,
    [`metric_${hashed}`, bucketAt.toISOString(), hashed],
  );
}

function bucketHour(date = new Date()) {
  return new Date(Math.floor(date.getTime() / 3600000) * 3600000);
}

function metricHash(queueId: string, bucketAt: Date) {
  const salt = process.env.METRICS_SALT ?? 'development-metrics-salt';
  return createHmac('sha256', salt).update(queueId).update('|').update(bucketAt.toISOString()).digest('hex');
}

