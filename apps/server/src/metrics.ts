import { type Database } from './db.js';
import { metricHash } from './security.js';

export async function incrementMetric(
  db: Database,
  queueId: string,
  bucketAt: Date,
  metric: 'enqueued_count' | 'delivered_count' | 'expired_count',
  by = 1,
) {
  const id = `metric_${metricHash(queueId, bucketAt)}`;
  const hashed = metricHash(queueId, bucketAt);
  const column = metric;

  await db.query(
    `INSERT INTO hourly_metrics (id, bucket_at, metric_hash, ${column})
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (bucket_at, metric_hash) DO UPDATE
     SET ${column} = hourly_metrics.${column} + EXCLUDED.${column},
         updated_at = now()`,
    [id, bucketAt.toISOString(), hashed, by],
  );
}

