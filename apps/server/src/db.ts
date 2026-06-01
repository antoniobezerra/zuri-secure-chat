import { Pool, type QueryResultRow } from 'pg';

export class Database {
  private readonly pool: Pool;

  constructor(connectionString = process.env.DATABASE_URL) {
    if (!connectionString) {
      throw new Error('DATABASE_URL is required for zuri-secure-chat relay.');
    }
    this.pool = new Pool({
      connectionString,
      max: Number(process.env.DATABASE_POOL_MAX ?? 8),
    });
  }

  query<T extends QueryResultRow>(text: string, params: unknown[] = []) {
    return this.pool.query<T>(text, params);
  }

  async health() {
    const result = await this.query<{ ok: number }>('SELECT 1 AS ok');
    return Boolean(result.rows[0]?.ok);
  }

  async close() {
    await this.pool.end();
  }
}

