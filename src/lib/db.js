
let pool;
async function getPool() {
  if (!pool) {
    const pg = await import('pg');
    pool = new pg.Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: {
        rejectUnauthorized: false // Required for Railway's encrypted connections
      }
    });
  }
  return pool;
}

export async function query(text, params) {
  const pool = await getPool();
  return pool.query(text, params);
}
