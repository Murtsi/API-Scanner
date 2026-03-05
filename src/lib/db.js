const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Railway's encrypted connections
  }
});

const query = (text, params) => pool.query(text, params);

module.exports = { query };
