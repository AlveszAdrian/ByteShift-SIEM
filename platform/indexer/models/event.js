// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Model de Eventos (TimescaleDB/PostgreSQL)
// ══════════════════════════════════════════════════════════════════════════════

import pool from '../db/postgres.js';

class EventModel {
  /**
   * Insere um novo evento no banco de dados.
   */
  async insert({ agent_id, log_type, severity, message, metadata, timestamp }) {
    const time = timestamp
      ? new Date(timestamp > 1e11 ? timestamp : timestamp * 1000)
      : new Date();

    const { rows } = await pool.query(
      `INSERT INTO events (time, agent_id, log_type, severity, message, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [time, agent_id, log_type || 'generic', severity || 'INFO', message, metadata || null]
    );
    return rows[0];
  }

  /**
   * Retorna os N eventos mais recentes.
   */
  async getRecent(limit = 50) {
    const { rows } = await pool.query(
      `SELECT id, EXTRACT(EPOCH FROM time)::bigint AS timestamp, agent_id, log_type, severity, message, metadata
       FROM events
       ORDER BY time DESC
       LIMIT $1`,
      [limit]
    );
    return rows;
  }

  /**
   * Busca full-text e filtros com paginação.
   */
  async search({ q, severity, agent_id, log_type, page = 1, per_page = 50 }) {
    const conditions = [];
    const params = [];

    if (q) {
      params.push(q);
      conditions.push(`to_tsvector('english', message) @@ plainto_tsquery('english', $${params.length})`);
    }
    if (severity) {
      params.push(severity);
      conditions.push(`severity = $${params.length}`);
    }
    if (agent_id) {
      params.push(agent_id);
      conditions.push(`agent_id = $${params.length}`);
    }
    if (log_type) {
      params.push(log_type);
      conditions.push(`log_type = $${params.length}`);
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const offset = (page - 1) * per_page;

    const [dataRes, countRes] = await Promise.all([
      pool.query(
        `SELECT id, EXTRACT(EPOCH FROM time)::bigint AS timestamp, agent_id, log_type, severity, message
         FROM events ${where}
         ORDER BY time DESC
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, per_page, offset]
      ),
      pool.query(`SELECT COUNT(*) FROM events ${where}`, params),
    ]);

    return {
      data: dataRes.rows,
      pagination: {
        total: parseInt(countRes.rows[0].count, 10),
        page,
        per_page,
        total_pages: Math.ceil(parseInt(countRes.rows[0].count, 10) / per_page),
      },
    };
  }
}

export default new EventModel();
