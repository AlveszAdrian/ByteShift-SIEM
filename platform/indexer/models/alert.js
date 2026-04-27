// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Model de Alertas (TimescaleDB/PostgreSQL)
// ══════════════════════════════════════════════════════════════════════════════

import pool from '../db/postgres.js';

class AlertModel {
  async insert(alert) {
    const { rule_id, rule_name, category, severity, agent_id, source_event, description, recommended_action, timestamp } = alert;
    const time = timestamp ? new Date(timestamp * 1000) : new Date();

    const { rows } = await pool.query(
      `INSERT INTO alerts (time, rule_id, rule_name, category, severity, agent_id, source_event, description, recommended_action)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [time, rule_id, rule_name, category, severity, agent_id, source_event, description, recommended_action]
    );
    return rows[0];
  }

  async getAll({ status, severity, category, limit = 100 }) {
    const conditions = [];
    const params = [];

    if (status)   { params.push(status);   conditions.push(`status = $${params.length}`); }
    if (severity) { params.push(severity); conditions.push(`severity = $${params.length}`); }
    if (category) { params.push(category); conditions.push(`category = $${params.length}`); }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    params.push(limit);

    const { rows } = await pool.query(
      `SELECT id, EXTRACT(EPOCH FROM time)::bigint AS timestamp, rule_id, rule_name, category,
              severity, agent_id, source_event, description, recommended_action, status
       FROM alerts ${where}
       ORDER BY time DESC
       LIMIT $${params.length}`,
      params
    );
    return rows;
  }

  async updateStatus(id, status) {
    const { rowCount } = await pool.query(
      `UPDATE alerts SET status = $1 WHERE id = $2`,
      [status, id]
    );
    return rowCount > 0;
  }
}

export default new AlertModel();
