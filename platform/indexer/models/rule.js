// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Model de Regras (TimescaleDB/PostgreSQL)
// ══════════════════════════════════════════════════════════════════════════════

import pool from '../db/postgres.js';

class RuleModel {
  async getAll() {
    const { rows } = await pool.query(
      `SELECT id, name, category, severity, pattern, description, action, enabled
       FROM rules ORDER BY category, severity DESC`
    );
    return rows;
  }

  async getById(id) {
    const { rows } = await pool.query(`SELECT * FROM rules WHERE id = $1`, [id]);
    return rows[0] || null;
  }

  async create(rule) {
    if (!rule.id) {
      rule.id = `CUST-${Date.now().toString().slice(-5)}`;
    }
    const { id, name, category, severity, pattern, description, action, enabled } = rule;
    const { rows } = await pool.query(
      `INSERT INTO rules (id, name, category, severity, pattern, description, action, enabled)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [id, name, category, severity, pattern, description || '', action || '', (enabled === false || enabled === 0) ? 0 : 1]
    );
    return rows[0];
  }

  async update(id, rule) {
    const existing = await this.getById(id);
    if (!existing) return null;

    const merged = { ...existing, ...rule };
    const { name, category, severity, pattern, description, action, enabled } = merged;
    const { rows } = await pool.query(
      `UPDATE rules SET name=$1, category=$2, severity=$3, pattern=$4, description=$5, action=$6, enabled=$7
       WHERE id=$8 RETURNING *`,
      [name, category, severity, pattern, description, action, (enabled === false || enabled === 0) ? 0 : 1, id]
    );
    return rows[0] || null;
  }

  async delete(id) {
    const { rowCount } = await pool.query(`DELETE FROM rules WHERE id = $1`, [id]);
    return rowCount > 0;
  }
}

export default new RuleModel();
