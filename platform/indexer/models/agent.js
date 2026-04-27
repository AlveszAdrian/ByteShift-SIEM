// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Model de Agentes (TimescaleDB/PostgreSQL)
// ══════════════════════════════════════════════════════════════════════════════

import pool from '../db/postgres.js';

class AgentModel {
  async upsert({ agent_id, hostname, ip_address, os, version, active_collectors }) {
    const collectors = JSON.stringify(active_collectors || []);
    const lastSeen = Math.floor(Date.now() / 1000);

    await pool.query(
      `INSERT INTO agents (agent_id, hostname, ip_address, os, version, active_collectors, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (agent_id) DO UPDATE SET
         hostname = EXCLUDED.hostname,
         ip_address = EXCLUDED.ip_address,
         os = EXCLUDED.os,
         version = EXCLUDED.version,
         active_collectors = EXCLUDED.active_collectors,
         last_seen = EXCLUDED.last_seen`,
      [agent_id, hostname, ip_address, os, version, collectors, lastSeen]
    );
  }

  async getAll() {
    const { rows } = await pool.query(
      `SELECT agent_id, hostname, ip_address, os, version, active_collectors, last_seen
       FROM agents ORDER BY last_seen DESC`
    );
    return rows;
  }
}

export default new AgentModel();
