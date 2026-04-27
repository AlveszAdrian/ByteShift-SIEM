// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Rotas de Estatísticas (PostgreSQL Aggregations)
// ══════════════════════════════════════════════════════════════════════════════

import express from 'express';
import pool from '../db/postgres.js';

const router = express.Router();

/**
 * GET /api/stats/overview
 * Retorna os KPIs principais do dashboard usando agregações nativas do PostgreSQL
 */
router.get('/stats/overview', async (req, res, next) => {
  try {
    const now = Math.floor(Date.now() / 1000);
    const oneHourAgo = new Date(Date.now() - 3600 * 1000);
    const oneDayAgo  = new Date(Date.now() - 86400 * 1000);
    const twoMinAgo  = now - 120;

    const [
      eventsTotal,
      eventsLastHour,
      eventsLastDay,
      bySeverity,
      alertsTotal,
      alertsOpen,
      alertsCriticalOpen,
      agentsTotal,
      agentsActive,
    ] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM events`),
      pool.query(`SELECT COUNT(*) FROM events WHERE time > $1`, [oneHourAgo]),
      pool.query(`SELECT COUNT(*) FROM events WHERE time > $1`, [oneDayAgo]),
      pool.query(`SELECT severity, COUNT(*) as count FROM events GROUP BY severity ORDER BY count DESC`),
      pool.query(`SELECT COUNT(*) FROM alerts`),
      pool.query(`SELECT COUNT(*) FROM alerts WHERE status = 'open'`),
      pool.query(`SELECT COUNT(*) FROM alerts WHERE status = 'open' AND severity = 'CRITICAL'`),
      pool.query(`SELECT COUNT(*) FROM agents`),
      pool.query(`SELECT COUNT(*) FROM agents WHERE last_seen > $1`, [twoMinAgo]),
    ]);

    res.json({
      events: {
        total:      parseInt(eventsTotal.rows[0].count,       10),
        last_hour:  parseInt(eventsLastHour.rows[0].count,    10),
        last_day:   parseInt(eventsLastDay.rows[0].count,     10),
        by_severity: bySeverity.rows.map(r => ({ severity: r.severity, count: parseInt(r.count, 10) })),
      },
      alerts: {
        total:         parseInt(alertsTotal.rows[0].count,        10),
        open:          parseInt(alertsOpen.rows[0].count,         10),
        critical_open: parseInt(alertsCriticalOpen.rows[0].count, 10),
      },
      agents: {
        total:  parseInt(agentsTotal.rows[0].count,  10),
        active: parseInt(agentsActive.rows[0].count, 10),
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/stats/timeline
 * Retorna a série temporal das últimas 24h agrupada por hora
 */
router.get('/stats/timeline', async (req, res, next) => {
  try {
    const oneDayAgo = new Date(Date.now() - 86400 * 1000);

    const { rows } = await pool.query(`
      SELECT
        EXTRACT(EPOCH FROM date_trunc('hour', time))::bigint AS timestamp,
        severity,
        COUNT(*) AS count
      FROM events
      WHERE time > $1
      GROUP BY date_trunc('hour', time), severity
      ORDER BY date_trunc('hour', time)
    `, [oneDayAgo]);

    // Pivotar para o formato esperado pelo frontend
    const byHour = {};
    for (const row of rows) {
      const ts = row.timestamp;
      if (!byHour[ts]) byHour[ts] = { timestamp: ts };
      byHour[ts][row.severity] = parseInt(row.count, 10);
    }

    res.json(Object.values(byHour));
  } catch (err) {
    next(err);
  }
});

export default router;
