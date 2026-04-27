// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Rotas de Eventos com Motor de Detecção + Log Parser
// ══════════════════════════════════════════════════════════════════════════════

import express from 'express';
import EventModel from '../models/event.js';
import AlertModel from '../models/alert.js';
import RuleModel from '../models/rule.js';
import { parseLogMessage } from '../services/parser.js';
import pool from '../db/postgres.js';

const router = express.Router();

// ── Rule Matching + Alert Generation ─────────────────────────────────────────
import { sigmaEngine } from '../services/sigma-engine.js';

async function applyRulesAndAlert(event) {
  // Parse structured fields from the raw message
  const parsed = parseLogMessage(event.message || '');
  event.fields = parsed; // Inject into event for Sigma Engine

  // Evaluate against SIGMA rules
  const matchedRules = sigmaEngine.evaluate(event);

  if (matchedRules.length > 0) {
    // Take the first matching rule (in a real EDR we might process all, but let's keep one alert per event for simplicity)
    const rule = matchedRules[0];
    const severity = (rule.level || 'WARNING').toUpperCase();

    // Upgrade severity
    event.severity = severity;
    event.metadata = JSON.stringify({
      rule_id: rule.id,
      rule_name: rule.title,
      category: rule.logsource?.category || 'Security',
    });

    // Generate alert
    try {
      await AlertModel.insert({
        rule_id: rule.id,
        rule_name: rule.title,
        category: rule.logsource?.category || 'Security',
        severity: severity,
        agent_id: event.agent_id,
        source_event: (event.message || '').substring(0, 500),
        description: rule.description || '',
        recommended_action: rule.action || 'Investigate immediately',
        timestamp: Number(event.timestamp) || Math.floor(Date.now() / 1000),
      });
    } catch (err) {
      console.error('[Alert] Failed to create alert:', err.message);
    }
  }

  // Merge rule metadata with parsed fields for backwards compat
  const existing = event.metadata ? (() => { try { return JSON.parse(event.metadata); } catch { return {}; } })() : {};
  event.metadata = JSON.stringify({ ...existing, ...parsed });

  return event;
}

/**
 * POST /api/ingest
 * Single event ingestion with rule detection
 */
router.post('/ingest', async (req, res, next) => {
  try {
    const e = req.body;
    if (!e.agent_id || !e.message) {
      return res.status(400).json({ error: 'Payload inválido: agent_id e message são obrigatórios' });
    }
    const processed = await applyRulesAndAlert(e);
    await EventModel.insert(processed);
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/ingest/bulk
 * Bulk event ingestion with rule detection on each event
 */
router.post('/ingest/bulk', async (req, res, next) => {
  try {
    const events = req.body;
    if (!Array.isArray(events)) {
      return res.status(400).json({ error: 'Esperado um array de eventos' });
    }
    // Apply rules and generate alerts for each event
    const processed = await Promise.all(events.map(e => applyRulesAndAlert(e)));
    await Promise.all(processed.map(e => EventModel.insert(e)));
    res.status(201).json({ ok: true, count: events.length });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/events/recent/:minutes
 * Recent events for the live dashboard
 */
router.get('/events/recent/:minutes?', async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const rows = await EventModel.getRecent(limit);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/events/:id
 * Returns a single event with full details and parsed fields
 */
router.get('/events/:id', async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, EXTRACT(EPOCH FROM time)::bigint AS timestamp, agent_id, log_type, severity, message, metadata
       FROM events WHERE id = $1 LIMIT 1`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Event not found' });
    const event = rows[0];
    // Parse metadata JSON and include parsed fields
    let parsed = {};
    try { parsed = JSON.parse(event.metadata || '{}'); } catch {}
    // Re-parse the message for events that were ingested before the parser existed
    if (!parsed.raw_length) {
      const freshParsed = parseLogMessage(event.message);
      parsed = { ...parsed, ...freshParsed };
    }
    res.json({ ...event, parsed_fields: parsed });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/search
 * Full-text search with pagination via PostgreSQL GIN index
 */
router.get('/search', async (req, res, next) => {
  try {
    const result = await EventModel.search(req.query);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

export default router;
