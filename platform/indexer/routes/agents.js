// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Rotas de Agentes (PostgreSQL)
// ══════════════════════════════════════════════════════════════════════════════

import express from 'express';
import AgentModel from '../models/agent.js';

const router = express.Router();

/**
 * POST /api/agent/heartbeat
 * Recebe o heartbeat de um agente e atualiza seus metadados
 */
router.post('/agent/heartbeat', async (req, res, next) => {
  try {
    await AgentModel.upsert(req.body);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/agents
 * Lista todos os agentes registrados
 */
router.get('/agents', async (req, res, next) => {
  try {
    const agents = await AgentModel.getAll();
    res.json(agents);
  } catch (err) {
    next(err);
  }
});

export default router;
