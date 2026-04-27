// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Rotas de Alertas (PostgreSQL)
// ══════════════════════════════════════════════════════════════════════════════

import express from 'express';
import AlertModel from '../models/alert.js';

const router = express.Router();

/**
 * POST /api/alerts
 * Recebe um novo alerta gerado pelo motor de detecção do Manager
 */
router.post('/alerts', async (req, res, next) => {
  try {
    const a = req.body;
    if (!a.rule_id) return res.status(400).json({ error: 'rule_id é obrigatório' });
    await AlertModel.insert(a);
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/alerts
 * Lista alertas com filtros opcionais (status, severity, category)
 */
router.get('/alerts', async (req, res, next) => {
  try {
    const rows = await AlertModel.getAll(req.query);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

/**
 * PUT /api/alerts/:id/status
 * Atualiza o ciclo de vida do alerta (open → acknowledged → closed)
 */
router.put('/alerts/:id/status', async (req, res, next) => {
  try {
    const { status } = req.body;
    const valid = ['open', 'acknowledged', 'closed'];

    if (!valid.includes(status)) {
      return res.status(400).json({ error: `Status deve ser: ${valid.join(', ')}` });
    }

    const updated = await AlertModel.updateStatus(req.params.id, status);
    if (!updated) return res.status(404).json({ error: 'Alerta não encontrado' });

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;
