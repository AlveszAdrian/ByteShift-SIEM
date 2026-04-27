// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Rotas de Regras (PostgreSQL)
//  CRUD completo para gerenciamento dinâmico de regras de detecção
// ══════════════════════════════════════════════════════════════════════════════

import express from 'express';
import RuleModel from '../models/rule.js';

const router = express.Router();

/**
 * GET /api/rules
 * Retorna todas as regras. Usado pelo Dashboard (visualização) e Manager (polling)
 */
router.get('/rules', async (req, res, next) => {
  try {
    const rules = await RuleModel.getAll();
    res.json(rules);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/rules
 * Cria uma nova regra de detecção
 */
router.post('/rules', async (req, res, next) => {
  try {
    const { name, category, severity, pattern, description, action, enabled } = req.body;
    
    if (!name || !pattern || !severity || !category) {
      return res.status(400).json({ error: 'Campos obrigatórios: name, pattern, severity, category' });
    }

    const newRule = await RuleModel.create({ name, category, severity, pattern, description, action, enabled });
    res.status(201).json(newRule);
  } catch (err) {
    next(err);
  }
});

/**
 * PUT /api/rules/:id
 * Atualiza uma regra existente
 */
router.put('/rules/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const ruleData = req.body;
    delete ruleData.id; // Impede modificação do ID

    const updated = await RuleModel.update(id, ruleData);
    if (!updated) return res.status(404).json({ error: 'Regra não encontrada' });

    res.json(updated);
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/rules/:id
 * Remove uma regra de detecção
 */
router.delete('/rules/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const deleted = await RuleModel.delete(id);
    if (!deleted) return res.status(404).json({ error: 'Regra não encontrada' });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

export default router;
