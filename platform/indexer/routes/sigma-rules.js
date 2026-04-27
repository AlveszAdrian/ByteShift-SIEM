import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import { sigmaEngine } from '../services/sigma-engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const router = express.Router();
const RULES_DIR = path.join(__dirname, '..', 'rules');

// GET all rules
router.get('/sigma-rules', (req, res) => {
  try {
    const rules = sigmaEngine.getRules();
    res.json(rules);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET single rule
router.get('/sigma-rules/:id', (req, res) => {
  const rule = sigmaEngine.getRule(req.params.id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });
  
  // Try to read raw yaml
  try {
    const rawYaml = fs.readFileSync(rule._filePath, 'utf8');
    res.json({ ...rule, rawYaml });
  } catch (err) {
    res.json(rule);
  }
});

// POST new rule
router.post('/sigma-rules', (req, res) => {
  try {
    const { yamlContent } = req.body;
    if (!yamlContent) return res.status(400).json({ error: 'YAML content is required' });

    // Validate YAML
    const rule = yaml.load(yamlContent);
    if (!rule || !rule.id) return res.status(400).json({ error: 'Invalid Sigma rule: missing id' });

    const filePath = path.join(RULES_DIR, `${rule.id}.yml`);
    if (fs.existsSync(filePath)) {
      return res.status(409).json({ error: 'Rule with this ID already exists' });
    }

    fs.writeFileSync(filePath, yamlContent, 'utf8');
    
    // Engine watches dir and loads automatically, but we can return ok immediately
    res.status(201).json({ ok: true, id: rule.id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// PUT update rule
router.put('/sigma-rules/:id', (req, res) => {
  try {
    const { id } = req.params;
    const { yamlContent } = req.body;
    if (!yamlContent) return res.status(400).json({ error: 'YAML content is required' });

    const rule = sigmaEngine.getRule(id);
    if (!rule) return res.status(404).json({ error: 'Rule not found' });

    // Validate new YAML
    const newParsed = yaml.load(yamlContent);
    if (!newParsed || newParsed.id !== id) {
       return res.status(400).json({ error: 'Invalid Sigma rule: ID cannot be changed' });
    }

    fs.writeFileSync(rule._filePath, yamlContent, 'utf8');
    res.json({ ok: true, id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// DELETE rule
router.delete('/sigma-rules/:id', (req, res) => {
  try {
    const { id } = req.params;
    const rule = sigmaEngine.getRule(id);
    if (!rule) return res.status(404).json({ error: 'Rule not found' });

    fs.unlinkSync(rule._filePath);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST test rule
router.post('/sigma-rules/test', async (req, res) => {
  try {
    const { yamlContent } = req.body;
    if (!yamlContent) return res.status(400).json({ error: 'YAML content is required' });

    const tempRule = yaml.load(yamlContent);
    if (!tempRule || !tempRule.detection) {
        return res.status(400).json({ error: 'Invalid Sigma rule' });
    }

    // Fetch recent events to test against
    const { default: EventModel } = await import('../models/event.js');
    const recentEvents = await EventModel.getRecent(100);
    
    const matches = [];
    for (const e of recentEvents) {
      // Re-hydrate fields if needed
      if (!e.fields && e.metadata) {
         try { e.fields = JSON.parse(e.metadata); } catch {}
      }
      if (sigmaEngine.evaluateRule(tempRule, e)) {
        matches.push(e);
      }
    }
    
    res.json({ ok: true, matchCount: matches.length, matches });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

export default router;
