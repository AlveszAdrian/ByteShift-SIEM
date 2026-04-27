// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Entry Point
//  Bootstraps the Express server, applies middlewares, and mounts routes
// ══════════════════════════════════════════════════════════════════════════════

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

// Central DB init — conecta ao TimescaleDB e cria o schema
import { initDb } from './db/postgres.js';

// Route modules
import eventsRoutes from './routes/events.js';
import alertsRoutes from './routes/alerts.js';
import agentsRoutes from './routes/agents.js';
import rulesRoutes  from './routes/rules.js';
import sigmaRoutes  from './routes/sigma-rules.js';
import statsRoutes  from './routes/stats.js';

// Middlewares
import { errorHandler, notFoundHandler } from './middleware/error.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8081;

const app = express();

// ── Global Middlewares ────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '5mb' }));

// ── API Routes Mounts ─────────────────────────────────────────────────────────
app.use('/api', eventsRoutes);  // /api/ingest, /api/events/recent, /api/search
app.use('/api', alertsRoutes);  // /api/alerts, /api/alerts/:id/status
app.use('/api', agentsRoutes);  // /api/agent/heartbeat, /api/agents
app.use('/api', rulesRoutes);   // /api/rules
app.use('/api', sigmaRoutes);   // /api/sigma-rules
app.use('/api', statsRoutes);   // /api/stats/overview, /api/stats/timeline

// ── Dashboard Static Files ────────────────────────────────────────────────────
app.use('/', express.static(path.join(__dirname, '..', 'dashboard', 'dist')));

// ── Error Handling ────────────────────────────────────────────────────────────
app.use('/api', notFoundHandler);
app.use(errorHandler);

// ── Start Server (aguarda TimescaleDB) ───────────────────────────────────────
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`[Indexer] API + Dashboard listening on :${PORT}`);
  });
}).catch(err => {
  console.error('[Indexer] Erro fatal ao conectar ao banco de dados:', err.message);
  process.exit(1);
});
