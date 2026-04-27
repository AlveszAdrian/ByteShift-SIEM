// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — generic API middlewares
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Basic error handling middleware for unresolved routes or internal errors
 */
export function errorHandler(err, req, res, next) {
  console.error('[Indexer] Error:', err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
}

export function notFoundHandler(req, res, next) {
  res.status(404).json({ error: 'Endpoint not found' });
}
