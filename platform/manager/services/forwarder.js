// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — Indexer Forwarder Service
//  Handles all HTTP communication with the Indexer microservice
// ══════════════════════════════════════════════════════════════════════════════

import fetch from 'node-fetch';
import { CORRELATION_RULES } from '../rules/correlation.js';

const INDEXER_URL = process.env.INDEXER_URL || 'http://localhost:8081';

/**
 * Forward a payload to the Indexer via HTTP POST
 */
export async function forwardToIndexer(endpoint, payload) {
  try {
    const res = await fetch(`${INDEXER_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) console.error(`[Forwarder] Indexer responded ${res.status} to ${endpoint}`);
  } catch (err) {
    console.error(`[Forwarder] Failed (${endpoint}):`, err.message);
  }
}

/**
 * Fetch all enabled detection rules from the Indexer
 */
export async function fetchRulesFromIndexer() {
  try {
    const res = await fetch(`${INDEXER_URL}/api/rules`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const rules = await res.json();
    return rules.filter(r => r.enabled === 1);
  } catch (err) {
    console.error('[Forwarder] Failed to fetch dynamic rules:', err.message);
    return [];
  }
}
