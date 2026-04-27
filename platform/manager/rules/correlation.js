// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — Correlation Engine
//  Detects patterns across multiple events (e.g. brute force)
// ══════════════════════════════════════════════════════════════════════════════

const BRUTE_FORCE_THRESHOLD  = 5;
const BRUTE_FORCE_WINDOW_SEC = 60;

// Sliding window tracker: agent_id -> [{ ts }]
const failedLoginTracker = new Map();

/**
 * Check if the current event, combined with recent history,
 * triggers a correlation-based alert.
 * @returns {Object|null} A correlation alert or null
 */
export function checkCorrelation(event, matchedRule) {
  // Brute Force: N failed logins in X seconds from same agent
  if (matchedRule && matchedRule.id === 'AUTH-001') {
    const now = Math.floor(Date.now() / 1000);
    const key = event.agent_id;

    if (!failedLoginTracker.has(key)) failedLoginTracker.set(key, []);
    const entries = failedLoginTracker.get(key);
    entries.push({ ts: now });

    // Purge entries outside the sliding window
    const cutoff = now - BRUTE_FORCE_WINDOW_SEC;
    while (entries.length > 0 && entries[0].ts < cutoff) entries.shift();

    if (entries.length >= BRUTE_FORCE_THRESHOLD) {
      failedLoginTracker.delete(key); // Reset after alert
      return {
        rule_id: 'COR-001',
        rule_name: 'Brute Force Attack Detected',
        category: 'Correlation',
        severity: 'CRITICAL',
        description: `${entries.length} failed login attempts from agent "${key}" in the last ${BRUTE_FORCE_WINDOW_SEC}s.`,
        action: 'Block the source IP immediately. Investigate for compromised credentials.',
      };
    }
  }

  return null;
}

/** Metadata for registering this rule with the Indexer */
export const CORRELATION_RULES = [
  {
    id: 'COR-001', name: 'Brute Force Attack Detected', category: 'Correlation',
    severity: 'CRITICAL',
    pattern: `${BRUTE_FORCE_THRESHOLD}+ failed logins in ${BRUTE_FORCE_WINDOW_SEC}s`,
    description: 'Correlates multiple AUTH-001 events from the same agent.',
    action: 'Block the source IP immediately.',
  },
];
