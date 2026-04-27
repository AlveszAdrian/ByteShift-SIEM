// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — Rules Engine
//  Applies detection rules to incoming events and generates alerts
// ══════════════════════════════════════════════════════════════════════════════

import { checkCorrelation } from './correlation.js';
import { forwardToIndexer } from '../services/forwarder.js';
import stats from '../services/stats.js';

let activeRules = [];

/**
 * Update the active ruleset. Converts SQLite regex strings to actual RegExp objects.
 */
export function updateRules(newRules) {
  activeRules = newRules.map(r => ({
    ...r,
    pattern: new RegExp(r.pattern, 'i') // case insensitive
  }));
}

/**
 * Evaluate all rules against a single event.
 * If a rule matches, escalate severity, generate an alert, and check correlation.
 */
export function applyRules(event) {
  stats.events_total++;

  let matchedRule = null;
  for (const rule of activeRules) {
    if (rule.pattern.test(event.message)) {
      event.severity = rule.severity;
      event.metadata = JSON.stringify({
        rule_id: rule.id,
        rule_name: rule.name,
        category: rule.category,
      });
      matchedRule = rule;
      break;
    }
  }

  // Set default severity for raw logs that don't match any rules
  if (!matchedRule && event.severity === 'RAW') {
    event.severity = 'INFO';
  }

  // Track severity stats
  stats.by_severity[event.severity] = (stats.by_severity[event.severity] || 0) + 1;

  // Generate alert if a rule matched
  if (matchedRule) {
    const alert = {
      rule_id: matchedRule.id,
      rule_name: matchedRule.name,
      category: matchedRule.category,
      severity: matchedRule.severity,
      agent_id: event.agent_id,
      source_event: event.message.substring(0, 500),
      description: matchedRule.description,
      recommended_action: matchedRule.action,
      timestamp: Number(event.timestamp) || Math.floor(Date.now() / 1000),
    };
    stats.alerts_total++;
    stats.by_category[matchedRule.category] = (stats.by_category[matchedRule.category] || 0) + 1;
    forwardToIndexer('/api/alerts', alert);
  }

  // Check correlation engine for multi-event patterns
  const correlationAlert = checkCorrelation(event, matchedRule);
  if (correlationAlert) {
    correlationAlert.agent_id = event.agent_id;
    correlationAlert.source_event = event.message.substring(0, 500);
    correlationAlert.timestamp = Math.floor(Date.now() / 1000);
    stats.alerts_total++;
    forwardToIndexer('/api/alerts', correlationAlert);
    console.log(`[CORRELATION] ${correlationAlert.rule_name} from ${event.agent_id}`);
  }

  return event;
}
