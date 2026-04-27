// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — In-Memory Statistics
// ══════════════════════════════════════════════════════════════════════════════

const stats = {
  events_total: 0,
  alerts_total: 0,
  by_severity: {},
  by_category: {},
};

export default stats;
