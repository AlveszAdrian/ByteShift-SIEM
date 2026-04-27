// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — Detection Rules Definition
//  Each rule has: id, name, category, severity, regex pattern, description, action
// ══════════════════════════════════════════════════════════════════════════════

const RULES = [
  // ── Authentication ──────────────────────────────────────────────────────────
  { id: 'AUTH-001', name: 'Failed Login Attempt',
    category: 'Authentication', severity: 'WARNING',
    pattern: /failed password|authentication failure|failed login|logon failure|bad password/i,
    description: 'A login attempt failed. Multiple occurrences may indicate brute force.',
    action: 'Check if the source IP is known. Consider blocking after repeated failures.' },

  { id: 'AUTH-002', name: 'Account Lockout',
    category: 'Authentication', severity: 'CRITICAL',
    pattern: /account.*lock(ed|out)|locked out|too many.*attempts/i,
    description: 'An account was locked out after too many failed attempts.',
    action: 'Investigate the source. Verify if the lockout was caused by an attack or a misconfigured service.' },

  { id: 'AUTH-003', name: 'Successful Login After Failures',
    category: 'Authentication', severity: 'WARNING',
    pattern: /successful.*login.*after.*fail|was successfully logged on/i,
    description: 'A successful login occurred, check if preceded by failures.',
    action: 'Correlate with recent failed login events for the same user.' },

  // ── Privilege Escalation ────────────────────────────────────────────────────
  { id: 'PRIV-001', name: 'Privilege Escalation Attempt',
    category: 'Privilege', severity: 'CRITICAL',
    pattern: /sudo|su\s+-|runas|privilege escalation|token elevation|SeDebugPrivilege/i,
    description: 'A privilege escalation command or token elevation was detected.',
    action: 'Verify if the user is authorized for elevated operations.' },

  { id: 'PRIV-002', name: 'New Admin or User Created',
    category: 'Privilege', severity: 'CRITICAL',
    pattern: /user.*created|new.*account|member.*added.*admin|net\s+user\s+.*\/add/i,
    description: 'A new user account was created or added to an admin group.',
    action: 'Confirm this was an authorized change. Audit the creating account.' },

  // ── Malware / Suspicious Activity ───────────────────────────────────────────
  { id: 'MAL-001', name: 'Suspicious Process Execution',
    category: 'Malware', severity: 'CRITICAL',
    pattern: /powershell.*-enc|cmd.*\/c.*whoami|certutil.*-urlcache|bitsadmin.*\/transfer|mimikatz|lazagne/i,
    description: 'A process commonly associated with malware or lateral movement was detected.',
    action: 'Isolate the endpoint immediately. Perform a forensic analysis.' },

  { id: 'MAL-002', name: 'Suspicious Script Execution',
    category: 'Malware', severity: 'CRITICAL',
    pattern: /wscript|cscript|mshta|regsvr32.*\/s|rundll32.*javascript/i,
    description: 'A Windows scripting host or living-off-the-land binary was used.',
    action: 'Review the command line. Check for persistence mechanisms.' },

  // ── Network ─────────────────────────────────────────────────────────────────
  { id: 'NET-001', name: 'Firewall Block',
    category: 'Network', severity: 'WARNING',
    pattern: /firewall.*block|dropped.*packet|denied.*connection|iptables.*DROP/i,
    description: 'The firewall blocked a connection attempt.',
    action: 'Review the blocked IP and port. Check if this is a scan or misconfiguration.' },

  { id: 'NET-002', name: 'Port Scan Detected',
    category: 'Network', severity: 'CRITICAL',
    pattern: /port scan|nmap|masscan|SYN.*flood|connection refused.*multiple/i,
    description: 'Activity consistent with a port scan was detected.',
    action: 'Block the source IP. Investigate for further exploitation attempts.' },

  // ── System ──────────────────────────────────────────────────────────────────
  { id: 'SYS-001', name: 'Service Crash or Stop',
    category: 'System', severity: 'ERROR',
    pattern: /service.*stopped|service.*crash|unexpected.*shutdown|segfault|core dump|blue screen/i,
    description: 'A critical system service stopped or crashed.',
    action: 'Check service logs. Restart the service and monitor for recurrence.' },

  { id: 'SYS-002', name: 'Disk Space Warning',
    category: 'System', severity: 'WARNING',
    pattern: /disk.*space|low.*storage|filesystem.*full|no space left/i,
    description: 'The system is running low on disk space.',
    action: 'Free up disk space. Archive or rotate old logs.' },

  { id: 'SYS-003', name: 'System Error or Fatal',
    category: 'System', severity: 'ERROR',
    pattern: /error|exception|fatal|critical/i,
    description: 'A generic error or fatal event was detected.',
    action: 'Review the full log message for context.' },

  { id: 'SYS-004', name: 'Warning Event',
    category: 'System', severity: 'WARNING',
    pattern: /warn(ing)?/i,
    description: 'A warning-level event was detected.',
    action: 'Monitor for escalation.' },
];

/**
 * Returns a serializable array of rules for the API
 */
export function getRulesForAPI() {
  return RULES.map(r => ({
    id: r.id, name: r.name, category: r.category, severity: r.severity,
    pattern: r.pattern.source, description: r.description, action: r.action,
  }));
}

export default RULES;
