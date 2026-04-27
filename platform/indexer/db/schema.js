// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Database Schema & Connection
//  SQLite setup with WAL mode for concurrent read/write
// ══════════════════════════════════════════════════════════════════════════════

import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', '..', 'siem_data.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ── Create tables ─────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id  TEXT,
    os        TEXT,
    log_type  TEXT,
    severity  TEXT,
    message   TEXT,
    timestamp INTEGER,
    metadata  TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ts        ON events(timestamp);
  CREATE INDEX IF NOT EXISTS idx_sev       ON events(severity);
  CREATE INDEX IF NOT EXISTS idx_agent     ON events(agent_id);
  CREATE INDEX IF NOT EXISTS idx_log_type  ON events(log_type);

  CREATE TABLE IF NOT EXISTS alerts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id            TEXT,
    rule_name          TEXT,
    category           TEXT,
    severity           TEXT,
    agent_id           TEXT,
    source_event       TEXT,
    description        TEXT,
    recommended_action TEXT,
    status             TEXT DEFAULT 'open',
    timestamp          INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_alert_ts     ON alerts(timestamp);
  CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
  CREATE INDEX IF NOT EXISTS idx_alert_sev    ON alerts(severity);

  CREATE TABLE IF NOT EXISTS agents (
    agent_id          TEXT PRIMARY KEY,
    os                TEXT,
    ip_address        TEXT,
    hostname          TEXT,
    uptime            INTEGER,
    version           TEXT,
    active_collectors TEXT,
    last_seen         INTEGER
  );

  CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    category    TEXT,
    severity    TEXT,
    pattern     TEXT,
    description TEXT,
    action      TEXT,
    enabled     INTEGER DEFAULT 1
  );
`);

// ── Seed Default Rules ────────────────────────────────────────────────────────
const ruleCount = db.prepare('SELECT COUNT(*) as c FROM rules').get().c;
if (ruleCount === 0) {
  console.log('[DB] Seeding default detection rules...');
  const insertRule = db.prepare(`
    INSERT INTO rules (id, name, category, severity, pattern, description, action)
    VALUES (@id, @name, @category, @severity, @pattern, @description, @action)
  `);

  const defaults = [
    { id: 'AUTH-001', name: 'Failed Login Attempt', category: 'Authentication', severity: 'WARNING', pattern: 'failed password|authentication failure|failed login|logon failure|bad password', description: 'A login attempt failed.', action: 'Check if the source IP is known.' },
    { id: 'AUTH-002', name: 'Account Lockout', category: 'Authentication', severity: 'CRITICAL', pattern: 'account.*lock(ed|out)|locked out|too many.*attempts', description: 'An account was locked out.', action: 'Investigate the source.' },
    { id: 'AUTH-003', name: 'Successful Login After Failures', category: 'Authentication', severity: 'WARNING', pattern: 'successful.*login.*after.*fail|was successfully logged on', description: 'A successful login occurred, check if preceded by failures.', action: 'Correlate with recent failed login events.' },
    { id: 'PRIV-001', name: 'Privilege Escalation Attempt', category: 'Privilege', severity: 'CRITICAL', pattern: 'sudo|su\\s+-|runas|privilege escalation|token elevation|SeDebugPrivilege', description: 'A privilege escalation command was detected.', action: 'Verify if authorized.' },
    { id: 'PRIV-002', name: 'New Admin or User Created', category: 'Privilege', severity: 'CRITICAL', pattern: 'user.*created|new.*account|member.*added.*admin|net\\s+user\\s+.*?/add', description: 'A new user account was created.', action: 'Confirm this was an authorized change.' },
    { id: 'MAL-001', name: 'Suspicious Process Execution', category: 'Malware', severity: 'CRITICAL', pattern: 'powershell.*-enc|cmd.*?/c.*whoami|certutil.*-urlcache|bitsadmin.*?/transfer|mimikatz|lazagne', description: 'A process commonly associated with malware was detected.', action: 'Isolate the endpoint immediately.' },
    { id: 'MAL-002', name: 'Suspicious Script Execution', category: 'Malware', severity: 'CRITICAL', pattern: 'wscript|cscript|mshta|regsvr32.*?/s|rundll32.*javascript', description: 'A Windows scripting host was used.', action: 'Review the command line for persistence mechanisms.' },
    { id: 'NET-001', name: 'Firewall Block', category: 'Network', severity: 'WARNING', pattern: 'firewall.*block|dropped.*packet|denied.*connection|iptables.*DROP', description: 'The firewall blocked a connection attempt.', action: 'Review the blocked IP and port.' },
    { id: 'NET-002', name: 'Port Scan Detected', category: 'Network', severity: 'CRITICAL', pattern: 'port scan|nmap|masscan|SYN.*flood|connection refused.*multiple', description: 'Activity consistent with a port scan was detected.', action: 'Block the source IP.' },
    { id: 'SYS-001', name: 'Service Crash or Stop', category: 'System', severity: 'ERROR', pattern: 'service.*stopped|service.*crash|unexpected.*shutdown|segfault|core dump|blue screen', description: 'A critical system service stopped or crashed.', action: 'Check service logs and restart.' },
    { id: 'SYS-002', name: 'Disk Space Warning', category: 'System', severity: 'WARNING', pattern: 'disk.*space|low.*storage|filesystem.*full|no space left', description: 'The system is running low on disk space.', action: 'Free up disk space.' },
    { id: 'SYS-003', name: 'System Error or Fatal', category: 'System', severity: 'ERROR', pattern: 'error|exception|fatal|critical', description: 'A generic error or fatal event was detected.', action: 'Review the full log message.' },
    { id: 'SYS-004', name: 'Warning Event', category: 'System', severity: 'WARNING', pattern: 'warn(ing)?', description: 'A warning-level event was detected.', action: 'Monitor for escalation.' }
  ];

  const trx = db.transaction((rules) => {
    for (const rule of rules) insertRule.run(rule);
  });
  trx(defaults);
}

console.log(`[DB] Connected to ${DB_PATH}`);

export default db;
