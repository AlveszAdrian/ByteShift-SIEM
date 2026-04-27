// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Database de Conexão (TimescaleDB/PostgreSQL)
//  Substituição Enterprise do SQLite por banco de dados de séries temporais
// ══════════════════════════════════════════════════════════════════════════════

import pg from 'pg';

const { Pool } = pg;

// Pool de conexões com o TimescaleDB
const pool = new Pool({
  host:     process.env.DB_HOST || 'localhost',
  user:     process.env.DB_USER || 'siem',
  password: process.env.DB_PASS || 'siem_secure_pass_123',
  database: process.env.DB_NAME || 'siem',
  port:     5432,
  max:      20,   // máximo de conexões simultâneas no pool
  idleTimeoutMillis:    30000,
  connectionTimeoutMillis: 5000,
});

// Verifica a conexão na inicialização
pool.on('error', (err) => {
  console.error('[DB] Erro inesperado no pool do PostgreSQL:', err.message);
});

/**
 * Inicializa o schema do banco: tabelas + extensão TimescaleDB (hyper-tables)
 */
export async function initDb() {
  const client = await pool.connect();
  try {
    console.log('[DB] Conectado ao TimescaleDB. Inicializando schema...');

    // Habilitar extensão TimescaleDB
    await client.query(`CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;`);

    // Tabela de eventos — será convertida em hyper-table por tempo
    await client.query(`
      CREATE TABLE IF NOT EXISTS events (
        id          BIGSERIAL,
        time        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        agent_id    TEXT NOT NULL,
        log_type    TEXT,
        severity    TEXT NOT NULL DEFAULT 'INFO',
        message     TEXT NOT NULL,
        metadata    TEXT,
        fields      JSONB DEFAULT '{}',
        PRIMARY KEY (id, time)
      );
    `);

    // Converter em TimescaleDB hyper-table para particionamento automático por tempo
    await client.query(`
      SELECT create_hypertable('events', by_range('time'), if_not_exists => TRUE);
    `).catch(() => {}); // silencia se já existir

    // Índices de alta performance para as queries mais comuns do SIEM
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_agent ON events (agent_id, time DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity, time DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_search ON events USING GIN (to_tsvector('english', message));`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_events_fields ON events USING GIN (fields);`);

    // Tabela de alertas
    await client.query(`
      CREATE TABLE IF NOT EXISTS alerts (
        id                 BIGSERIAL PRIMARY KEY,
        time               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        rule_id            TEXT NOT NULL,
        rule_name          TEXT,
        category           TEXT,
        severity           TEXT NOT NULL,
        agent_id           TEXT,
        source_event       TEXT,
        description        TEXT,
        recommended_action TEXT,
        status             TEXT NOT NULL DEFAULT 'open'
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status, time DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity, time DESC);`);

    // Tabela de agentes
    await client.query(`
      CREATE TABLE IF NOT EXISTS agents (
        agent_id          TEXT PRIMARY KEY,
        hostname          TEXT,
        ip_address        TEXT,
        os                TEXT,
        version           TEXT,
        active_collectors TEXT,
        last_seen         BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
      );
    `);

    // Tabela de regras de detecção (regex-based, legacy + custom)
    await client.query(`
      CREATE TABLE IF NOT EXISTS rules (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        category    TEXT,
        severity    TEXT NOT NULL DEFAULT 'WARNING',
        pattern     TEXT NOT NULL,
        description TEXT,
        action      TEXT,
        enabled     INTEGER NOT NULL DEFAULT 1
      );
    `);

    // Seed default detection rules if table is empty
    const ruleCount = await client.query(`SELECT COUNT(*) FROM rules`);
    if (parseInt(ruleCount.rows[0].count, 10) === 0) {
      console.log('[DB] Seeding default detection rules...');
      const defaults = [
        { id: 'AUTH-001', name: 'Failed Login Attempt', category: 'Authentication', severity: 'WARNING', pattern: 'failed password|authentication failure|failed login|logon failure|bad password', description: 'A login attempt failed.', action: 'Check if the source IP is known.' },
        { id: 'AUTH-002', name: 'Account Lockout', category: 'Authentication', severity: 'CRITICAL', pattern: 'account.*lock(ed|out)|locked out|too many.*attempts', description: 'An account was locked out.', action: 'Investigate the source.' },
        { id: 'AUTH-003', name: 'Successful Login After Failures', category: 'Authentication', severity: 'WARNING', pattern: 'successful.*login.*after.*fail|was successfully logged on', description: 'A successful login occurred after failures.', action: 'Correlate with recent failed login events.' },
        { id: 'PRIV-001', name: 'Privilege Escalation Attempt', category: 'Privilege', severity: 'CRITICAL', pattern: 'sudo|su\\s+-|runas|privilege escalation|token elevation|SeDebugPrivilege', description: 'A privilege escalation was detected.', action: 'Verify if authorized.' },
        { id: 'PRIV-002', name: 'New Admin or User Created', category: 'Privilege', severity: 'CRITICAL', pattern: 'user.*created|new.*account|member.*added.*admin|net\\s+user\\s+.*/add', description: 'A new user account was created.', action: 'Confirm this was authorized.' },
        { id: 'MAL-001', name: 'Suspicious Process Execution', category: 'Malware', severity: 'CRITICAL', pattern: 'powershell.*-enc|cmd.*/c.*whoami|certutil.*-urlcache|bitsadmin.*/transfer|mimikatz|lazagne', description: 'A malware-associated process was detected.', action: 'Isolate the endpoint immediately.' },
        { id: 'MAL-002', name: 'Suspicious Script Execution', category: 'Malware', severity: 'CRITICAL', pattern: 'wscript|cscript|mshta|regsvr32.*/s|rundll32.*javascript', description: 'A Windows scripting host was used.', action: 'Review the command line.' },
        { id: 'NET-001', name: 'Firewall Block', category: 'Network', severity: 'WARNING', pattern: 'firewall.*block|dropped.*packet|denied.*connection|iptables.*DROP', description: 'The firewall blocked a connection.', action: 'Review the blocked IP and port.' },
        { id: 'NET-002', name: 'Port Scan Detected', category: 'Network', severity: 'CRITICAL', pattern: 'port scan|nmap|masscan|SYN.*flood|connection refused.*multiple', description: 'Port scan activity detected.', action: 'Block the source IP.' },
        { id: 'SYS-001', name: 'Service Crash or Stop', category: 'System', severity: 'ERROR', pattern: 'service.*stopped|service.*crash|unexpected.*shutdown|segfault|core dump|blue screen', description: 'A critical service stopped.', action: 'Check logs and restart.' },
        { id: 'SYS-002', name: 'Disk Space Warning', category: 'System', severity: 'WARNING', pattern: 'disk.*space|low.*storage|filesystem.*full|no space left', description: 'Low disk space.', action: 'Free up disk space.' },
        { id: 'SYS-003', name: 'System Error or Fatal', category: 'System', severity: 'ERROR', pattern: 'error|exception|fatal|critical', description: 'A generic error was detected.', action: 'Review the full log message.' },
        { id: 'SYS-004', name: 'Warning Event', category: 'System', severity: 'WARNING', pattern: 'warn(ing)?', description: 'A warning-level event.', action: 'Monitor for escalation.' },
      ];
      for (const r of defaults) {
        await client.query(
          `INSERT INTO rules (id, name, category, severity, pattern, description, action) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.name, r.category, r.severity, r.pattern, r.description, r.action]
        );
      }
      console.log(`[DB] Seeded ${defaults.length} default detection rules.`);
    }

    console.log('[DB] Schema TimescaleDB inicializado com sucesso.');
  } finally {
    client.release();
  }
}

export default pool;
