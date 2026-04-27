// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Indexer — Log Parser
//  Extracts structured fields from raw log messages
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Parse a raw log message and extract structured fields.
 * Returns a JSON-serializable object with extracted data.
 */
export function parseLogMessage(message) {
  if (!message || typeof message !== 'string') return {};

  const fields = {};

  // ── IP Addresses ───────────────────────────────────────────────────────────
  const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const ips = [...new Set((message.match(ipPattern) || []))];
  if (ips.length > 0) fields.ip_addresses = ips;

  // Source IP (from X / rhost=X)
  const srcIp = message.match(/(?:from|rhost[= ])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
  if (srcIp) fields.source_ip = srcIp[1];

  // ── Port ───────────────────────────────────────────────────────────────────
  const port = message.match(/port\s+(\d+)/i);
  if (port) fields.port = parseInt(port[1]);

  const dpt = message.match(/DPT=(\d+)/);
  if (dpt) fields.destination_port = parseInt(dpt[1]);

  // ── Username / Account ─────────────────────────────────────────────────────
  const userPatterns = [
    /(?:for|for invalid user|for user)\s+(\S+)/i,
    /user[= ](\S+)/i,
    /account[: ]+(\S+)/i,
    /logname=(\S+)/i,
    /name=(\S+)/i,
  ];
  for (const p of userPatterns) {
    const m = message.match(p);
    if (m && m[1] && m[1].length > 1 && m[1] !== 'root') {
      fields.username = m[1];
      break;
    }
  }

  // Root user detection
  if (/\broot\b/.test(message)) fields.root_involved = true;

  // ── Windows Event ID ───────────────────────────────────────────────────────
  const eventId = message.match(/EventID[= ](\d+)/i);
  if (eventId) fields.event_id = parseInt(eventId[1]);

  // ── Timestamp extraction from log body ─────────────────────────────────────
  const tsPatterns = [
    /\[(\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2})\]/,           // [17/03/2026 20:02:20]
    /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/,                 // 2026-03-17T20:02:20
    /(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,                    // Mar 17 20:02:20
  ];
  for (const p of tsPatterns) {
    const m = message.match(p);
    if (m) { fields.log_timestamp = m[1]; break; }
  }

  // ── Protocol ───────────────────────────────────────────────────────────────
  const proto = message.match(/\b(ssh2?|tcp|udp|icmp|http|https|ftp|rdp|smb)\b/i);
  if (proto) fields.protocol = proto[1].toLowerCase();

  // ── Process / Service ──────────────────────────────────────────────────────
  const process = message.match(/^(\w[\w.-]+)\[?\d*\]?:\s/);
  if (process) fields.process = process[1];

  const sshd = message.match(/\bsshd\b/i);
  if (sshd) fields.service = 'sshd';

  const sudo = message.match(/\bsudo\b/i);
  if (sudo) fields.service = 'sudo';

  // ── Action keywords ────────────────────────────────────────────────────────
  const actions = [];
  if (/failed|failure|denied|rejected|blocked/i.test(message)) actions.push('denied');
  if (/accepted|success|opened|granted/i.test(message)) actions.push('accepted');
  if (/locked|lockout/i.test(message)) actions.push('lockout');
  if (/created|added|useradd/i.test(message)) actions.push('created');
  if (/deleted|removed/i.test(message)) actions.push('deleted');
  if (/sudo|root|privilege|escalat/i.test(message)) actions.push('privilege_escalation');
  if (actions.length > 0) fields.actions = actions;

  // ── Threat indicators ──────────────────────────────────────────────────────
  const threats = [];
  if (/mimikatz/i.test(message)) threats.push('mimikatz');
  if (/meterpreter/i.test(message)) threats.push('meterpreter');
  if (/psexec/i.test(message)) threats.push('psexec');
  if (/cobalt|beacon/i.test(message)) threats.push('cobalt_strike');
  if (/netcat|ncat|nc\.exe/i.test(message)) threats.push('netcat');
  if (/xmrig|minerd|cryptominer/i.test(message)) threats.push('cryptominer');
  if (threats.length > 0) fields.threat_indicators = threats;

  // ── Raw message length ─────────────────────────────────────────────────────
  fields.raw_length = message.length;

  return fields;
}
