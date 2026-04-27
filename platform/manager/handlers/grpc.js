// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — gRPC Handlers (Kafka Producer)
//  Recebe eventos via gRPC e os publica imediatamente no Kafka
// ══════════════════════════════════════════════════════════════════════════════

import { publishEvent } from '../services/kafka.js';
import { forwardToIndexer } from '../services/forwarder.js';

/**
 * Unary RPC: recebe um único evento e publica no Kafka para processamento assíncrono.
 * Responde ao agent em microssegundos sem bloquear no processamento das regras.
 */
export function sendEvent(call, callback) {
  const event = { ...call.request };

  // Publicar imediatamente no Kafka — o Worker processará as regras em seguida
  publishEvent(event).catch(err =>
    console.error('[gRPC] Erro ao publicar no Kafka:', err.message)
  );

  callback(null, { success: true, error_message: '' });
}

/**
 * Client streaming RPC: recebe stream contínuo de eventos
 */
export function streamEvents(call) {
  call.on('data', (event) => {
    publishEvent({ ...event }).catch(() => {});
  });

  call.on('end', () => {
    call.end({ success: true, error_message: 'Stream ended' });
  });

  call.on('error', (err) => {
    console.error('[STREAM ERROR]', err.message);
  });
}

/**
 * Unary RPC: heartbeat do agente — vai direto para o Indexer (não precisa de Kafka)
 */
export function heartbeat(call, callback) {
  const info = call.request;
  console.log(`[HEARTBEAT] ${info.agent_id} @ ${info.ip_address} (${info.os})`);

  forwardToIndexer('/api/agent/heartbeat', {
    agent_id: info.agent_id, os: info.os, ip_address: info.ip_address,
    hostname: info.hostname, uptime: Number(info.uptime),
    version: info.version, active_collectors: info.active_collectors,
  });

  callback(null, { success: true, error_message: '' });
}
