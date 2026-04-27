// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — Worker Kafka Consumer
//  Consome eventos do tópico siem.logs.raw, aplica regras e encaminha ao Indexer
// ══════════════════════════════════════════════════════════════════════════════

import { kafka, TOPIC } from './kafka.js';
import { applyRules } from '../rules/engine.js';
import { forwardToIndexer } from './forwarder.js';

const consumer = kafka.consumer({ groupId: 'siem-rules-engine' });

/**
 * Inicia o Worker consumidor do Kafka.
 * Processar eventos em batches para alta eficiência.
 */
export async function startWorker() {
  await consumer.connect();
  await consumer.subscribe({ topic: TOPIC, fromBeginning: false });

  console.log(`[Worker] Consumidor Kafka ativo no tópico: ${TOPIC}`);

  await consumer.run({
    eachBatch: async ({ batch, heartbeat }) => {
      const events = batch.messages.map(msg => {
        try {
          return JSON.parse(msg.value.toString());
        } catch {
          return null;
        }
      }).filter(Boolean);

      if (!events.length) return;

      // Processar eventos em paralelo pelo motor de regras
      const processed = await Promise.all(events.map(async (event) => {
        try {
          return applyRules(event);
        } catch (err) {
          console.error('[Worker] Erro ao aplicar regras:', err.message);
          return event;
        }
      }));

      // Encaminhar os eventos processados ao Indexer em bulk
      const validEvents = processed.filter(Boolean);
      if (validEvents.length > 0) {
        forwardToIndexer('/api/ingest/bulk', validEvents);
      }

      // Manter o heartbeat do Kafka durante processamentos longos
      await heartbeat();
    },
  });
}
