// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — Serviço Kafka
//  Inicializa o Producer Kafka para publicar eventos no tópico siem.logs.raw
// ══════════════════════════════════════════════════════════════════════════════

import { Kafka, Partitioners } from 'kafkajs';

const BROKER  = process.env.KAFKA_BROKER || 'localhost:9092';
const TOPIC   = 'siem.logs.raw';

const kafka = new Kafka({
  clientId: 'siem-manager',
  brokers: [BROKER],
  retry: {
    initialRetryTime: 500,
    retries: 10,
  },
});

const producer = kafka.producer({
  createPartitioner: Partitioners.LegacyPartitioner,
});

let connected = false;

export async function connectProducer() {
  await producer.connect();
  connected = true;
  console.log(`[Kafka] Producer conectado ao broker: ${BROKER}`);
}

/**
 * Publica um evento bruto no tópico Kafka.
 * Chave = agent_id para garantir ordem por agente.
 */
export async function publishEvent(event) {
  if (!connected) return;
  try {
    await producer.send({
      topic: TOPIC,
      messages: [{
        key: String(event.agent_id || 'unknown'),
        value: JSON.stringify(event),
      }],
    });
  } catch (err) {
    console.error('[Kafka] Erro ao publicar evento:', err.message);
  }
}

export { kafka, TOPIC };
