// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Manager — Entry Point
//  Bootstraps the gRPC server and registers rules with the Indexer
// ══════════════════════════════════════════════════════════════════════════════

import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import { fileURLToPath } from 'url';
import path from 'path';

import { sendEvent, streamEvents, heartbeat } from './handlers/grpc.js';
import { fetchRulesFromIndexer } from './services/forwarder.js';
import { updateRules } from './rules/engine.js';
import { connectProducer } from './services/kafka.js';
import { startWorker } from './services/worker.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.join(__dirname, '..', 'proto', 'events.proto');
const PORT = process.env.PORT || '50051';

// Load protobuf definition
const packageDef = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
});
const proto = grpc.loadPackageDefinition(packageDef).siem.events;

// Create and start gRPC server
const server = new grpc.Server();

server.addService(proto.EventService.service, {
  SendEvent:    sendEvent,
  StreamEvents: streamEvents,
  Heartbeat:    heartbeat,
});

server.bindAsync(`0.0.0.0:${PORT}`, grpc.ServerCredentials.createInsecure(), (err, port) => {
  if (err) { console.error('gRPC bind error:', err); process.exit(1); }
  console.log(`[Manager] gRPC server listening on port ${port}`);

  // Inicializar Kafka Producer e Worker
  connectProducer().then(() => startWorker()).catch(err => {
    console.error('[Manager] Erro ao conectar ao Kafka:', err.message);
  });

  // Polling de regras dinâmicas
  const refreshRules = async () => {
    const freshRules = await fetchRulesFromIndexer();
    if (freshRules.length > 0) {
      updateRules(freshRules);
      console.log(`[Manager] Motor de regras carregou ${freshRules.length} regras dinâmicas.`);
    }
  };

  setTimeout(refreshRules, 3000);
  setInterval(refreshRules, 30000);
});
