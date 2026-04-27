# SIEM Platform — Enterprise Security

Open-source SIEM built for high-throughput log ingestion and real-time threat detection.

## Architecture

```
┌──────────┐  gRPC   ┌──────────┐  Kafka   ┌──────────┐  TimescaleDB
│  Agent   │ ──────▶ │ Manager  │ ──────▶  │ Indexer  │ ──────────▶ PostgreSQL
│  (Go)    │  :50051 │ (Node.js)│ Raw Topic │ (Node.js)│   Events / Alerts
└──────────┘         └──────────┘          └──────────┘
                          │                      │
                     Rules Poller            REST API :8081
                     (30s interval)              │
                                          ┌──────────┐
                                          │Dashboard │
                                          │ (React)  │
                                          └──────────┘
```

## Stack

| Component      | Technology                         |
|----------------|------------------------------------|
| Agent          | Go + Wails (GUI/CLI dual-mode)     |
| Manager        | Node.js, gRPC, KafkaJS             |
| Indexer        | Node.js, Express, PostgreSQL (pg)  |
| Database       | TimescaleDB (PostgreSQL extension) |
| Message Broker | Apache Kafka (KRaft mode)          |
| Dashboard      | React + Vite                       |
| Installer      | WiX Toolset (MSI)                  |

## Project Structure

```
siem/
├── agent-ui/                  # Windows Agent (Go + Wails)
│   ├── app.go                 # Core agent logic (collectors, gRPC)
│   ├── main.go                # Entry point (GUI / CLI modes)
│   ├── frontend/              # Wails embedded UI
│   ├── proto/                 # Protobuf definitions
│   └── installer/             # WiX MSI source + build scripts
│       ├── installer.wxs      # WiX XML manifest
│       ├── build_installer.ps1
│       └── wix/               # WiX toolset binaries
│
├── platform/                  # Server-side components
│   ├── manager/               # Event ingestion service
│   │   ├── index.js           # Entry point (gRPC server + Kafka)
│   │   ├── handlers/grpc.js   # gRPC stream handlers
│   │   ├── services/kafka.js  # Kafka producer
│   │   ├── services/worker.js # Kafka consumer (batch processor)
│   │   └── rules/engine.js    # Dynamic rule engine
│   │
│   ├── indexer/               # Storage and API service
│   │   ├── index.js           # Entry point (Express + static files)
│   │   ├── db/postgres.js     # TimescaleDB connection + schema
│   │   ├── models/            # Data access layer (event, alert, agent, rule)
│   │   ├── routes/            # REST API endpoints
│   │   └── middleware/        # Express middleware
│   │
│   ├── dashboard/             # React SPA (Vite)
│   │   ├── src/App.jsx        # Main layout (sidebar, routing)
│   │   ├── src/components/    # Views (Overview, Alerts, Agents, Rules, Search)
│   │   ├── src/services/api.js # API client
│   │   └── dist/              # Production build (served by Indexer)
│   │
│   └── proto/                 # Shared protobuf definitions
│
└── docker-compose.yml         # Full stack orchestration
```

## Quick Start

### Prerequisites
- Docker Desktop running
- Node.js 18+ (for local development)
- Go 1.21+ (for agent builds)

### 1. Start the Platform
```bash
docker compose up -d
```
This starts: TimescaleDB, Kafka (KRaft), Manager (gRPC :50051), Indexer (API + Dashboard :8081)

### 2. Access the Dashboard
Open [http://localhost:8081](http://localhost:8081)

### 3. Install an Agent
Run the MSI installer on any Windows machine. Enter the Manager IP when prompted.
The agent will appear in the Dashboard under **Agents**.

### 4. Agent Manual Start (Development)
```bash
cd agent-ui
go run . cli          # Headless mode
go run .              # GUI mode (Wails window)
```

## Detection Rules

13 pre-built rules covering:
- **Authentication**: SSH failures, Windows lockouts, root access
- **Malware**: Crypto miners, suspicious processes (mimikatz, psexec)
- **Network**: Firewall blocks, suspicious ports
- **Privilege**: sudo usage, user creation

Create custom rules via Dashboard → Detection Rules → New Rule.

## Data Flow

1. **Agent** collects Windows Event Logs (System, Application, Security) + file tailing
2. **Agent** sends raw events via gRPC stream to **Manager** (:50051)
3. **Manager** publishes to Kafka topic `siem.logs.raw` (microsecond response)
4. **Worker** consumes from Kafka in batches, applies detection rules
5. Matched events generate **Alerts** sent to **Indexer**
6. **Indexer** stores events in TimescaleDB hyper-tables with full-text search
7. **Dashboard** displays real-time data with 10s auto-refresh

## API Reference

| Endpoint                  | Method | Description                    |
|---------------------------|--------|--------------------------------|
| `/api/stats/overview`     | GET    | KPI summary (events, alerts)   |
| `/api/stats/timeline`     | GET    | Event timeline (24h buckets)   |
| `/api/events`             | GET    | Search events (query, filters) |
| `/api/events/recent/:min` | GET    | Last N minutes of events       |
| `/api/ingest`             | POST   | Single event ingestion         |
| `/api/ingest/bulk`        | POST   | Batch event ingestion          |
| `/api/alerts`             | GET    | List alerts (status, severity) |
| `/api/alerts/:id`         | PUT    | Update alert status            |
| `/api/agents`             | GET    | List registered agents         |
| `/api/rules`              | GET    | List detection rules           |
| `/api/rules`              | POST   | Create rule                    |
| `/api/rules/:id`          | PUT    | Update rule                    |
| `/api/rules/:id`          | DELETE | Delete rule                    |

## License

All components use open-source technologies with permissive licenses suitable for commercial redistribution.
