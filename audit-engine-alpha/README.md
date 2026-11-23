# Audit & Compliance Engine MVP

Local-only **Audit & Compliance Engine with AI-Driven Detection for Cloud Infrastructure**.

Pipeline: synthetic CloudTrail events → **Kafka** → Python middleware → **OPA** (deterministic deny) → **SQLite**; OPA-clean events go to a sliding window assessed by local **Ollama** (no paid APIs).

## Prerequisites

- Docker / Docker Compose (Kafka + OPA)
- Python 3.11+
- [Ollama](https://ollama.com) listening on `localhost:11434` (for live LLM analysis)

Apple Silicon / ARM64: Compose uses `bitnamilegacy/kafka:3.9.0` and the official multi-arch OPA image.

## Layout

```
audit-engine-alpha/
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── README.md
├── policies/
│   ├── s3_compliance.rego
│   └── iam_kms_compliance.rego
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   ├── storage.py
│   ├── opa_client.py
│   ├── llm_client.py
│   ├── producer.py
│   └── middleware.py
└── tests/
    ├── __init__.py
    └── test_mvp_pipeline.py
```

## 1. Start Kafka + OPA

```bash
cd audit-engine-alpha
docker compose up -d
docker compose ps
curl -s http://localhost:8181/health
```

## 2. Pull an Ollama model

```bash
ollama pull llama3.2
# optional check
curl -s http://localhost:11434/api/tags
```

## 3. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # optional overrides
```

## 4. Run producer (Terminal A)

Cyclic scenarios: compliant, S3/IAM/KMS policy violations, and a suspicious `bob` sequence intended for LLM review (OPA may pass).

```bash
python src/producer.py
```

Logs include `eventName`, `userName`, and a `scenario=` tag.

## 5. Run middleware (Terminal B)

```bash
python src/middleware.py
```

Routing:

1. Validate JSON → `CloudAuditEvent`
2. Query both OPA deny paths; persist each violation to SQLite
3. If clean → append to deque window and `asyncio.create_task` Ollama analysis (non-blocking)
4. SIGINT / SIGTERM drain in-flight LLM tasks and shut down cleanly

## 6. Run tests (offline, mocked)

```bash
cd audit-engine-alpha
pytest -q
```

## 7. Inspect SQLite

```bash
sqlite3 ./data/audit_mvp.db 'SELECT event_name, user_name, message FROM policy_violations ORDER BY id DESC LIMIT 10;'
sqlite3 ./data/audit_mvp.db 'SELECT is_anomalous, risk_score, anomaly_type, fallback_used, incident_summary FROM anomaly_reports ORDER BY id DESC LIMIT 10;'
```

## Configuration

See `.env.example`. Important defaults:

| Variable | Default |
|----------|---------|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` |
| `KAFKA_AUDIT_TOPIC` | `audit-events` |
| `KAFKA_CONSUMER_GROUP` | `audit-middleware-mvp` |
| `KAFKA_AUTO_OFFSET_RESET` | `earliest` |
| `OPA_URL` | `http://localhost:8181` |
| `OPA_DENY_PATHS` | S3 + IAM/KMS deny paths (CSV) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` |
| `OLLAMA_MODEL` | `llama3.2` |
| `LLM_WINDOW_SIZE` | `5` |
| `SQLITE_DB_PATH` | `./data/audit_mvp.db` |
| `PRODUCER_INTERVAL_SECONDS` | `2` |

## Policies

- `policies/s3_compliance.rego` — deny `CreateBucket` with `acl=public-read`
- `policies/iam_kms_compliance.rego` — deny privileged `CreateAccessKey` (`root`/`admin`/`security-admin` + `status=Active`); deny `PutBucketEncryption` / `CreateDbInstance` when `kmsKeyId` missing/empty or `storageEncrypted=false`

## Tear down

```bash
docker compose down
```
