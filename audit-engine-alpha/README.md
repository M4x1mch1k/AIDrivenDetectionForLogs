# Audit Engine Alpha

Event-driven audit & compliance skeleton for a Master's thesis: synthetic CloudTrail events → Kafka → Python middleware → OPA Rego policy. LLM anomaly checks are stubbed for this alpha (no Ollama).

## Prerequisites

- Docker / Docker Compose
- Python 3.11+

## Start infrastructure

From this directory:

```bash
docker compose up -d
```

This starts:

- **Kafka** (Bitnami, single-node KRaft) on `localhost:9092`
- **OPA** on `localhost:8181` with `./policies` mounted

Wait until both are healthy (`docker compose ps`).

## Install Python deps

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run producer

Publishes one CloudTrail-like JSON event every 2 seconds to topic `audit-events`:

```bash
python src/producer.py
```

Optional env:

- `KAFKA_BOOTSTRAP_SERVERS` (default `localhost:9092`)
- `PRODUCER_INTERVAL_SECONDS` (default `2`)

## Run middleware

In a second terminal (same venv):

```bash
python src/middleware.py
```

Optional env:

- `KAFKA_BOOTSTRAP_SERVERS` (default `localhost:9092`)
- `OPA_URL` (default `http://localhost:8181/v1/data/aws/s3/compliance/deny`)
- `KAFKA_GROUP_ID` (default `audit-middleware-alpha`)

Output:

- `Event Passed` (+ stub line `LLM Check Bypassed for Alpha`) when OPA deny set is empty
- `Violation Detected: [Reason]` when Rego reports a deny

## OPA input shape

Middleware POSTs:

```json
{
  "input": {
    "eventVersion": "1.08",
    "eventTime": "2026-10-26T12:00:00Z",
    "eventName": "CreateBucket",
    "requestParameters": {
      "bucketName": "public-logs",
      "acl": "public-read"
    },
    "userIdentity": {
      "type": "IAMUser",
      "principalId": "AIDAEXAMPLE1",
      "userName": "alice"
    }
  }
}
```

to `POST /v1/data/aws/s3/compliance/deny`.

Policy (`policies/s3_compliance.rego`, package `aws.s3.compliance`) denies when `eventName == "CreateBucket"` and `requestParameters.acl == "public-read"`, returning a set of violation messages that name the user.

Manual check:

```bash
curl -s http://localhost:8181/v1/data/aws/s3/compliance/deny \
  -H 'Content-Type: application/json' \
  -d '{"input":{"eventName":"CreateBucket","requestParameters":{"acl":"public-read"},"userIdentity":{"type":"IAMUser","principalId":"1","userName":"alice"},"eventTime":"2026-10-26T12:00:00Z","eventVersion":"1.08"}}'
```

## Layout

```
audit-engine-alpha/
├── docker-compose.yml
├── requirements.txt
├── README.md
├── policies/
│   └── s3_compliance.rego
└── src/
    ├── models.py
    ├── producer.py
    └── middleware.py
```
