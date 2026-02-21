# RUN.md — Secure Analysis Platform

## Prerequisites

- Python 3.10+
- pip

---

## 1. Install dependencies

```bash
cd secure-analysis-platform
pip install -r requirements.txt
```

---

## 2. Configure environment

Copy the example env file and fill in values:

```bash
cp .env.example .env


# Retrieve credentials related to azure account 
az ad sp create-for-rbac --name my-app --role Contributor --scopes /subscriptions/<SUBSCRIPTION_ID>
```

**Mapping:**

- appId → AZURE_CLIENT_ID
- password → AZURE_CLIENT_SECRET
- tenant → AZURE_TENANT_ID



Minimum required for **local/demo mode** (no Azure):

```env
KMS_LOCAL=true
AZURE_DEPLOY_DRY_RUN=true
```

For **real Azure** deployment:

```env
KMS_LOCAL=false
AZURE_DEPLOY_DRY_RUN=false
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
RESOURCE_GROUP_NAME=rg-secure-analysis
LOCATION=eastus
VAULT_NAME=your-key-vault-name
GITHUB_TOKEN=ghp_yourtoken
```

---

## 3. Start the platform

### FastAPI + Dashboard (recommended)

```bash
python run.py
```

Open: **http://localhost:8000**

### Custom port

```bash
MONITOR_PORT=9000 python run.py
```

### With uvicorn directly

```bash
uvicorn ui.monitor:app --host 0.0.0.0 --port 8000 --reload
```

---

## 4. Trigger an analysis

### Via the UI

1. Open http://localhost:8000
2. Paste a GitHub URL in the input bar (e.g. `https://github.com/psf/requests`)
3. Press **Enter** or click **Analyze**
4. Watch the 8-stage pipeline animate in real time

### Via CLI

```bash
python run.py --analyze https://github.com/psf/requests
```

### Via API

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/psf/requests"}'
```

---

## 5. API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Interactive dashboard |
| `GET` | `/docs` | FastAPI Swagger UI |
| `POST` | `/api/analyze` | Trigger analysis |
| `GET` | `/api/tasks` | Recent tasks + stats |
| `GET` | `/api/logs` | Audit log entries |
| `GET` | `/api/events` | Raw event stream |
| `GET` | `/api/stats` | Platform statistics |
| `GET` | `/api/health` | Health check |
| `WS` | `/ws` | Real-time event stream |

---

## 6. Train the ML model (optional)

```bash
# Generate 5000 synthetic IR samples and fine-tune GraphCodeBERT
python -m src.analyzer.model_trainer --samples 5000 --epochs-p1 10 --epochs-p2 5

# Checkpoint saved to /tmp/ir_security_model/
# Next run of the platform auto-loads it
```

---

## 7. Run tests

```bash
pytest tests/ -v
```

---

## 8. View audit logs

Logs survive all VM teardowns and are written to:

```
logs/audit.jsonl
```

```bash
# Tail the audit log
tail -f logs/audit.jsonl | python -m json.tool

# Count events by type
cat logs/audit.jsonl | python -c "
import json,sys
from collections import Counter
c = Counter(json.loads(l)['event'] for l in sys.stdin if l.strip())
[print(f'{v:>5}  {k}') for k,v in c.most_common()]
"
```

---

## 9. Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `KMS_LOCAL` | `true` | Use in-process KMS (dev) |
| `AZURE_DEPLOY_DRY_RUN` | `true` | Simulate Azure calls |
| `MONITOR_PORT` | `8000` | Dashboard port |
| `MONITOR_HOST` | `0.0.0.0` | Dashboard bind address |
| `AUDIT_LOG_DIR` | `logs/` | Where audit.jsonl is written |
| `GITHUB_TOKEN` | _(none)_ | GitHub API token (higher rate limit) |
| `MTLS_CERT_PATH` | `/tmp/agent.crt` | Agent TLS cert |
| `MTLS_KEY_PATH` | `/tmp/agent.key` | Agent TLS key |
| `MTLS_CA_PATH` | `/tmp/ca.crt` | CA certificate |
