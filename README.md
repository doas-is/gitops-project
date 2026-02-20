# Secure Analysis Platform

Zero-trust static analysis pipeline that ingests a GitHub repository, runs it through a chain of isolated microVMs, and produces validated Terraform + Ansible infrastructure-as-code — without ever exposing source code semantics to any agent.

---

## What it does

```
GitHub Repo URL
      │
      ▼ Stage 1: FETCH (SecureFetcherAgent)
      │  Pull files via GitHub API. Encrypt each file immediately (AES-256-GCM).
      │  Plaintext lifetime < 1ms. No disk write.
      │
      ▼ Stage 2: PARSE (AST Parser)
      │  Decrypt JIT. Strip all strings, comments, docstrings.
      │  Hash all identifiers (SHA-256). Emit sanitised ASTPayload.
      │
      ▼ Stage 3: IR BUILD (IR Builder)
      │  Convert AST → language-agnostic IR (28 structural token types).
      │  No executable code. No natural language.
      │
      ▼ Stage 4: ML SCORE (ML Analyzer)
      │  Rule-based scorer + fine-tuned GraphCodeBERT on IR tokens.
      │  5 risk dimensions. P90 aggregate risk.
      │
      ▼ Stage 5: POLICY (Policy Engine)
      │  Evaluate 6 rules. APPROVE / REJECT / APPROVE_WITH_CONSTRAINTS.
      │  HITL escalation when confidence < 0.60.
      │
      ▼ Stage 6: STRATEGY (DeploymentStrategyAgent)
      │  Analyse IR metrics + policy constraints.
      │  Decide: DECLARATIVE (Terraform+Ansible) / IMPERATIVE (az CLI) / HYBRID.
      │
      ▼ Stage 7: IaC GENERATE (IaCGeneratorAgent)
      │  Produce Terraform (.tf) + Ansible (.yml) from constraints.
      │  NSG rules, sandboxed containers, monitoring — all from policy output.
      │
      ▼ Stage 8: DEPLOY (DeploymentAgent)
      │  Apply IaC to Azure. Verify. Report result.
      │  Self-destruct VM after completion.
      │
      ▼ TEARDOWN
         All microVMs destroyed. Resource group cleaned up.
         Audit log (logs/audit.jsonl) preserved forever.
```

---

## Security measures

### Encryption
- **AES-256-GCM** per file, unique nonce + DEK. DEK wrapped with RSA-OAEP-256 KEK stored in Azure Key Vault.
- Plaintext held in `bytearray`, zeroized via `ctypes.memset` immediately after use.
- All inter-agent traffic encrypted via **TLS 1.3** (mTLS, mutual authentication).

### Zero Trust
- Each agent runs in its own **ephemeral microVM** — destroyed on task completion, violation, or lifetime expiry (default 1h).
- No shared memory, no shared disk, no shared credentials between agents.
- Every VM gets a **unique short-lived TLS certificate** (2h validity, revoked on teardown).
- No agent sees another agent's data — only the typed A2A schema payload it was designed to receive.

### Network security (Azure NSG)
- All VMs on a private subnet (no public IPs).
- NSG default-deny inbound + outbound. Only approved ports (443 HTTPS, 8443 mTLS) allowed.
- `network_isolation` constraint adds private endpoints + blocks all outbound.

### Semantic stripping
- `SemanticStrippingVisitor` removes all string literals, docstrings, comments.
- Identifiers → `ID_<sha256[:8]>`. No real names reach any model.
- ML models see only IR structural tokens from a fixed 28-item vocabulary.

### Audit trail
- Every stage, VM creation/destruction, policy decision, and deployment action is written to `logs/audit.jsonl` (append-only, survives all teardowns).
- Audit log is the **only component not destroyed** after a task.

### Additional measures
- **Schema validation** on every A2A message (Pydantic). No untyped data passes between agents.
- **P90 aggregate risk** (not mean) — robust to outlier files.
- **HITL escalation** when ML confidence < 60%.
- Deployment strategy agent prevents deploying high-risk code with default declarative flow — escalates to imperative with ordered hardening steps.

---

## Project structure

```
secure-analysis-platform/
├── config/
│   └── azure_config.py          Azure + agent configuration
├── logs/
│   ├── audit.py                 Persistent audit logger
│   └── audit.jsonl              Append-only event log (created at runtime)
├── src/
│   ├── agents/
│   │   ├── policy_engine.py     Rules R001–R006 + HITL
│   │   ├── deployment_strategy.py  Decides deploy method from IR metrics
│   │   ├── iac_generator.py     Produces Terraform + Ansible
│   │   └── deployment_agent.py  Applies IaC, then self-destructs
│   ├── analyzer/
│   │   ├── ast_parser.py        Semantic stripping (Python native AST)
│   │   ├── ir_builder.py        AST → IR (28 node types)
│   │   ├── ml_analyzer.py       3-layer ensemble scorer
│   │   ├── model_trainer.py     Fine-tuning pipeline (GraphCodeBERT)
│   │   └── training_data.py     Synthetic IR security dataset generator
│   ├── schemas/
│   │   └── a2a_schemas.py       All A2A message contracts (Pydantic)
│   ├── security/
│   │   └── mtls.py              TLS 1.3 mutual auth + cert generation
│   ├── azure_setup.py           µVM orchestrator
│   ├── key_management.py        Envelope encryption + zeroization
│   ├── parser.py                Multi-language parser dispatcher (10 languages)
│   ├── repo_cloner.py           Secure fetcher agent
│   └── main.py                  8-stage pipeline orchestrator
├── ui/
│   └── monitor.py               FastAPI dashboard + WebSocket
├── tests/
│   └── test_azure_setup.py
├── run.py                       Entrypoint
├── RUN.md                       Commands reference
├── README.md                    This file
└── requirements.txt
```

---

## Supported languages

Python, JavaScript, TypeScript, Go, Java, Rust, Ruby, C#, C/C++, PHP, Shell

---

## Quick start

```bash
pip install -r requirements.txt
KMS_LOCAL=true AZURE_DEPLOY_DRY_RUN=true python run.py
# Open http://localhost:8000
```

See **RUN.md** for the full command reference.