"""
Main Orchestrator

Coordinates the full analysis pipeline:
  1. Receive analysis task
  2. Provision agent microVMs
  3. Execute pipeline: Fetch → Parse → IR → ML → Policy
  4. Return policy decision
  5. Destroy all VMs

Implements A2A protocol for all inter-agent communication.
"""
from __future__ import annotations

import asyncio
import gc
import logging
import os
import secrets
import time
from base64 import b64decode
from typing import Dict, List, Optional

from config.azure_config import AGENT_CONFIG
from src.analyzer.ast_parser import parse_python_source
from src.analyzer.ir_builder import build_ir_from_ast
from src.analyzer.ml_analyzer import MLSecurityAnalyzer
from src.agents.policy_engine import PolicyEngine
from src.key_management import FileEncryptor, build_kms
from src.schemas.a2a_schemas import (
    AgentRole, ASTPayload, EncryptedFilePayload, IRPayload,
    MessageType, PolicyDecision, RiskAssessment,
    TaskManifest, ViolationEvent, create_header,
)
from src.security.mtls import MTLSConfig, generate_ca_certificate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# Disable noisy libraries
for lib in ("azure", "urllib3", "transformers", "torch"):
    logging.getLogger(lib).setLevel(logging.WARNING)


class SecureAnalysisPipeline:
    """
    In-process pipeline coordinator.
    
    In production, each agent runs in its own microVM.
    This implementation simulates the A2A flow with proper data contracts.
    """

    def __init__(self, use_local_kms: bool = True) -> None:
        self.kms = build_kms(use_local=use_local_kms)
        self.encryptor = FileEncryptor(self.kms)
        self.ml_analyzer = MLSecurityAnalyzer()
        self.policy_engine = PolicyEngine()

        # Stats
        self._pipeline_runs = 0
        self._violations: List[ViolationEvent] = []

    def _handle_encrypted_payload(
        self,
        payload: EncryptedFilePayload,
    ) -> Optional[ASTPayload]:
        """
        Decrypt → Parse → Sanitize → Return ASTPayload.
        Plaintext exists only within decrypt_context block.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from base64 import b64decode

        try:
            # Reconstruct encrypted payload for decryption
            from src.key_management import EncryptedPayload
            enc = EncryptedPayload(
                ciphertext=b64decode(payload.ciphertext_b64),
                nonce=b64decode(payload.nonce_b64),
                encrypted_dek=b64decode(payload.encrypted_dek_b64),
                kek_key_id=payload.kek_key_id,
            )

            with self.encryptor.decrypt_context(enc) as plaintext_bytes:
                # Parse while plaintext is in scope
                if payload.file_extension == ".py":
                    ast_payload = parse_python_source(
                        plaintext_bytes,
                        payload.file_index,
                        payload.header.task_id,
                    )
                else:
                    # For non-Python files, create minimal payload
                    from src.schemas.a2a_schemas import ASTNode, create_header
                    ast_payload = ASTPayload(
                        header=create_header(
                            MessageType.AST_PAYLOAD,
                            AgentRole.AST_PARSER,
                            AgentRole.IR_BUILDER,
                            payload.header.task_id,
                        ),
                        file_index=payload.file_index,
                        file_extension=payload.file_extension,
                        root_node=ASTNode(node_type="Module", children=[], attributes={}),
                        node_count=0,
                        depth=0,
                        cyclomatic_complexity=0,
                        import_count=0,
                        function_count=0,
                        class_count=0,
                        parse_errors=["unsupported_extension"],
                    )
            # Plaintext is gone here
            return ast_payload

        except Exception as e:
            logger.error("Failed to process encrypted payload %d: %s",
                         payload.file_index, type(e).__name__)
            return None

    async def run_analysis(self, repo_url: str, task_id: Optional[str] = None) -> dict:
        """
        Execute full analysis pipeline for a repository.
        
        Pipeline stages:
          Fetch (GitHub) → Encrypt → AST Parse → IR Build → ML Score → Policy Decide
        """
        task_id = task_id or secrets.token_hex(12)
        self._pipeline_runs += 1

        logger.info("=== Starting analysis task: %s ===", task_id)
        logger.info("Repository: %s", repo_url)
        start_time = time.time()

        # Stage 1: Fetch and encrypt repository files
        from src.repo_cloner import SecureFetcherAgent

        # Create minimal mTLS config for local operation
        mtls_config = MTLSConfig(
            cert_path=os.getenv("MTLS_CERT_PATH", "/tmp/agent.crt"),
            key_path=os.getenv("MTLS_KEY_PATH", "/tmp/agent.key"),
            ca_path=os.getenv("MTLS_CA_PATH", "/tmp/ca.crt"),
            agent_id=f"orchestrator-{task_id[:8]}",
        )

        fetcher = SecureFetcherAgent(
            mtls_config=mtls_config,
            parser_host="localhost",
            parser_port=8443,
            use_local_kms=True,
        )

        encrypted_payloads: List[EncryptedFilePayload] = []
        logger.info("[Stage 1] Fetching repository...")

        try:
            async for payload in fetcher.fetch_and_encrypt_stream(repo_url, task_id):
                encrypted_payloads.append(payload)
                logger.debug("Fetched+encrypted file %d/%d",
                             payload.file_index + 1, payload.total_files)
        except Exception as e:
            logger.error("Fetch failed: %s", e)
            return {
                "task_id": task_id,
                "status": "failed",
                "error": f"Fetch error: {type(e).__name__}",
                "duration_seconds": time.time() - start_time,
            }

        if not encrypted_payloads:
            return {
                "task_id": task_id,
                "status": "failed",
                "error": "No files fetched",
                "duration_seconds": time.time() - start_time,
            }

        logger.info("[Stage 1] Fetched %d files", len(encrypted_payloads))

        # Stage 2: AST Parsing (decrypt → parse → re-encrypt implicitly via ASTPayload)
        logger.info("[Stage 2] Parsing ASTs...")
        ast_payloads: List[ASTPayload] = []

        for enc_payload in encrypted_payloads:
            ast_payload = self._handle_encrypted_payload(enc_payload)
            if ast_payload is not None:
                ast_payloads.append(ast_payload)

        # Discard encrypted payloads
        del encrypted_payloads
        gc.collect()

        logger.info("[Stage 2] Parsed %d ASTs", len(ast_payloads))

        # Stage 3: IR Construction
        logger.info("[Stage 3] Building IR...")
        ir_payloads: List[IRPayload] = []

        for ast_payload in ast_payloads:
            ir_payload = build_ir_from_ast(ast_payload)
            ir_payloads.append(ir_payload)

        del ast_payloads
        gc.collect()

        logger.info("[Stage 3] Built %d IR payloads", len(ir_payloads))

        # Stage 4: ML Risk Analysis
        logger.info("[Stage 4] Running ML security analysis...")
        risk_assessment = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self.ml_analyzer.analyze_batch(ir_payloads, task_id),
        )

        del ir_payloads
        gc.collect()

        logger.info(
            "[Stage 4] Risk assessment complete. Aggregate risk: %.2f",
            risk_assessment.aggregate_risk,
        )

        # Stage 5: Policy Decision
        logger.info("[Stage 5] Evaluating policy...")
        policy_decision = self.policy_engine.evaluate(risk_assessment)

        duration = time.time() - start_time
        logger.info(
            "=== Task %s complete in %.2fs. Decision: %s (confidence: %.2f) ===",
            task_id, duration, policy_decision.decision, policy_decision.confidence,
        )

        return {
            "task_id": task_id,
            "status": "complete",
            "decision": policy_decision.decision,
            "confidence": policy_decision.confidence,
            "aggregate_risk": risk_assessment.aggregate_risk,
            "total_files": risk_assessment.total_files,
            "high_risk_files": risk_assessment.high_risk_file_count,
            "anomalous_patterns": risk_assessment.anomalous_pattern_count,
            "constraints": [c.constraint_type for c in policy_decision.constraints],
            "required_mitigations": policy_decision.required_mitigations,
            "hitl_required": policy_decision.hitl_required,
            "duration_seconds": duration,
            "risk_summary": policy_decision.risk_summary,
            "terraform_constraints": [
                {"type": c.constraint_type, "snippet": c.terraform_snippet}
                for c in policy_decision.constraints
                if c.terraform_snippet
            ],
        }

    def get_stats(self) -> dict:
        return {
            "pipeline_runs": self._pipeline_runs,
            "violations": len(self._violations),
            "policy_stats": self.policy_engine.get_stats(),
        }


# Singleton pipeline
_pipeline: Optional[SecureAnalysisPipeline] = None


def get_pipeline() -> SecureAnalysisPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = SecureAnalysisPipeline()
    return _pipeline


async def main() -> None:
    """CLI entrypoint."""
    repo_url = os.getenv("GITHUB_REPO_URL", "")
    if not repo_url:
        raise ValueError("GITHUB_REPO_URL environment variable required")

    pipeline = get_pipeline()
    result = await pipeline.run_analysis(repo_url)

    print("\n" + "=" * 60)
    print("ANALYSIS RESULT")
    print("=" * 60)
    for key, value in result.items():
        if key != "risk_summary":
            print(f"  {key}: {value}")
    print("\nRisk Summary:")
    print(result.get("risk_summary", "N/A"))
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())