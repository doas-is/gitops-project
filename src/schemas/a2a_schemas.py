"""
Agent-to-Agent (A2A) Protocol Message Schemas.

ALL inter-agent communication MUST use these schemas.
Messages are:
  - Schema-validated before processing
  - Signed with agent private key
  - Encrypted via mTLS transport
  - Immutable once created

No agent sees raw source code.
No agent sees another agent's full context.
"""
from __future__ import annotations

import secrets
import time
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    SECURE_FETCHER = "secure_fetcher"
    AST_PARSER = "ast_parser"
    IR_BUILDER = "ir_builder"
    ML_ANALYZER = "ml_analyzer"
    POLICY_ENGINE = "policy_engine"
    IAC_GENERATOR = "iac_generator"
    HITL_ESCALATION = "hitl_escalation"


class MessageType(str, Enum):
    ENCRYPTED_FILE_PAYLOAD = "encrypted_file_payload"
    AST_PAYLOAD = "ast_payload"
    IR_PAYLOAD = "ir_payload"
    RISK_ASSESSMENT = "risk_assessment"
    POLICY_DECISION = "policy_decision"
    TASK_START = "task_start"
    TASK_COMPLETE = "task_complete"
    TASK_FAILED = "task_failed"
    VIOLATION_DETECTED = "violation_detected"
    HITL_REQUEST = "hitl_request"
    HITL_RESPONSE = "hitl_response"
    HEALTH_CHECK = "health_check"


class A2AHeader(BaseModel):
    """Signed message envelope - never contains code."""
    message_id: str = Field(default_factory=lambda: secrets.token_hex(16))
    message_type: MessageType
    sender_role: AgentRole
    recipient_role: AgentRole
    task_id: str
    timestamp: float = Field(default_factory=time.time)
    signature: Optional[str] = None
    schema_version: str = "1.0.0"

    class Config:
        frozen = True


class EncryptedFilePayload(BaseModel):
    """
    Secure Fetcher → AST Parser.
    Contains AES-256-GCM encrypted file bytes.
    Plaintext is NEVER present after encryption.
    """
    header: A2AHeader
    ciphertext_b64: str
    nonce_b64: str
    encrypted_dek_b64: str
    kek_key_id: str
    file_extension: str
    file_size_bytes: int
    ciphertext_sha256: str
    file_index: int
    total_files: int

    @field_validator("file_extension")
    @classmethod
    def validate_extension(cls, v: str) -> str:
        # Matches repo_cloner.py ALLOWED_EXTENSIONS exactly
        allowed = {
            ".py", ".js", ".ts", ".jsx", ".tsx",
            ".java", ".go", ".rs", ".rb",
            ".cpp", ".c", ".h", ".hpp",
            ".cs", ".php", ".sh",
            ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
        }
        if v.lower() not in allowed:
            raise ValueError(f"File extension {v} not in allowed set")
        return v.lower()

    class Config:
        frozen = True


class ASTNode(BaseModel):
    """Sanitized AST node - no strings, no comments, no docstrings."""
    node_type: str
    lineno: Optional[int] = None
    col_offset: Optional[int] = None
    children: List["ASTNode"] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        frozen = True


ASTNode.model_rebuild()


class ASTPayload(BaseModel):
    """
    AST Parser → IR Builder.
    Sanitized AST with all semantic content stripped.
    """
    header: A2AHeader
    file_index: int
    file_extension: str
    root_node: ASTNode
    node_count: int
    depth: int

    # Complexity metrics
    cyclomatic_complexity: int
    cognitive_complexity: int = 0        # ast_parser.py emits this

    import_count: int
    function_count: int
    class_count: int

    # Core anomaly flags (all parsers emit these)
    has_exec_calls: bool = False
    has_eval_calls: bool = False
    has_dynamic_imports: bool = False
    has_network_calls: bool = False
    has_file_io: bool = False

    # Extended anomaly flags (ast_parser.py emits; ir_builder.py reads)
    has_privilege_calls: bool = False
    has_obfuscation: bool = False
    has_high_entropy: bool = False
    has_injection_risk: bool = False
    has_deserialisation: bool = False

    parse_errors: List[str] = Field(default_factory=list)

    class Config:
        frozen = True


class IRNode(BaseModel):
    """Language-agnostic IR node."""
    ir_type: str
    category: str
    risk_level: int = Field(ge=0, le=10)
    children: List["IRNode"] = Field(default_factory=list)
    properties: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        frozen = True


IRNode.model_rebuild()


class DependencyEdge(BaseModel):
    """Edge in dependency graph - no semantic content."""
    source_index: int
    target_index: int
    edge_type: str
    weight: float = 1.0

    class Config:
        frozen = True


class CrossPatternHit(BaseModel):
    """A detected cross-node anomaly pattern."""
    pattern_id: str
    risk_boost: int
    node_indices: List[int]
    description: str

    class Config:
        frozen = True


class IRPayload(BaseModel):
    """IR Builder → ML Analyzer."""
    header: A2AHeader
    file_index: int
    file_extension: str
    ir_nodes: List[IRNode]
    dependency_edges: List[DependencyEdge]
    total_nodes: int
    max_depth: int
    privilege_sensitive_count: int
    network_call_count: int
    io_call_count: int
    dynamic_eval_count: int
    embedding_vector: Optional[List[float]] = None

    class Config:
        frozen = True


class MLRiskScore(BaseModel):
    """Risk scores from ML model - no raw code references."""
    structural_anomaly_score: float = Field(ge=0.0, le=1.0)
    dependency_abuse_score: float = Field(ge=0.0, le=1.0)
    privilege_escalation_score: float = Field(ge=0.0, le=1.0)
    obfuscation_score: float = Field(ge=0.0, le=1.0)
    backdoor_pattern_score: float = Field(ge=0.0, le=1.0)
    overall_risk: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    flagged_patterns: List[str] = Field(default_factory=list)

    class Config:
        frozen = True


class RiskAssessment(BaseModel):
    """ML Analyzer → Policy Engine."""
    header: A2AHeader
    task_id: str
    file_scores: List[MLRiskScore]
    aggregate_risk: float = Field(ge=0.0, le=1.0)
    high_risk_file_count: int
    total_files: int
    circular_dependency_count: int
    external_dependency_count: int
    privileged_api_count: int
    total_ir_nodes: int
    anomalous_pattern_count: int

    class Config:
        frozen = True


class PolicyConstraint(BaseModel):
    """A single policy constraint for IaC generation."""
    constraint_id: str
    constraint_type: str
    severity: str
    description: str
    terraform_snippet: Optional[str] = None

    class Config:
        frozen = True


class PolicyDecision(BaseModel):
    """Policy Engine → IaC Generator."""
    header: A2AHeader
    task_id: str
    decision: str
    confidence: float = Field(ge=0.0, le=1.0)
    risk_summary: str
    constraints: List[PolicyConstraint] = Field(default_factory=list)
    required_mitigations: List[str] = Field(default_factory=list)
    rules_evaluated: int
    rules_triggered: int
    hitl_required: bool = False
    hitl_reason: Optional[str] = None
    approver_id: Optional[str] = None

    class Config:
        frozen = True


class HITLRequest(BaseModel):
    """Policy Engine → Human Operator."""
    header: A2AHeader
    task_id: str
    reason: str
    risk_assessment_summary: str
    aggregate_risk: float
    flagged_patterns: List[str]
    recommended_action: str
    expires_at: float

    class Config:
        frozen = True


class HITLResponse(BaseModel):
    """Human operator decision."""
    header: A2AHeader
    request_id: str
    decision: str
    operator_id: str
    notes: str
    timestamp: float = Field(default_factory=time.time)

    class Config:
        frozen = True


class ViolationEvent(BaseModel):
    """Security violation - triggers VM teardown."""
    header: A2AHeader
    violation_type: str
    agent_role: AgentRole
    vm_id: str
    severity: str
    description: str
    action: str = "TERMINATE_VM"

    class Config:
        frozen = True


class TaskManifest(BaseModel):
    """Orchestrator → All Agents. Task start signal."""
    header: A2AHeader
    task_id: str
    repo_url: str
    requested_by: str
    priority: int = Field(ge=1, le=10, default=5)
    created_at: float = Field(default_factory=time.time)

    class Config:
        frozen = True


def create_header(
    message_type: MessageType,
    sender_role: AgentRole,
    recipient_role: AgentRole,
    task_id: str,
) -> A2AHeader:
    """Factory for A2A message headers."""
    return A2AHeader(
        message_type=message_type,
        sender_role=sender_role,
        recipient_role=recipient_role,
        task_id=task_id,
    )