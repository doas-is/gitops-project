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

import hashlib
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
    # Fetcher → Parser
    ENCRYPTED_FILE_PAYLOAD = "encrypted_file_payload"
    # Parser → IR Builder
    AST_PAYLOAD = "ast_payload"
    # IR Builder → ML Analyzer
    IR_PAYLOAD = "ir_payload"
    # ML Analyzer → Policy Engine
    RISK_ASSESSMENT = "risk_assessment"
    # Policy Engine → IaC Generator
    POLICY_DECISION = "policy_decision"
    # Control
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
    signature: Optional[str] = None  # Set after signing
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
    # Encrypted content (base64-encoded ciphertext)
    ciphertext_b64: str
    # Nonce for AES-GCM (base64)
    nonce_b64: str
    # Encrypted DEK wrapped with KEK from Key Vault
    encrypted_dek_b64: str
    # Key Vault key ID used to wrap DEK
    kek_key_id: str
    # File metadata (no semantic content)
    file_extension: str
    file_size_bytes: int
    # Content hash for integrity (of ciphertext, not plaintext)
    ciphertext_sha256: str
    # Sequential index within task batch
    file_index: int
    total_files: int

    @field_validator("file_extension")
    @classmethod
    def validate_extension(cls, v: str) -> str:
        allowed = {".py", ".js", ".ts", ".java", ".go", ".rs", ".rb", ".cpp", ".c", ".h",
                   ".cs", ".php", ".sh", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"}
        if v.lower() not in allowed:
            raise ValueError(f"File extension {v} not in allowed set")
        return v.lower()

    class Config:
        frozen = True


class ASTNode(BaseModel):
    """Sanitized AST node - no strings, no comments, no docstrings."""
    node_type: str  # e.g. "FunctionDef", "Import", "Call"
    lineno: Optional[int] = None
    col_offset: Optional[int] = None
    children: List["ASTNode"] = Field(default_factory=list)
    # Structural attributes only - no names, no values
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
    # Structural complexity metrics only
    cyclomatic_complexity: int
    import_count: int
    function_count: int
    class_count: int
    # Anomaly flags from parser
    has_exec_calls: bool = False
    has_eval_calls: bool = False
    has_dynamic_imports: bool = False
    has_network_calls: bool = False
    has_file_io: bool = False
    parse_errors: List[str] = Field(default_factory=list)

    class Config:
        frozen = True


class IRNode(BaseModel):
    """
    Language-agnostic Intermediate Representation node.
    Behavior-centric, non-executable, no semantic labels.
    """
    ir_type: str  # e.g. "IMPORT", "CALL", "BRANCH", "LOOP", "ASSIGN"
    category: str  # "control_flow", "io", "network", "privilege", "dependency"
    risk_level: int = Field(ge=0, le=10)  # 0=safe, 10=critical
    children: List["IRNode"] = Field(default_factory=list)
    # Structural properties only
    properties: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        frozen = True


IRNode.model_rebuild()


class DependencyEdge(BaseModel):
    """Edge in dependency graph - no semantic content."""
    source_index: int
    target_index: int
    edge_type: str  # "imports", "calls", "inherits", "uses"
    weight: float = 1.0

    class Config:
        frozen = True


class IRPayload(BaseModel):
    """
    IR Builder → ML Analyzer.
    Complete IR for a single file.
    """
    header: A2AHeader
    file_index: int
    file_extension: str
    ir_nodes: List[IRNode]
    dependency_edges: List[DependencyEdge]
    # Structural metrics
    total_nodes: int
    max_depth: int
    privilege_sensitive_count: int
    network_call_count: int
    io_call_count: int
    dynamic_eval_count: int
    # Embedding placeholder (filled by ML agent)
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
    flagged_patterns: List[str] = Field(default_factory=list)  # Pattern IDs, not code

    class Config:
        frozen = True


class RiskAssessment(BaseModel):
    """
    ML Analyzer → Policy Engine.
    Risk profile - no code, no AST, no IR.
    """
    header: A2AHeader
    task_id: str
    file_scores: List[MLRiskScore]
    aggregate_risk: float = Field(ge=0.0, le=1.0)
    high_risk_file_count: int
    total_files: int
    # Dependency graph summary
    circular_dependency_count: int
    external_dependency_count: int
    privileged_api_count: int
    # Structural summaries
    total_ir_nodes: int
    anomalous_pattern_count: int

    class Config:
        frozen = True


class PolicyConstraint(BaseModel):
    """A single policy constraint for IaC generation."""
    constraint_id: str
    constraint_type: str  # "network_isolation", "privilege_restriction", "resource_limit", etc.
    severity: str  # "mandatory", "recommended", "informational"
    description: str
    terraform_snippet: Optional[str] = None

    class Config:
        frozen = True


class PolicyDecision(BaseModel):
    """
    Policy Engine → IaC Generator.
    Approved/rejected with constraints.
    """
    header: A2AHeader
    task_id: str
    decision: str  # "APPROVE", "REJECT", "APPROVE_WITH_CONSTRAINTS"
    confidence: float = Field(ge=0.0, le=1.0)
    risk_summary: str  # Human-readable summary (no code)
    constraints: List[PolicyConstraint] = Field(default_factory=list)
    required_mitigations: List[str] = Field(default_factory=list)
    # Audit trail
    rules_evaluated: int
    rules_triggered: int
    hitl_required: bool = False
    hitl_reason: Optional[str] = None
    approver_id: Optional[str] = None  # Set if HITL approved

    class Config:
        frozen = True


class HITLRequest(BaseModel):
    """
    Policy Engine → Human Operator.
    Escalation request with risk summary.
    """
    header: A2AHeader
    task_id: str
    reason: str
    risk_assessment_summary: str
    aggregate_risk: float
    flagged_patterns: List[str]
    recommended_action: str
    expires_at: float  # Unix timestamp

    class Config:
        frozen = True


class HITLResponse(BaseModel):
    """Human operator decision."""
    header: A2AHeader
    request_id: str
    decision: str  # "APPROVE", "REJECT"
    operator_id: str
    notes: str
    timestamp: float = Field(default_factory=time.time)

    class Config:
        frozen = True


class ViolationEvent(BaseModel):
    """Security violation - triggers VM teardown."""
    header: A2AHeader
    violation_type: str  # "disk_write_attempt", "plaintext_exposure", "policy_breach", etc.
    agent_role: AgentRole
    vm_id: str
    severity: str  # "critical", "high", "medium"
    description: str
    action: str = "TERMINATE_VM"

    class Config:
        frozen = True


class TaskManifest(BaseModel):
    """Orchestrator → All Agents. Task start signal."""
    header: A2AHeader
    task_id: str
    repo_url: str  # Opaque - only Fetcher uses it
    requested_by: str  # User/system identifier
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