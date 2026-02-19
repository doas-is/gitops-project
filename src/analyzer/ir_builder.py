"""
Converts sanitized AST to language-agnostic Intermediate Representation (IR).

IR properties:
  - Language-agnostic
  - Non-executable
  - Behavior-centric (what the code DOES structurally, not what it means)
  - No semantic labels
  - No natural language

IR node categories:
  - IMPORT: External dependency
  - CALL: Function invocation
  - BRANCH: Conditional logic
  - LOOP: Iteration
  - ASSIGN: Variable assignment
  - RETURN: Value return
  - EXCEPTION: Error handling
  - IO: File/stream operations
  - NETWORK: Network operations
  - PRIVILEGE: Elevated permission operations
  - DYNAMIC: Dynamic evaluation
  - CLASS_DEF: Type definition
  - FUNC_DEF: Function definition
  - MODULE: Top-level scope
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from src.schemas.a2a_schemas import (
    ASTNode, ASTPayload, AgentRole, DependencyEdge,
    IRNode, IRPayload, MessageType, create_header,
)

logger = logging.getLogger(__name__)

# AST node type → IR type mapping
_AST_TO_IR: Dict[str, Tuple[str, str, int]] = {
    # (ir_type, category, base_risk)
    "Module": ("MODULE", "structure", 0),
    "FunctionDef": ("FUNC_DEF", "structure", 1),
    "AsyncFunctionDef": ("FUNC_DEF", "structure", 2),
    "ClassDef": ("CLASS_DEF", "structure", 1),
    "Return": ("RETURN", "control_flow", 0),
    "Delete": ("DELETE", "memory", 2),
    "Assign": ("ASSIGN", "data_flow", 0),
    "AugAssign": ("ASSIGN", "data_flow", 0),
    "AnnAssign": ("ASSIGN", "data_flow", 0),
    "For": ("LOOP", "control_flow", 1),
    "AsyncFor": ("LOOP", "control_flow", 2),
    "While": ("LOOP", "control_flow", 1),
    "If": ("BRANCH", "control_flow", 0),
    "With": ("CONTEXT", "resource", 1),
    "AsyncWith": ("CONTEXT", "resource", 2),
    "Raise": ("RAISE", "exception", 1),
    "Try": ("TRY", "exception", 1),
    "TryStar": ("TRY", "exception", 1),
    "ExceptHandler": ("CATCH", "exception", 1),
    "Import": ("IMPORT", "dependency", 2),
    "ImportFrom": ("IMPORT", "dependency", 2),
    "Global": ("GLOBAL", "scope", 3),
    "Nonlocal": ("NONLOCAL", "scope", 2),
    "Call": ("CALL", "execution", 2),
    "Await": ("AWAIT", "async", 1),
    "Yield": ("YIELD", "generator", 1),
    "YieldFrom": ("YIELD", "generator", 1),
    "Lambda": ("LAMBDA", "structure", 2),
    "ListComp": ("COMPREHENSION", "data_flow", 1),
    "SetComp": ("COMPREHENSION", "data_flow", 1),
    "DictComp": ("COMPREHENSION", "data_flow", 1),
    "GeneratorExp": ("COMPREHENSION", "data_flow", 1),
    "Assert": ("ASSERT", "validation", 0),
    "Match": ("MATCH", "control_flow", 1),
}

# High-risk patterns that elevate risk score
_HIGH_RISK_IR_TYPES = frozenset({"GLOBAL", "DYNAMIC", "PRIVILEGE"})
_MEDIUM_RISK_IR_TYPES = frozenset({"LAMBDA", "DELETE", "NONLOCAL"})


def _ast_to_ir_node(ast_node: ASTNode, depth: int = 0) -> Optional[IRNode]:
    """
    Convert a single ASTNode to IRNode.
    Returns None for purely syntactic nodes with no behavioral significance.
    """
    if depth > 50:
        return IRNode(
            ir_type="TRUNCATED",
            category="structure",
            risk_level=0,
            properties={"depth_exceeded": True},
        )

    node_type = ast_node.node_type

    # Check for special high-risk patterns based on attributes
    ir_type_override = None
    category_override = None
    risk_override = None

    if node_type == "Call":
        attrs = ast_node.attributes
        # arg_count 0 with no kwargs often indicates simple getter
        # arg_count > 5 may indicate complex privilege call
        if attrs.get("arg_count", 0) > 5:
            risk_override = 4

    # Look up base mapping
    mapping = _AST_TO_IR.get(node_type)
    if mapping is None:
        # Unknown/expression node - create minimal IR entry
        ir_type = "EXPR"
        category = "data_flow"
        base_risk = 0
    else:
        ir_type, category, base_risk = mapping

    if ir_type_override:
        ir_type = ir_type_override
    if category_override:
        category = category_override

    risk_level = risk_override if risk_override is not None else base_risk

    # Escalate risk for known high-risk types
    if ir_type in _HIGH_RISK_IR_TYPES:
        risk_level = max(risk_level, 6)
    elif ir_type in _MEDIUM_RISK_IR_TYPES:
        risk_level = max(risk_level, 4)

    # Properties (structural, not semantic)
    properties: Dict = {}
    attrs = ast_node.attributes
    if attrs:
        if "is_async" in attrs:
            properties["is_async"] = attrs["is_async"]
        if "arg_count" in attrs:
            properties["arg_count"] = attrs["arg_count"]
        if "decorator_count" in attrs:
            properties["decorator_count"] = attrs["decorator_count"]
        if "base_count" in attrs:
            properties["base_count"] = attrs["base_count"]
        if "alias_count" in attrs:
            properties["alias_count"] = attrs["alias_count"]
        if "level" in attrs:
            properties["import_level"] = attrs["level"]

    # Recurse
    children = []
    for child in ast_node.children:
        child_ir = _ast_to_ir_node(child, depth + 1)
        if child_ir is not None:
            children.append(child_ir)

    return IRNode(
        ir_type=ir_type,
        category=category,
        risk_level=min(risk_level, 10),
        children=children,
        properties=properties,
    )


def _collect_edges(
    ir_node: IRNode,
    parent_idx: int,
    counter: List[int],
    edges: List[DependencyEdge],
) -> int:
    """Collect dependency edges from IR tree. Returns node index."""
    my_idx = counter[0]
    counter[0] += 1

    for child in ir_node.children:
        child_idx = counter[0]
        _collect_edges(child, my_idx, counter, edges)

        # Add edge based on relationship
        if ir_node.ir_type == "IMPORT":
            edge_type = "imports"
        elif ir_node.ir_type in ("CALL", "AWAIT"):
            edge_type = "calls"
        elif ir_node.ir_type == "CLASS_DEF":
            edge_type = "inherits"
        else:
            edge_type = "uses"

        # Risk-weighted edge
        weight = 1.0 + child.risk_level * 0.1

        edges.append(DependencyEdge(
            source_index=my_idx,
            target_index=child_idx,
            edge_type=edge_type,
            weight=weight,
        ))

    return my_idx


def _count_ir_types(ir_node: IRNode, counts: Dict[str, int]) -> None:
    """Count IR node types recursively."""
    counts[ir_node.ir_type] = counts.get(ir_node.ir_type, 0) + 1
    for child in ir_node.children:
        _count_ir_types(child, counts)


def _max_ir_depth(ir_node: IRNode, depth: int = 0) -> int:
    if not ir_node.children:
        return depth
    return max(_max_ir_depth(c, depth + 1) for c in ir_node.children)


def build_ir_from_ast(ast_payload: ASTPayload) -> IRPayload:
    """
    Convert ASTPayload to IRPayload.
    
    The IR is the sole representation passed to downstream agents.
    No AST data is forwarded.
    """
    header = create_header(
        MessageType.IR_PAYLOAD,
        AgentRole.IR_BUILDER,
        AgentRole.ML_ANALYZER,
        ast_payload.header.task_id,
    )

    # Convert root AST node to IR
    root_ir = _ast_to_ir_node(ast_payload.root_node)
    if root_ir is None:
        root_ir = IRNode(ir_type="MODULE", category="structure", risk_level=0)

    # Flatten IR for analysis
    ir_nodes: List[IRNode] = []

    def flatten(node: IRNode) -> None:
        ir_nodes.append(node)
        for child in node.children:
            flatten(child)

    flatten(root_ir)

    # Build dependency edges
    edges: List[DependencyEdge] = []
    counter = [0]
    _collect_edges(root_ir, -1, counter, edges)

    # Count structural metrics
    type_counts: Dict[str, int] = {}
    _count_ir_types(root_ir, type_counts)

    privilege_count = type_counts.get("PRIVILEGE", 0) + type_counts.get("GLOBAL", 0)
    network_count = sum(1 for n in ir_nodes if n.category == "network")
    io_count = sum(1 for n in ir_nodes if n.category == "io")
    dynamic_count = type_counts.get("DYNAMIC", 0)

    # Incorporate AST-level anomaly flags into IR risk
    if ast_payload.has_exec_calls:
        ir_nodes.append(IRNode(ir_type="DYNAMIC", category="privilege", risk_level=9,
                               properties={"source": "exec_detected"}))
    if ast_payload.has_eval_calls:
        ir_nodes.append(IRNode(ir_type="DYNAMIC", category="privilege", risk_level=9,
                               properties={"source": "eval_detected"}))
    if ast_payload.has_dynamic_imports:
        ir_nodes.append(IRNode(ir_type="DYNAMIC", category="dependency", risk_level=7,
                               properties={"source": "dynamic_import"}))
    if ast_payload.has_network_calls:
        network_count += 1
    if ast_payload.has_file_io:
        io_count += 1

    max_depth = _max_ir_depth(root_ir)

    return IRPayload(
        header=header,
        file_index=ast_payload.file_index,
        file_extension=ast_payload.file_extension,
        ir_nodes=ir_nodes,
        dependency_edges=edges,
        total_nodes=len(ir_nodes),
        max_depth=max_depth,
        privilege_sensitive_count=privilege_count,
        network_call_count=network_count,
        io_call_count=io_count,
        dynamic_eval_count=dynamic_count,
    )