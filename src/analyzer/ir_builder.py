"""
IR Builder Agent  —  src/analyzer/ir_builder.py

Converts a sanitised ASTPayload into a language-agnostic IRPayload.

IR design principles:
  • Language-agnostic — identical node types for Python, JS, Go, Rust, etc.
  • Non-executable — no code can be reconstructed from the IR
  • Behaviour-centric — captures WHAT the code does, not HOW
  • No semantic content — no names, no strings, no comments

Rich output produced:
  ┌──────────────────────────────────────────────────────────────────────┐
  │ IR node tree        — typed, risk-weighted, depth-annotated          │
  │ Dependency edges    — risk-normalised weights [0,1], typed labels    │
  │ type_frequency      — histogram of all 52 IR token types            │
  │ category_risk_sums  — per-category cumulative risk (defaultdict)    │
  │ cross_patterns      — 19 multi-node anomaly sequences               │
  │ feature_vector      — 100 named numeric signals for ML              │
  │ token_sequence      — flat string for CodeBERT tokeniser            │
  └──────────────────────────────────────────────────────────────────────┘

Cross-node pattern detection (19 patterns):
  EXEC_CHAIN          IMPORT → CALL → EXEC/EVAL
  EXFIL_CHAIN         DYNAMIC + NETWORK in same file
  OBFUSC_EXEC         Obfuscation + dynamic execution
  DESER_EXEC          Deserialization + high-arity CALL
  PRIV_NETWORK        PRIVILEGE + NETWORK in same file
  DEEP_DYNAMIC        DYNAMIC node at depth ≥ 5
  SILENT_EXCEPT       CATCH with only PASS/ellipsis child
  GLOBAL_WRITE        GLOBAL followed by ASSIGN in ≤10 nodes
  SHADOW_IMPORT       IMPORT at depth > 2 (not top-level)
  ASYNC_DYNAMIC       DYNAMIC node within 5 positions of AWAIT
  MULTI_OBFUSC        3+ obfuscation nodes
  HOOK_PATTERN        HOOK + FUNC_DEF in same file
  CONCUR_PRIV         Concurrency spawn + privilege operation
  ENTROPY_EXEC        High-entropy literal blob + EXEC/EVAL
  PICKLE_GADGET       Pickle gadget methods + DESER node
  NATIVE_CODE_LOAD    ctypes/cffi CDLL load + privilege call
  TAINTED_EXEC        exec/eval called with non-constant argument  [NEW]
  HOOK_PERSIST        __del__/__init_subclass__ + network/io       [NEW]
  WEAKREF_EXFIL       weakref hook + network access                [NEW]
"""
from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from src.schemas.a2a_schemas import (
    ASTNode, ASTPayload, AgentRole, CrossPatternHit,
    DependencyEdge, IRNode, IRPayload, MessageType, create_header,
)

logger = logging.getLogger(__name__)

# ── Mapping: ASTNode type → (ir_type, category, base_risk) ──────────────────
#
# 52 IR node types across 16 categories.
# Risk scale: 0 = safe, 10 = critical
#
_AST_TO_IR: Dict[str, Tuple[str, str, int]] = {
    # ── Structure ────────────────────────────────────────────────────────────
    "Module":            ("MODULE",         "structure",    0),
    "Interactive":       ("MODULE",         "structure",    0),
    "Expression":        ("MODULE",         "structure",    0),
    "FunctionDef":       ("FUNC_DEF",       "structure",    1),
    "AsyncFunctionDef":  ("FUNC_DEF",       "structure",    2),
    "ClassDef":          ("CLASS_DEF",      "structure",    1),
    "Lambda":            ("LAMBDA",         "structure",    3),

    # ── Data flow ────────────────────────────────────────────────────────────
    "Assign":            ("ASSIGN",         "data_flow",    0),
    "AugAssign":         ("ASSIGN",         "data_flow",    0),
    "AnnAssign":         ("ASSIGN",         "data_flow",    0),
    "NamedExpr":         ("ASSIGN",         "data_flow",    1),   # walrus :=
    "Delete":            ("DELETE",         "data_flow",    2),
    "Starred":           ("UNPACK",         "data_flow",    1),

    # ── Control flow ─────────────────────────────────────────────────────────
    "Return":            ("RETURN",         "control_flow", 0),
    "Break":             ("BREAK",          "control_flow", 0),
    "Continue":          ("CONTINUE",       "control_flow", 0),
    "Pass":              ("PASS",           "control_flow", 0),
    "If":                ("BRANCH",         "control_flow", 1),
    "For":               ("LOOP",           "control_flow", 1),
    "AsyncFor":          ("LOOP",           "control_flow", 2),
    "While":             ("LOOP",           "control_flow", 1),
    "Match":             ("MATCH",          "control_flow", 1),
    "Assert":            ("ASSERT",         "validation",   0),
    "IfExp":             ("TERNARY",        "control_flow", 0),

    # ── Execution ────────────────────────────────────────────────────────────
    "Call":              ("CALL",           "execution",    2),
    "Await":             ("AWAIT",          "async",        1),
    "Yield":             ("YIELD",          "generator",    1),
    "YieldFrom":         ("YIELD",          "generator",    2),

    # ── Scope manipulation ───────────────────────────────────────────────────
    "Global":            ("GLOBAL",         "scope",        6),
    "Nonlocal":          ("NONLOCAL",       "scope",        3),

    # ── Dependencies ─────────────────────────────────────────────────────────
    "Import":            ("IMPORT",         "dependency",   2),
    "ImportFrom":        ("IMPORT",         "dependency",   2),

    # ── Exception handling ───────────────────────────────────────────────────
    "Try":               ("TRY",            "exception",    1),
    "TryStar":           ("TRY",            "exception",    1),
    "ExceptHandler":     ("CATCH",          "exception",    1),
    "Raise":             ("RAISE",          "exception",    2),

    # ── Resource management ──────────────────────────────────────────────────
    "With":              ("CONTEXT",        "resource",     1),
    "AsyncWith":         ("CONTEXT",        "resource",     2),

    # ── Comprehensions ───────────────────────────────────────────────────────
    "ListComp":          ("COMPREHENSION",  "data_flow",    1),
    "SetComp":           ("COMPREHENSION",  "data_flow",    1),
    "DictComp":          ("COMPREHENSION",  "data_flow",    1),
    "GeneratorExp":      ("COMPREHENSION",  "data_flow",    1),
    "comprehension":     ("GENERATOR",      "data_flow",    1),

    # ── Operators / expressions ──────────────────────────────────────────────
    "BoolOp":            ("BOOL_OP",        "data_flow",    0),
    "BinOp":             ("BIN_OP",         "data_flow",    0),
    "UnaryOp":           ("UNARY_OP",       "data_flow",    0),
    "Compare":           ("COMPARE",        "data_flow",    0),
    "Subscript":         ("SUBSCRIPT",      "data_flow",    0),

    # ── Non-Python nodes (regex parsers / other language frontends) ──────────
    "FUNC_DEF":          ("FUNC_DEF",       "structure",    1),
    "CLASS_DEF":         ("CLASS_DEF",      "structure",    1),
    "IMPORT":            ("IMPORT",         "dependency",   2),
    "IF":                ("BRANCH",         "control_flow", 1),
    "FOR":               ("LOOP",           "control_flow", 1),
    "WHILE":             ("LOOP",           "control_flow", 1),
    "SWITCH":            ("BRANCH",         "control_flow", 1),
    "TRY":               ("TRY",            "exception",    1),
    "CATCH":             ("CATCH",          "exception",    1),
    "ELSE":              ("BRANCH",         "control_flow", 0),
    "ELIF":              ("BRANCH",         "control_flow", 1),
    "RETURN":            ("RETURN",         "control_flow", 0),
    "AWAIT":             ("AWAIT",          "async",        1),
    "MATCH":             ("MATCH",          "control_flow", 1),
    "SELECT":            ("BRANCH",         "control_flow", 1),
    "DEFER":             ("CONTEXT",        "resource",     1),
    "GO":                ("ASYNC_SPAWN",    "async",        2),
    "CASE":              ("BRANCH",         "control_flow", 0),
    "FINALLY":           ("CONTEXT",        "exception",    0),
    "DEPTH_LIMIT":       ("TRUNCATED",      "structure",    0),
    "UNLESS":            ("BRANCH",         "control_flow", 1),
    "RESCUE":            ("CATCH",          "exception",    1),
    "LOOP":              ("LOOP",           "control_flow", 1),
}

# Category → risk multiplier
_CATEGORY_MULTIPLIERS: Dict[str, float] = {
    "structure":    1.0,
    "data_flow":    1.0,
    "control_flow": 1.0,
    "execution":    1.2,
    "dependency":   1.1,
    "exception":    1.0,
    "validation":   0.8,
    "scope":        1.5,
    "resource":     1.1,
    "async":        1.1,
    "generator":    1.0,
    "network":      1.8,
    "io":           1.4,
    "privilege":    2.0,
    "dynamic":      2.2,
    "memory":       1.3,
    "concurrency":  1.2,
    "hook":         1.6,    # NEW: hook/finalizer nodes
    "taint":        2.5,    # NEW: tainted exec/eval
}

# Types that get elevated risk regardless of base mapping
_CRITICAL_TYPES: FrozenSet[str] = frozenset({"DYNAMIC", "PRIVILEGE", "NETWORK", "OBFUSC"})
_HIGH_RISK_TYPES: FrozenSet[str] = frozenset({
    "GLOBAL", "EXEC", "EVAL", "DYNAMIC_IMPORT",
    "HOOK", "DESER", "NATIVE_LOAD", "SYS_POISON",
    "TAINTED_EXEC",  # NEW
})

MAX_IR_DEPTH = 60

# ── Structural attributes forwarded from AST parser ─────────────────────────
# Only non-semantic structural keys are kept.
_KEEP_ATTRS: FrozenSet[str] = frozenset({
    # Node-level structural attributes
    "is_async", "arg_count", "kwonly_count", "posonlyargs",
    "has_varargs", "has_kwargs", "has_defaults",
    "decorator_count", "base_count", "alias_count",
    "import_level", "has_orelse", "handler_count", "item_count",
    "generator_count", "name_count", "operand_count",
    "comparator_count", "has_starargs", "has_star_kwargs",
    "numeric_magnitude", "value_type", "is_slice", "has_metaclass",
    # Module-level anomaly flags from root_node.attributes
    "has_exec_calls", "has_eval_calls", "has_compile_calls",
    "has_dynamic_imports", "has_network_calls", "has_file_io",
    "has_file_write",          # NEW
    "has_privilege_calls", "has_obfuscation", "has_deserialisation",
    "has_reflection", "has_crypto_ops", "has_injection_risk",
    "has_concurrency", "has_thread_local",  # NEW
    "has_global_scope", "has_nested_functions",
    "has_exception_silence", "has_high_entropy",
    "has_metaclass", "has_slot_manipulation",
    "has_star_imports", "has_relative_imports",
    "has_chained_calls", "has_dynamic_attr_set",
    "has_pickle_gadgets", "has_sys_modules_poison", "has_native_lib_load",
    "has_del_hook", "has_subclass_hook", "has_missing_hook", "has_fspath_hook",  # NEW
    "has_tainted_exec", "has_tainted_eval", "has_concat_exec",  # NEW
    "has_format_injection", "has_weakref_hooks",  # NEW
    # Count signals
    "count_exec", "count_eval", "count_compile",
    "count_privilege", "count_network", "count_io", "count_io_write",  # io_write NEW
    "count_obfusc", "count_deserialise", "count_reflection",
    "count_dynamic", "count_inject", "count_concur",
    "count_silent_except", "count_star_imports",
    "count_relative_imports", "chained_call_max_depth",
    "count_hook_dunders", "count_tainted_exec", "count_format_calls",  # NEW
    # Complexity signals
    "cyclomatic_complexity", "cognitive_complexity",
    "halstead_distinct_operators", "halstead_distinct_operands",
    "halstead_total_operators", "halstead_total_operands",
    "total_lines", "blank_ratio",
    "source_entropy",          # NEW: stored float
    "max_nested_function_depth", "decorator_total",
    "function_count", "class_count", "import_count",
    "async_function_count", "try_count", "except_count",
})


# ── Walk result accumulator ──────────────────────────────────────────────────

@dataclass
class _WalkResult:
    flat_nodes:    List[IRNode]         = field(default_factory=list)
    edges:         List[DependencyEdge] = field(default_factory=list)
    type_counts:   Counter              = field(default_factory=Counter)
    category_risk: Dict[str, int]       = field(default_factory=lambda: defaultdict(int))
    max_depth:     int                  = 0
    node_index:    int                  = 0


# ── AST → IR mapping ─────────────────────────────────────────────────────────

def _ast_node_to_ir(ast_node: ASTNode, depth: int) -> Tuple[str, str, int, Dict]:
    """
    Map a single ASTNode to (ir_type, category, base_risk, properties).
    Risk is refined from structural attributes and category multipliers.
    """
    nt = ast_node.node_type
    mapping = _AST_TO_IR.get(nt)
    if mapping is None:
        ir_type, category, base_risk = "EXPR", "data_flow", 0
    else:
        ir_type, category, base_risk = mapping

    attrs = ast_node.attributes or {}
    risk  = base_risk

    # ── Risk refinements from structural attributes ──────────────────────
    if ir_type == "CALL":
        arg_count = attrs.get("arg_count", 0)
        if arg_count > 8:
            risk = max(risk, 4)
        if attrs.get("has_starargs") or attrs.get("has_star_kwargs"):
            risk = max(risk, 3)

    elif ir_type == "IMPORT":
        if attrs.get("import_level", 0) > 1:
            risk = max(risk, 3)   # deep relative import
        if attrs.get("alias_count", 0) > 10:
            risk = max(risk, 3)   # mass import

    elif ir_type == "FUNC_DEF":
        if attrs.get("decorator_count", 0) >= 3:
            risk = max(risk, 2)
        if attrs.get("arg_count", 0) > 10:
            risk = max(risk, 2)
        if attrs.get("is_async"):
            risk = max(risk, 2)

    elif ir_type == "LAMBDA":
        if attrs.get("arg_count", 0) == 0:
            risk = max(risk, 2)

    elif ir_type == "CLASS_DEF":
        if attrs.get("has_metaclass"):
            risk = max(risk, 4)

    elif ir_type == "CATCH":
        if not attrs.get("has_type", True):   # bare except
            risk = max(risk, 2)

    elif ir_type == "GLOBAL":
        risk = max(risk, 6)

    elif ir_type == "COMPREHENSION":
        if attrs.get("is_async"):
            risk = max(risk, 2)

    # ── Apply category multiplier ────────────────────────────────────────
    mult = _CATEGORY_MULTIPLIERS.get(category, 1.0)
    risk_final = min(int(risk * mult), 10)

    # ── Elevated type overrides ──────────────────────────────────────────
    if ir_type in _CRITICAL_TYPES:
        risk_final = max(risk_final, 8)
    elif ir_type in _HIGH_RISK_TYPES:
        risk_final = max(risk_final, 6)

    # ── Forward structural (non-semantic) properties ─────────────────────
    properties: Dict = {k: v for k, v in attrs.items() if k in _KEEP_ATTRS}
    properties["depth"] = depth

    return ir_type, category, risk_final, properties


# ── Iterative tree builder ───────────────────────────────────────────────────

def _build_ir_tree_iterative(root_ast: ASTNode) -> IRNode:
    """
    Convert ASTNode tree → IRNode tree using an explicit stack.
    Fully iterative — no recursion, no Python stack limit concerns.
    Pre-order DFS: parent is always processed before its children.

    Returns the root IRNode only. Flattening is done separately
    in _flatten_and_collect so the two concerns are cleanly separated.
    """
    if not root_ast:
        return IRNode(ir_type="MODULE", category="structure", risk_level=0,
                      properties={"depth": 0}, children=[])

    ir_type, category, risk, props = _ast_node_to_ir(root_ast, 0)
    root_ir = IRNode(ir_type=ir_type, category=category, risk_level=risk,
                     properties=props, children=[])

    # Stack: (ast_node, depth, parent_ir_node)
    # Children pushed in reverse so they are processed left-to-right
    stack: List[Tuple[ASTNode, int, IRNode]] = [
        (child, 1, root_ir) for child in reversed(root_ast.children)
    ]

    while stack:
        ast_n, depth, parent_ir = stack.pop()

        if depth > MAX_IR_DEPTH:
            child_ir = IRNode(
                ir_type="TRUNCATED", category="structure", risk_level=0,
                properties={"depth": depth, "truncated": True}, children=[],
            )
        else:
            ct, cc, cr, cp = _ast_node_to_ir(ast_n, depth)
            child_ir = IRNode(ir_type=ct, category=cc, risk_level=cr,
                              properties=cp, children=[])
            # Push children in reverse so left-child is popped first
            for grandchild in reversed(ast_n.children):
                stack.append((grandchild, depth + 1, child_ir))

        parent_ir.children.append(child_ir)

    return root_ir


# ── Iterative flatten + edge collection ─────────────────────────────────────

def _edge_type(ir_type: str) -> str:
    """Semantic edge label from node type."""
    if ir_type == "IMPORT":                              return "imports"
    if ir_type in ("CALL", "AWAIT", "ASYNC_SPAWN"):     return "calls"
    if ir_type in ("CLASS_DEF", "FUNC_DEF"):            return "defines"
    if ir_type in ("CATCH", "TRY"):                     return "handles"
    if ir_type in ("DYNAMIC", "PRIVILEGE", "NETWORK",
                   "OBFUSC", "SYS_POISON", "NATIVE_LOAD",
                   "TAINTED_EXEC"):                     return "risks"
    if ir_type in ("GLOBAL", "NONLOCAL"):               return "scopes"
    if ir_type in ("IO", "DESER", "MEMORY"):            return "accesses"
    if ir_type == "CONCUR":                             return "spawns"
    if ir_type in ("HOOK", "DEL_HOOK", "SUBCLASS_HOOK"):return "hooks"
    return "uses"


def _flatten_and_collect(root: IRNode, result: _WalkResult) -> None:
    """
    Pre-order iterative flatten.
    Assigns monotonically-increasing indices.
    Builds parent→child edges with risk-normalised weights in [0, 1].
    Accumulates type_counts, category_risk, max_depth in one pass.

    Edge weight = risk_level / 10.0 (max 1.0 for risk=10)
    This gives a cleaner signal range than the previous 1.0 + risk * 0.15.
    """
    # Stack: (ir_node, depth, parent_index)
    stack: List[Tuple[IRNode, int, int]] = [(root, 0, -1)]

    while stack:
        node, depth, parent_idx = stack.pop()

        my_idx = result.node_index
        result.node_index += 1

        result.flat_nodes.append(node)
        result.type_counts[node.ir_type] += 1
        result.category_risk[node.category] += node.risk_level
        if depth > result.max_depth:
            result.max_depth = depth

        if parent_idx >= 0:
            etype  = _edge_type(node.ir_type)
            weight = round(node.risk_level / 10.0, 3)   # normalised to [0,1]
            result.edges.append(DependencyEdge(
                source_index=parent_idx,
                target_index=my_idx,
                edge_type=etype,
                weight=weight,
            ))

        # Push children in reverse for left-to-right traversal
        for child in reversed(node.children):
            stack.append((child, depth + 1, my_idx))


# ── Cross-node pattern detection ─────────────────────────────────────────────

# Pattern registry: id → (risk_boost, description)
CROSS_PATTERNS: Dict[str, Tuple[int, str]] = {
    "EXEC_CHAIN":       (8,  "IMPORT → CALL → EXEC/EVAL sequence"),
    "EXFIL_CHAIN":      (9,  "DYNAMIC + NETWORK in same file"),
    "OBFUSC_EXEC":      (8,  "Obfuscation + dynamic execution"),
    "DESER_EXEC":       (8,  "Deserialization + high-arity CALL"),
    "PRIV_NETWORK":     (7,  "Privilege escalation + network access"),
    "DEEP_DYNAMIC":     (6,  "DYNAMIC node at depth ≥ 5"),
    "SILENT_EXCEPT":    (4,  "CATCH block with only PASS/ellipsis child"),
    "GLOBAL_WRITE":     (5,  "GLOBAL declaration + nearby ASSIGN"),
    "SHADOW_IMPORT":    (4,  "IMPORT at depth > 2 (not top-level)"),
    "ASYNC_DYNAMIC":    (7,  "DYNAMIC node within 5 positions of AWAIT"),
    "MULTI_OBFUSC":     (6,  "3+ obfuscation nodes in same file"),
    "HOOK_PATTERN":     (5,  "Runtime hook/monkey-patch + FUNC_DEF"),
    "CONCUR_PRIV":      (6,  "Concurrency spawn + privilege operation"),
    "ENTROPY_EXEC":     (7,  "High-entropy blob + execution primitive"),
    "PICKLE_GADGET":    (8,  "Pickle gadget method + DESER call (RCE vector)"),
    "NATIVE_CODE_LOAD": (7,  "Native library load (ctypes/cffi) + privilege call"),
    "TAINTED_EXEC":     (9,  "exec/eval called with non-constant argument"),       # NEW
    "HOOK_PERSIST":     (7,  "__del__/__init_subclass__ + network or IO access"),  # NEW
    "WEAKREF_EXFIL":    (6,  "weakref finalizer hook + network access"),           # NEW
}


def _detect_cross_patterns(
    flat_nodes: List[IRNode],
    type_counts: Counter,
) -> Tuple[List[CrossPatternHit], int]:
    """
    Scan the flat node list for multi-node anomaly patterns.
    Returns (list_of_hits, total_extra_risk).
    Each pattern fires at most once per file.
    """
    hits: List[CrossPatternHit] = []
    seen: Set[str] = set()
    extra_risk = 0

    def _hit(pid: str, indices: List[int]) -> None:
        nonlocal extra_risk
        if pid in seen:
            return
        seen.add(pid)
        boost, desc = CROSS_PATTERNS[pid]
        hits.append(CrossPatternHit(
            pattern_id=pid,
            risk_boost=boost,
            node_indices=indices,
            description=desc,
        ))
        extra_risk += boost

    # ── Pre-compute index sets — O(n), done once ─────────────────────────
    def _idx(pred) -> List[int]:
        return [i for i, n in enumerate(flat_nodes) if pred(n)]

    def _prop(n: IRNode, key: str) -> bool:
        v = n.properties.get(key, 0)
        return bool(v) if not isinstance(v, (int, float)) else v != 0

    dyn_idx    = _idx(lambda n: n.ir_type == "DYNAMIC"
                                or _prop(n, "has_exec_calls")
                                or _prop(n, "has_eval_calls")
                                or _prop(n, "has_dynamic_imports"))
    net_idx    = _idx(lambda n: n.ir_type == "NETWORK"
                                or n.category == "network"
                                or _prop(n, "has_network_calls"))
    priv_idx   = _idx(lambda n: n.ir_type in ("PRIVILEGE", "GLOBAL")
                                or _prop(n, "has_privilege_calls"))
    obf_idx    = _idx(lambda n: n.ir_type == "OBFUSC"
                                or _prop(n, "has_obfuscation"))
    exec_idx   = _idx(lambda n: n.ir_type == "DYNAMIC"
                                and (_prop(n, "has_exec_calls")
                                     or _prop(n, "has_eval_calls")
                                     or n.properties.get("source") in
                                        ("exec_detected", "eval_detected",
                                         "injection_detected")))
    deser_idx  = _idx(lambda n: n.ir_type == "DESER"
                                or _prop(n, "has_deserialisation"))
    hook_idx   = _idx(lambda n: n.ir_type == "HOOK")
    concur_idx = _idx(lambda n: n.ir_type in ("ASYNC_SPAWN", "CONCUR")
                                or _prop(n, "has_concurrency"))
    entropy_idx= _idx(lambda n: _prop(n, "has_high_entropy")
                                or n.properties.get("source") == "entropy_blob_detected")
    await_set  = {i for i, n in enumerate(flat_nodes)
                  if n.ir_type in ("AWAIT", "ASYNC_SPAWN")}
    import_idx = _idx(lambda n: n.ir_type == "IMPORT")
    assign_set = {i for i, n in enumerate(flat_nodes) if n.ir_type == "ASSIGN"}
    global_idx = _idx(lambda n: n.ir_type == "GLOBAL")
    high_arity = _idx(lambda n: n.ir_type == "CALL"
                                and n.properties.get("arg_count", 0) > 4)
    pickle_idx = _idx(lambda n: _prop(n, "has_pickle_gadgets"))
    native_idx = _idx(lambda n: _prop(n, "has_native_lib_load")
                                or n.ir_type == "NATIVE_LOAD")
    # NEW index sets
    tainted_idx = _idx(lambda n: n.ir_type == "TAINTED_EXEC"
                                 or _prop(n, "has_tainted_exec")
                                 or _prop(n, "has_tainted_eval"))
    del_hook_idx= _idx(lambda n: _prop(n, "has_del_hook")
                                 or _prop(n, "has_subclass_hook")
                                 or n.properties.get("source") in
                                    ("del_hook_detected", "subclass_hook_detected"))
    weakref_idx = _idx(lambda n: _prop(n, "has_weakref_hooks")
                                 or n.properties.get("source") == "weakref_hook_detected")
    io_idx      = _idx(lambda n: n.ir_type == "IO"
                                 or n.category == "io"
                                 or _prop(n, "has_file_io"))

    # ── EXFIL_CHAIN ──────────────────────────────────────────────────────
    if dyn_idx and net_idx:
        _hit("EXFIL_CHAIN", dyn_idx[:1] + net_idx[:1])

    # ── PRIV_NETWORK ─────────────────────────────────────────────────────
    if priv_idx and net_idx:
        _hit("PRIV_NETWORK", priv_idx[:1] + net_idx[:1])

    # ── OBFUSC_EXEC ──────────────────────────────────────────────────────
    if obf_idx and dyn_idx:
        _hit("OBFUSC_EXEC", obf_idx[:1] + dyn_idx[:1])

    # ── DESER_EXEC ───────────────────────────────────────────────────────
    if (deser_idx or obf_idx) and high_arity:
        src = deser_idx[:1] if deser_idx else obf_idx[:1]
        _hit("DESER_EXEC", src + high_arity[:1])

    # ── DEEP_DYNAMIC ─────────────────────────────────────────────────────
    deep_dyn = [i for i in dyn_idx if flat_nodes[i].properties.get("depth", 0) >= 5]
    if deep_dyn:
        _hit("DEEP_DYNAMIC", deep_dyn[:2])

    # ── SILENT_EXCEPT ────────────────────────────────────────────────────
    silent = [i for i, n in enumerate(flat_nodes)
              if n.ir_type == "CATCH"
              and (len(n.children) == 0
                   or (len(n.children) == 1 and n.children[0].ir_type == "PASS"))]
    if silent:
        _hit("SILENT_EXCEPT", silent[:3])

    # ── GLOBAL_WRITE ─────────────────────────────────────────────────────
    for gi in global_idx:
        nearby = [j for j in range(gi + 1, min(gi + 10, len(flat_nodes)))
                  if j in assign_set]
        if nearby:
            _hit("GLOBAL_WRITE", [gi] + nearby[:1])
            break

    # ── SHADOW_IMPORT ────────────────────────────────────────────────────
    shadow = [i for i in import_idx
              if flat_nodes[i].properties.get("depth", 0) > 2]
    if shadow:
        _hit("SHADOW_IMPORT", shadow[:3])

    # ── ASYNC_DYNAMIC ────────────────────────────────────────────────────
    # Note: proximity is positional in the flat pre-order list (not depth-based).
    # This is an approximation; same-function co-occurrence of DYNAMIC+AWAIT
    # is the intended signal, which positional proximity approximates well.
    async_dyn = [i for i in dyn_idx
                 if any(abs(i - aw) <= 5 for aw in await_set)]
    if async_dyn:
        _hit("ASYNC_DYNAMIC", async_dyn[:2])

    # ── MULTI_OBFUSC ─────────────────────────────────────────────────────
    if len(obf_idx) >= 3:
        _hit("MULTI_OBFUSC", obf_idx[:3])

    # ── HOOK_PATTERN ─────────────────────────────────────────────────────
    if hook_idx and type_counts.get("FUNC_DEF", 0) > 0:
        func_def_idx = [i for i, n in enumerate(flat_nodes) if n.ir_type == "FUNC_DEF"]
        _hit("HOOK_PATTERN", hook_idx[:1] + func_def_idx[:1])

    # ── CONCUR_PRIV ──────────────────────────────────────────────────────
    if concur_idx and priv_idx:
        _hit("CONCUR_PRIV", concur_idx[:1] + priv_idx[:1])

    # ── ENTROPY_EXEC ─────────────────────────────────────────────────────
    if entropy_idx and exec_idx:
        _hit("ENTROPY_EXEC", entropy_idx[:1] + exec_idx[:1])

    # ── EXEC_CHAIN: IMPORT < CALL < EXEC (order-preserving) ─────────────
    if import_idx and type_counts.get("CALL", 0) > 0 and exec_idx:
        call_idx = [i for i, n in enumerate(flat_nodes) if n.ir_type == "CALL"]
        min_import = import_idx[0]
        valid_calls = [c for c in call_idx if c > min_import]
        if valid_calls:
            min_call = valid_calls[0]
            valid_exec = [e for e in exec_idx if e > min_call]
            if valid_exec:
                _hit("EXEC_CHAIN", [min_import, min_call, valid_exec[0]])

    # ── PICKLE_GADGET ────────────────────────────────────────────────────
    if pickle_idx and deser_idx:
        _hit("PICKLE_GADGET", pickle_idx[:1] + deser_idx[:1])

    # ── NATIVE_CODE_LOAD ─────────────────────────────────────────────────
    if native_idx and priv_idx:
        _hit("NATIVE_CODE_LOAD", native_idx[:1] + priv_idx[:1])

    # ── TAINTED_EXEC (NEW) ───────────────────────────────────────────────
    if tainted_idx:
        _hit("TAINTED_EXEC", tainted_idx[:2])

    # ── HOOK_PERSIST (NEW) ───────────────────────────────────────────────
    # __del__ or __init_subclass__ combined with network or IO = persistence vector
    if del_hook_idx and (net_idx or io_idx):
        secondary = (net_idx or io_idx)[:1]
        _hit("HOOK_PERSIST", del_hook_idx[:1] + secondary)

    # ── WEAKREF_EXFIL (NEW) ──────────────────────────────────────────────
    if weakref_idx and net_idx:
        _hit("WEAKREF_EXFIL", weakref_idx[:1] + net_idx[:1])

    return hits, extra_risk


# ── Anomaly injection from AST flags ────────────────────────────────────────

def _inject_anomaly_nodes(
    ast_payload: ASTPayload,
    flat_nodes: List[IRNode],
    edges: List[DependencyEdge],
    start_idx: int,
) -> Tuple[int, int, int, int]:
    """
    Append synthetic IR nodes for anomalies detected at AST level.
    All injected nodes connect to MODULE root (index 0) via 'flags' edges.
    Returns (privilege_delta, network_delta, io_delta, dynamic_delta).
    """
    ROOT = 0
    next_idx = start_idx
    priv_d = net_d = io_d = dyn_d = 0

    def _add(ir_type: str, category: str, risk: int, src: str, extra: Dict = None) -> None:
        nonlocal next_idx
        props: Dict = {"source": src, "injected": True, "depth": 1}
        if extra:
            props.update(extra)
        node = IRNode(ir_type=ir_type, category=category, risk_level=risk,
                      properties=props, children=[])
        flat_nodes.append(node)
        edges.append(DependencyEdge(
            source_index=ROOT,
            target_index=next_idx,
            edge_type="flags",
            weight=round(risk / 10.0, 3),   # normalised weight
        ))
        next_idx += 1

    root_attrs = ast_payload.root_node.attributes or {}

    def _flag(key: str) -> bool:
        v = root_attrs.get(key, 0)
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v != 0
        return bool(v)

    def _cnt(key: str) -> int:
        return int(root_attrs.get(key, 0))

    def _flt(key: str) -> float:
        try:
            return float(root_attrs.get(key, 0.0))
        except (TypeError, ValueError):
            return 0.0

    # ── Core ASTPayload flags ─────────────────────────────────────────────
    if ast_payload.has_exec_calls:
        _add("DYNAMIC", "privilege", 9, "exec_detected",
             {"tainted": _flag("has_tainted_exec"),
              "concat":  _flag("has_concat_exec"),
              "count":   _cnt("count_exec")})
        dyn_d += 1; priv_d += 1

    if ast_payload.has_eval_calls:
        _add("DYNAMIC", "privilege", 9, "eval_detected",
             {"tainted": _flag("has_tainted_eval"),
              "count":   _cnt("count_eval")})
        dyn_d += 1; priv_d += 1

    if ast_payload.has_dynamic_imports:
        _add("DYNAMIC", "dependency", 7, "dynamic_import",
             {"count": _cnt("count_dynamic")})
        dyn_d += 1

    if ast_payload.has_network_calls:
        _add("NETWORK", "network", 6, "network_detected",
             {"count": _cnt("count_network")})
        net_d += 1

    if ast_payload.has_file_io:
        _add("IO", "io", 4, "file_io_detected",
             {"count":   _cnt("count_io"),
              "writes":  _cnt("count_io_write")})   # NEW: write count
        io_d += 1

    if ast_payload.has_privilege_calls:
        _add("PRIVILEGE", "privilege", 8, "privilege_detected",
             {"count": _cnt("count_privilege")})
        priv_d += 1

    if ast_payload.has_obfuscation:
        _add("OBFUSC", "dynamic", 8, "obfuscation_detected",
             {"count": _cnt("count_obfusc")})
        dyn_d += 1

    if ast_payload.has_high_entropy:
        _add("OBFUSC", "dynamic", 7, "entropy_blob_detected",
             {"has_high_entropy": 1,
              "source_entropy": _flt("source_entropy")})  # NEW: include value
        dyn_d += 1

    if ast_payload.has_injection_risk:
        _add("DYNAMIC", "execution", 9, "injection_detected",
             {"count": _cnt("count_inject")})
        dyn_d += 1

    if ast_payload.has_deserialisation:
        _add("DESER", "execution", 8, "deserialisation_detected",
             {"count": _cnt("count_deserialise")})
        dyn_d += 1

    # ── Extended flags from root_node.attributes ──────────────────────────
    if _flag("has_reflection"):
        _add("DYNAMIC", "scope", 6, "reflection_detected",
             {"count": _cnt("count_reflection")})
        dyn_d += 1

    if _flag("has_exception_silence"):
        _add("CATCH", "exception", 3, "silent_exception",
             {"count": _cnt("count_silent_except")})

    if _flag("has_metaclass"):
        _add("CLASS_DEF", "scope", 4, "metaclass_detected")

    if _flag("has_dynamic_attr_set"):
        _add("DYNAMIC", "scope", 6, "dynamic_attr_set")
        dyn_d += 1

    if _flag("has_pickle_gadgets"):
        _add("HOOK", "dynamic", 8, "pickle_gadget_detected",
             {"has_pickle_gadgets": 1})
        dyn_d += 1

    if _flag("has_sys_modules_poison"):
        _add("DYNAMIC", "dynamic", 9, "sys_modules_poison",
             {"has_sys_modules_poison": 1})
        dyn_d += 1

    if _flag("has_native_lib_load"):
        _add("PRIVILEGE", "privilege", 7, "native_lib_load",
             {"has_native_lib_load": 1})
        priv_d += 1

    if _flag("has_concurrency"):
        _add("CONCUR", "concurrency", 4, "concurrency_detected",
             {"count":       _cnt("count_concur"),
              "thread_local": _flag("has_thread_local")})  # NEW

    if _flag("has_crypto_ops"):
        _add("IO", "io", 2, "crypto_ops_detected")

    # ── NEW: taint, hooks, weakref ─────────────────────────────────────────
    if _flag("has_tainted_exec") or _flag("has_tainted_eval"):
        _add("TAINTED_EXEC", "taint", 10, "tainted_exec_detected",
             {"count_tainted": _cnt("count_tainted_exec"),
              "has_concat":    _flag("has_concat_exec")})
        dyn_d += 1

    if _flag("has_del_hook"):
        _add("HOOK", "hook", 7, "del_hook_detected",
             {"hook_type": "del"})
        dyn_d += 1

    if _flag("has_subclass_hook"):
        _add("HOOK", "hook", 6, "subclass_hook_detected",
             {"hook_type": "init_subclass"})
        dyn_d += 1

    if _flag("has_missing_hook"):
        _add("HOOK", "hook", 5, "missing_hook_detected",
             {"hook_type": "missing"})

    if _flag("has_fspath_hook"):
        _add("HOOK", "hook", 5, "fspath_hook_detected",
             {"hook_type": "fspath"})

    if _flag("has_weakref_hooks"):
        _add("HOOK", "hook", 5, "weakref_hook_detected")

    if _flag("has_file_write"):
        _add("IO", "io", 6, "file_write_detected",
             {"count_writes": _cnt("count_io_write")})
        io_d += 1

    if _flag("has_format_injection"):
        _add("DYNAMIC", "execution", 5, "format_injection_surface",
             {"count_format": _cnt("count_format_calls")})

    if _flag("has_thread_local"):
        _add("CONCUR", "concurrency", 6, "thread_local_detected")

    return priv_d, net_d, io_d, dyn_d


# ── Token sequence builder ────────────────────────────────────────────────────

# Canonical 52-token vocabulary for CodeBERT (extended from 46)
IR_VOCAB: List[str] = [
    # Structure
    "MODULE", "FUNC_DEF", "CLASS_DEF", "LAMBDA",
    # Dependencies
    "IMPORT", "CALL", "AWAIT", "ASYNC_SPAWN",
    # Data
    "ASSIGN", "DELETE", "UNPACK",
    "BOOL_OP", "BIN_OP", "UNARY_OP", "COMPARE", "SUBSCRIPT",
    # Control
    "BRANCH", "LOOP", "MATCH", "TERNARY",
    "RETURN", "BREAK", "CONTINUE", "PASS",
    # Scope
    "GLOBAL", "NONLOCAL",
    # Exception
    "TRY", "CATCH", "RAISE", "CONTEXT",
    # Generators
    "YIELD", "COMPREHENSION", "GENERATOR",
    # Risk nodes
    "DYNAMIC", "PRIVILEGE", "NETWORK", "OBFUSC",
    "IO", "DESER", "MEMORY", "CONCUR", "HOOK",
    "NATIVE_LOAD", "SYS_POISON",
    # NEW risk nodes
    "TAINTED_EXEC", "DEL_HOOK", "SUBCLASS_HOOK", "WEAKREF_HOOK",
    "FILE_WRITE", "THREAD_LOCAL",
    # Meta
    "ASSERT", "EXPR", "TRUNCATED",
]
_VOCAB_SET: FrozenSet[str] = frozenset(IR_VOCAB)

# High-signal tokens — amplified at token sequence tail
_AMPLIFIED: FrozenSet[str] = frozenset({
    "DYNAMIC", "PRIVILEGE", "NETWORK", "OBFUSC",
    "GLOBAL", "LAMBDA", "DESER", "HOOK", "MEMORY",
    "NATIVE_LOAD", "SYS_POISON",
    "TAINTED_EXEC", "DEL_HOOK", "SUBCLASS_HOOK",  # NEW
    "FILE_WRITE", "THREAD_LOCAL",                  # NEW
})


def _build_token_sequence(flat_nodes: List[IRNode], max_tokens: int = 512) -> str:
    """
    Build a flat space-separated IR token string for CodeBERT input.
    High-risk tokens are appended again at the tail to boost attention weight.
    Unknown types are normalised to EXPR.

    Tail budget = min(len(amplified), max_tokens // 4) — at most 25% tail.
    Body budget = max_tokens - tail_budget — no truncation risk.
    """
    tokens: List[str] = []
    amplified: List[str] = []

    for node in flat_nodes:
        t = node.ir_type if node.ir_type in _VOCAB_SET else "EXPR"
        tokens.append(t)
        if t in _AMPLIFIED:
            amplified.append(t)

    tail_budget = min(len(amplified), max_tokens // 4)
    body_budget = max_tokens - tail_budget

    seq = tokens[:body_budget]
    seq.extend(amplified[:tail_budget])
    return seq  # return the list directly, not a joined string


# ── Feature vector builder ─────────────────────────────────────────────────

def _build_feature_vector(
    flat_nodes:    List[IRNode],
    type_counts:   Counter,
    category_risk: Dict[str, int],
    max_depth:     int,
    pattern_hits:  List[CrossPatternHit],
    ast_payload:   ASTPayload,
) -> Dict[str, float]:
    """
    Build a 100-dimensional named feature vector.
    All features are structural — zero semantic content.

    Dimensions:
      52 token type frequencies            (one per IR_VOCAB entry)
      11 graph metrics
       5 risk distribution stats
       9 category risk sums (normalised)
       4 cross-node pattern features
       5 AST-level structural signals
       7 complexity/halstead signals
       7 new threat/taint signals
    = 100 features
    """
    n = max(len(flat_nodes), 1)
    root_attrs = ast_payload.root_node.attributes or {}

    # ── Token frequency histogram (52 dims) ──────────────────────────────
    token_freq = {f"freq_{t}": type_counts.get(t, 0) / n for t in IR_VOCAB}

    # ── Graph metrics (11 dims) ───────────────────────────────────────────
    high_risk   = sum(1 for nd in flat_nodes if nd.risk_level >= 7)
    med_risk    = sum(1 for nd in flat_nodes if 4 <= nd.risk_level < 7)
    ctrl_flow   = (type_counts.get("BRANCH", 0) + type_counts.get("LOOP", 0)
                   + type_counts.get("MATCH", 0))
    io_nodes    = sum(1 for nd in flat_nodes if nd.category == "io"        or nd.ir_type == "IO")
    net_nodes   = sum(1 for nd in flat_nodes if nd.category == "network"   or nd.ir_type == "NETWORK")
    priv_nodes  = sum(1 for nd in flat_nodes if nd.ir_type in ("PRIVILEGE", "GLOBAL"))
    dyn_nodes   = sum(1 for nd in flat_nodes if nd.ir_type == "DYNAMIC")
    hook_nodes  = sum(1 for nd in flat_nodes if nd.ir_type == "HOOK" or nd.category == "hook")
    concur_nodes= sum(1 for nd in flat_nodes if nd.ir_type == "CONCUR")
    deser_nodes = sum(1 for nd in flat_nodes if nd.ir_type == "DESER")
    taint_nodes = sum(1 for nd in flat_nodes if nd.ir_type == "TAINTED_EXEC" or nd.category == "taint")

    # ── Risk distribution (5 dims) ────────────────────────────────────────
    risk_vals   = [nd.risk_level for nd in flat_nodes]
    mean_risk   = sum(risk_vals) / n
    max_risk_v  = max(risk_vals, default=0)
    sorted_risk = sorted(risk_vals)
    p90_risk    = sorted_risk[int(0.9 * len(sorted_risk))] if sorted_risk else 0
    p75_risk    = sorted_risk[int(0.75 * len(sorted_risk))] if sorted_risk else 0

    # ── Category risk sums normalised (9 dims) ────────────────────────────
    cat_risk_norm = {
        f"cat_risk_{cat}": category_risk.get(cat, 0) / n
        for cat in ("execution", "scope", "network", "io", "privilege",
                    "dynamic", "dependency", "exception", "memory")
    }

    # ── Cross-node pattern features (4 dims) ──────────────────────────────
    hit_ids = {h.pattern_id for h in pattern_hits}

    # ── Complexity signals from root attributes ───────────────────────────
    def _ra(key: str, default: float = 0.0) -> float:
        try:
            return float(root_attrs.get(key, default))
        except (TypeError, ValueError):
            return default

    h_η1    = _ra("halstead_distinct_operators")
    h_η2    = _ra("halstead_distinct_operands")
    h_N1    = _ra("halstead_total_operators")
    h_N2    = _ra("halstead_total_operands")
    h_vocab = max(h_η1 + h_η2, 1.0)
    h_volume = min((h_N1 + h_N2) * math.log2(h_vocab), 10_000.0)

    # ── New threat/taint signals (7 dims) ────────────────────────────────
    source_entropy  = _ra("source_entropy")
    tainted_exec_ct = _ra("count_tainted_exec")
    io_write_ct     = _ra("count_io_write")
    hook_dunder_ct  = _ra("count_hook_dunders")
    format_call_ct  = _ra("count_format_calls")
    has_concat_exec = float(bool(root_attrs.get("has_concat_exec", 0)))
    has_weakref     = float(bool(root_attrs.get("has_weakref_hooks", 0)))

    return {
        # Token frequencies (52)
        **token_freq,
        # Graph metrics (11)
        "total_nodes":       float(n),
        "max_depth":         float(max_depth),
        "high_risk_ratio":   high_risk / n,
        "med_risk_ratio":    med_risk / n,
        "ctrl_flow_ratio":   ctrl_flow / n,
        "io_ratio":          io_nodes / n,
        "net_ratio":         net_nodes / n,
        "priv_ratio":        priv_nodes / n,
        "dyn_ratio":         dyn_nodes / n,
        "hook_ratio":        hook_nodes / n,
        "taint_ratio":       taint_nodes / n,
        # Risk distribution (5)
        "mean_risk":         mean_risk,
        "max_risk":          max_risk_v / 10.0,
        "p90_risk":          p90_risk / 10.0,
        "p75_risk":          p75_risk / 10.0,
        "risk_variance":     (sum((r - mean_risk) ** 2 for r in risk_vals) / n),
        # Category risk sums (9)
        **cat_risk_norm,
        # Cross-node patterns (4)
        "pattern_hit_count":   float(len(pattern_hits)),
        "pattern_total_boost": sum(h.risk_boost for h in pattern_hits) / 100.0,
        "has_exfil_pattern":   float("EXFIL_CHAIN" in hit_ids),
        "has_exec_pattern":    float(bool(hit_ids & {
            "EXEC_CHAIN", "OBFUSC_EXEC", "DESER_EXEC", "ENTROPY_EXEC", "TAINTED_EXEC",
        })),
        # AST-level structural signals (5)
        "import_count":        float(ast_payload.import_count),
        "function_count":      float(ast_payload.function_count),
        "class_count":         float(ast_payload.class_count),
        "cyclomatic":          _ra("cyclomatic_complexity"),
        "depth":               float(ast_payload.depth),
        # Complexity signals (7)
        "cognitive":           _ra("cognitive_complexity"),
        "halstead_volume":     h_volume / 10_000.0,
        "halstead_vocab":      h_vocab,
        "blank_ratio":         _ra("blank_ratio"),
        "max_nested_depth":    _ra("max_nested_function_depth"),
        "try_except_ratio":    (
            _ra("except_count") / max(_ra("try_count"), 1.0)
        ),
        "decorator_density":   (
            _ra("decorator_total") / max(_ra("function_count", 1.0), 1.0)
        ),
        # New threat / taint signals (7)
        "source_entropy":      source_entropy / 8.0,    # normalised to [0,1]
        "tainted_exec_count":  tainted_exec_ct,
        "io_write_count":      io_write_ct,
        "hook_dunder_count":   hook_dunder_ct,
        "format_call_count":   format_call_ct,
        "has_concat_exec":     has_concat_exec,
        "has_weakref_hooks":   has_weakref,
        # Advanced threat flags (previously 3, now merged into new section)
        "has_pickle_gadgets":  float(bool(root_attrs.get("has_pickle_gadgets", 0))),
        "has_native_load":     float(bool(root_attrs.get("has_native_lib_load", 0))),
        "has_sys_poison":      float(bool(root_attrs.get("has_sys_modules_poison", 0))),
        # Extra ratio signals
        "concur_ratio":        concur_nodes / n,
        "deser_ratio":         deser_nodes / n,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def build_ir_from_ast(ast_payload: ASTPayload) -> IRPayload:
    """
    Convert ASTPayload → richly-annotated IRPayload in a single pipeline.

    Steps:
      1. Build IR tree (iterative, depth-limited) → returns root IRNode only
      2. Flatten tree + collect edges/metrics (iterative, single pass)
      3. Inject anomaly nodes from AST-level flags
      4. Update counters for injected nodes
      5. Detect 19 cross-node patterns
      6. Build token sequence for CodeBERT (52-token vocab)
      7. Build 100-dim named feature vector
      8. Assemble and return IRPayload — all computed fields included
    """
    header = create_header(
        MessageType.IR_PAYLOAD,
        AgentRole.IR_BUILDER,
        AgentRole.ML_ANALYZER,
        ast_payload.header.task_id,
    )

    # ① Build IR tree — returns root only (no implicit state)
    root_ir = _build_ir_tree_iterative(ast_payload.root_node)

    # ② Flatten + collect — populates result.flat_nodes, edges, counters
    result = _WalkResult()
    _flatten_and_collect(root_ir, result)

    flat_nodes  = result.flat_nodes
    edges       = result.edges
    type_counts = result.type_counts

    # ③ Inject anomaly nodes from AST flags
    start_idx = result.node_index
    priv_d, net_d, io_d, dyn_d = _inject_anomaly_nodes(
        ast_payload, flat_nodes, edges, start_idx
    )

    # ④ Update counters for injected nodes
    for nd in flat_nodes[start_idx:]:
        type_counts[nd.ir_type] += 1
        result.category_risk[nd.category] += nd.risk_level

    # ⑤ Cross-node pattern detection
    patterns, extra_risk = _detect_cross_patterns(flat_nodes, type_counts)

    # ⑥ Token sequence (52-token vocab)
    token_seq = _build_token_sequence(flat_nodes)

    # ⑦ Feature vector (100 dims)
    features = _build_feature_vector(
        flat_nodes, type_counts,
        dict(result.category_risk),
        result.max_depth,
        patterns, ast_payload,
    )

    # ⑧ Scalar metrics
    privilege_count = (
        type_counts.get("GLOBAL", 0) + type_counts.get("PRIVILEGE", 0) + priv_d
    )
    network_count   = type_counts.get("NETWORK", 0) + net_d
    io_count        = type_counts.get("IO", 0) + io_d
    dynamic_count   = type_counts.get("DYNAMIC", 0) + dyn_d
    high_risk_count = sum(1 for nd in flat_nodes if nd.risk_level >= 7)

    pattern_ids = [h.pattern_id for h in patterns]

    logger.debug(
        "IR built: nodes=%d edges=%d depth=%d priv=%d net=%d io=%d dyn=%d "
        "patterns=%s features=%d",
        len(flat_nodes), len(edges), result.max_depth,
        privilege_count, network_count, io_count, dynamic_count,
        pattern_ids, len(features),
    )

    return IRPayload(
        header=header,
        file_index=ast_payload.file_index,
        file_extension=ast_payload.file_extension,
        ir_nodes=flat_nodes,
        dependency_edges=edges,
        total_nodes=len(flat_nodes),
        max_depth=result.max_depth,
        privilege_sensitive_count=privilege_count,
        network_call_count=network_count,
        io_call_count=io_count,
        dynamic_eval_count=dynamic_count,
        high_risk_node_count=high_risk_count,
        pattern_extra_risk=extra_risk,
        # ── Rich outputs — fully propagated to ML analyzer ──────────────
        cross_patterns=patterns,
        token_sequence=token_seq,
        feature_vector=features,
        type_frequency=dict(type_counts),
        category_risk_sums=dict(result.category_risk),
        embedding_vector=None,   # filled by ML agent
    )