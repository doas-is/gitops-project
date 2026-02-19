"""
AST Parser Agent (analyzer/ast_parser.py)

Parses source code syntax ONLY.
ALL semantic content is stripped:
  - String literals → removed
  - Comments → removed  
  - Docstrings → removed
  - Variable names → anonymized (replaced with positional IDs)
  - Function/class names → anonymized
  - Import names → hashed (not readable)

Produces a sanitized structural AST with no semantic leakage.
"""
from __future__ import annotations

import ast
import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.schemas.a2a_schemas import ASTNode, ASTPayload

logger = logging.getLogger(__name__)

# Privilege-sensitive builtin/stdlib patterns (by hash, not name)
# These are structural markers, not readable strings
_SENSITIVE_BUILTINS = frozenset({
    hashlib.sha256(b"exec").hexdigest()[:8],
    hashlib.sha256(b"eval").hexdigest()[:8],
    hashlib.sha256(b"compile").hexdigest()[:8],
    hashlib.sha256(b"__import__").hexdigest()[:8],
    hashlib.sha256(b"importlib").hexdigest()[:8],
    hashlib.sha256(b"subprocess").hexdigest()[:8],
    hashlib.sha256(b"os.system").hexdigest()[:8],
    hashlib.sha256(b"socket").hexdigest()[:8],
    hashlib.sha256(b"urllib").hexdigest()[:8],
    hashlib.sha256(b"requests").hexdigest()[:8],
    hashlib.sha256(b"open").hexdigest()[:8],
    hashlib.sha256(b"ctypes").hexdigest()[:8],
    hashlib.sha256(b"pickle").hexdigest()[:8],
})

_NETWORK_PATTERNS = frozenset({
    hashlib.sha256(b"socket").hexdigest()[:8],
    hashlib.sha256(b"requests").hexdigest()[:8],
    hashlib.sha256(b"urllib").hexdigest()[:8],
    hashlib.sha256(b"http").hexdigest()[:8],
    hashlib.sha256(b"aiohttp").hexdigest()[:8],
    hashlib.sha256(b"httpx").hexdigest()[:8],
})

_IO_PATTERNS = frozenset({
    hashlib.sha256(b"open").hexdigest()[:8],
    hashlib.sha256(b"read").hexdigest()[:8],
    hashlib.sha256(b"write").hexdigest()[:8],
    hashlib.sha256(b"pathlib").hexdigest()[:8],
    hashlib.sha256(b"shutil").hexdigest()[:8],
    hashlib.sha256(b"os.path").hexdigest()[:8],
})


def _hash_identifier(name: str) -> str:
    """Replace identifier name with 8-char structural hash."""
    return "ID_" + hashlib.sha256(name.encode()).hexdigest()[:8]


class SemanticStrippingVisitor(ast.NodeTransformer):
    """
    AST transformer that removes ALL semantic content.
    
    After transformation:
    - No string values exist
    - No identifier names exist (replaced with hashes)  
    - No comments (already stripped by ast module)
    - Docstrings replaced with empty strings
    """

    def visit_Str(self, node):  # Python 3.7 compat
        return ast.Constant(value="", kind=None)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            return ast.Constant(value="", kind=None)
        if isinstance(node.value, bytes):
            return ast.Constant(value=b"", kind=None)
        return node  # Keep numeric constants (structural)

    def visit_JoinedStr(self, node):  # f-strings
        return ast.Constant(value="", kind=None)

    def visit_Name(self, node):
        # Replace name with hash
        node.id = _hash_identifier(node.id)
        return node

    def visit_Attribute(self, node):
        node.attr = _hash_identifier(node.attr)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        node.name = _hash_identifier(node.name)
        # Remove docstring (first statement if it's a string)
        if (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(getattr(node.body[0], "value", None), ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            node.body = node.body[1:]
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        node.name = _hash_identifier(node.name)
        # Remove class docstring
        if (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(getattr(node.body[0], "value", None), ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            node.body = node.body[1:]
        return self.generic_visit(node)

    def visit_Import(self, node):
        # Anonymize module names but keep structure
        new_aliases = []
        for alias in node.names:
            new_name = _hash_identifier(alias.name)
            new_asname = _hash_identifier(alias.asname) if alias.asname else None
            new_aliases.append(ast.alias(name=new_name, asname=new_asname))
        node.names = new_aliases
        return node

    def visit_ImportFrom(self, node):
        if node.module:
            node.module = _hash_identifier(node.module)
        new_aliases = []
        for alias in node.names:
            new_name = _hash_identifier(alias.name)
            new_asname = _hash_identifier(alias.asname) if alias.asname else None
            new_aliases.append(ast.alias(name=new_name, asname=new_asname))
        node.names = new_aliases
        return node

    def visit_Global(self, node):
        node.names = [_hash_identifier(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [_hash_identifier(n) for n in node.names]
        return node


def _ast_to_a2a_node(node: ast.AST, depth: int = 0) -> ASTNode:
    """Convert Python AST node to A2A schema ASTNode (sanitized)."""
    if depth > 100:  # Prevent stack overflow on deeply nested code
        return ASTNode(node_type="DEPTH_LIMIT", attributes={"truncated": True})

    node_type = type(node).__name__
    attributes: Dict[str, Any] = {}

    # Extract only structural (non-semantic) attributes
    if isinstance(node, ast.Constant):
        attributes["type"] = type(node.value).__name__
        # Value NOT included - semantic content
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        attributes["is_async"] = isinstance(node, ast.AsyncFunctionDef)
        attributes["decorator_count"] = len(node.decorator_list)
        attributes["arg_count"] = len(node.args.args)
        attributes["has_varargs"] = node.args.vararg is not None
        attributes["has_kwargs"] = node.args.kwarg is not None
    elif isinstance(node, ast.ClassDef):
        attributes["base_count"] = len(node.bases)
        attributes["decorator_count"] = len(node.decorator_list)
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        attributes["alias_count"] = len(node.names)
        if isinstance(node, ast.ImportFrom):
            attributes["level"] = node.level or 0
    elif isinstance(node, ast.Call):
        attributes["arg_count"] = len(node.args)
        attributes["kwarg_count"] = len(node.keywords)
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        attributes["is_async"] = isinstance(node, ast.AsyncFor)
    elif isinstance(node, ast.comprehension):
        attributes["is_async"] = bool(node.is_async)

    # Recurse into children
    children = []
    for child in ast.iter_child_nodes(node):
        children.append(_ast_to_a2a_node(child, depth + 1))

    return ASTNode(
        node_type=node_type,
        lineno=getattr(node, "lineno", None),
        col_offset=getattr(node, "col_offset", None),
        children=children,
        attributes=attributes,
    )


class AnomalyDetector:
    """Structural anomaly detection on raw AST (before stripping)."""

    @staticmethod
    def detect(tree: ast.AST) -> Dict[str, Any]:
        flags = {
            "has_exec_calls": False,
            "has_eval_calls": False,
            "has_dynamic_imports": False,
            "has_network_calls": False,
            "has_file_io": False,
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("exec",):
                    flags["has_exec_calls"] = True
                elif func_name in ("eval",):
                    flags["has_eval_calls"] = True
                elif func_name in ("__import__",) or (
                    isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"
                ):
                    flags["has_dynamic_imports"] = True
                elif func_name in ("open", "read", "write"):
                    flags["has_file_io"] = True

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if any(net in alias.name.lower() for net in ("socket", "urllib", "requests", "http", "aiohttp")):
                        flags["has_network_calls"] = True
                    if alias.name.lower() in ("subprocess", "os"):
                        flags["has_exec_calls"] = True

        return flags


def _compute_complexity(tree: ast.AST) -> int:
    """McCabe cyclomatic complexity approximation."""
    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler,
                              ast.With, ast.Assert, ast.comprehension)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
    return complexity


def parse_python_source(source_bytes: bytes, file_index: int, task_id: str) -> ASTPayload:
    """
    Parse Python source bytes into a sanitized ASTPayload.
    
    1. Parse to AST
    2. Detect anomalies BEFORE stripping (for accuracy)
    3. Strip all semantic content
    4. Convert to A2A schema
    5. Discard original AST
    """
    from src.schemas.a2a_schemas import (
        AgentRole, MessageType, create_header
    )

    parse_errors: List[str] = []
    header = create_header(
        MessageType.AST_PAYLOAD,
        AgentRole.AST_PARSER,
        AgentRole.IR_BUILDER,
        task_id,
    )

    try:
        source_text = source_bytes.decode("utf-8", errors="replace")
    except Exception:
        source_text = source_bytes.decode("latin-1", errors="replace")

    try:
        tree = ast.parse(source_text, type_comments=False)
    except SyntaxError as e:
        parse_errors.append(f"SyntaxError:L{e.lineno}")
        # Return minimal payload for malformed files
        return ASTPayload(
            header=header,
            file_index=file_index,
            file_extension=".py",
            root_node=ASTNode(node_type="Module", children=[], attributes={}),
            node_count=0,
            depth=0,
            cyclomatic_complexity=0,
            import_count=0,
            function_count=0,
            class_count=0,
            parse_errors=parse_errors,
        )
    except Exception as e:
        parse_errors.append(f"ParseError:{type(e).__name__}")
        return ASTPayload(
            header=header,
            file_index=file_index,
            file_extension=".py",
            root_node=ASTNode(node_type="Module", children=[], attributes={}),
            node_count=0,
            depth=0,
            cyclomatic_complexity=0,
            import_count=0,
            function_count=0,
            class_count=0,
            parse_errors=parse_errors,
        )

    # Detect anomalies on ORIGINAL tree (before anonymization)
    anomalies = AnomalyDetector.detect(tree)
    complexity = _compute_complexity(tree)

    # Count structural elements
    import_count = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)))
    function_count = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    class_count = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
    node_count = sum(1 for _ in ast.walk(tree))

    # Compute max depth
    def max_depth(node, d=0):
        return max((max_depth(c, d + 1) for c in ast.iter_child_nodes(node)), default=d)

    depth = max_depth(tree)

    # NOW strip semantic content
    stripper = SemanticStrippingVisitor()
    stripped_tree = stripper.visit(tree)
    ast.fix_missing_locations(stripped_tree)

    # Convert to A2A schema
    root_node = _ast_to_a2a_node(stripped_tree)

    # Discard source text and trees
    del source_text
    del tree
    del stripped_tree

    return ASTPayload(
        header=header,
        file_index=file_index,
        file_extension=".py",
        root_node=root_node,
        node_count=node_count,
        depth=depth,
        cyclomatic_complexity=complexity,
        import_count=import_count,
        function_count=function_count,
        class_count=class_count,
        parse_errors=parse_errors,
        **anomalies,
    )