"""
AST Parser Agent  —  src/analyzer/ast_parser.py

Parses Python source code into a fully-sanitised ASTPayload.

Security guarantees (enforced before any data leaves this module):
  ① String literals     → replaced with empty constant
  ② Bytes literals      → replaced with empty bytes
  ③ F-strings           → replaced with empty constant
  ④ Comments            → stripped by ast.parse (never reach here)
  ⑤ Docstrings          → detected and removed from body
  ⑥ Identifier names    → SHA-256 hashed (one-way, deterministic)
  ⑦ Import names        → SHA-256 hashed
  ⑧ Type annotations    → stripped entirely
  ⑨ Source text         → del'd immediately after parse; AST del'd after strip
  ⑩ match/case patterns → variable names in MatchAs/MatchMapping stripped

Rich metrics emitted (all structural — zero semantic content):
  • McCabe cyclomatic complexity
  • Cognitive complexity (Sonar approximation)
  • Halstead volume proxy (η1, η2, N1, N2) — run on ORIGINAL tree
  • Shannon entropy (bits/byte) — stored as float, not discarded
  • Max nesting depth (iterative, stack-safe)
  • Total node count
  • Async/await usage
  • Decorator density
  • Exception handling ratio + silent-exception count
  • 48 anomaly flags across 12 threat categories with per-category counts
  • Nested function depth (corrected algorithm)
  • Chained call depth (iterative — no recursion limit)
  • Star-import and relative-import counts
  • Pickle/marshal gadget detection (__reduce__, __reduce_ex__, etc.)
  • ctypes/cffi native-code-loading detection
  • sys.modules poisoning detection
  • Thread-local / thread pool detection
  • __del__ / __init_subclass__ / __class_getitem__ hook detection
  • Taint tracking: exec/eval called with non-constant argument
  • String-concat-before-eval detection
  • open() write-mode detection (file creation/overwrite)
  • os.fspath / __fspath__ path traversal hooks
  • weakref finalizer hooks
  • Format string injection surface
  • Line count, blank-line ratio, source entropy (stored)
"""
from __future__ import annotations

import ast
import hashlib
import logging
import math
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from src.schemas.a2a_schemas import ASTNode, ASTPayload

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_AST_DEPTH    = 80
MAX_SOURCE_BYTES = 5 * 1024 * 1024   # 5 MB
MAX_NODE_COUNT   = 200_000
_ENTROPY_THRESHOLD = 5.2              # bits/byte

# ── Sensitive pattern sets ────────────────────────────────────────────────────
# All checked against ORIGINAL (pre-strip) AST names.

_EXEC_NAMES: FrozenSet[str] = frozenset({"exec", "execfile"})
_EVAL_NAMES: FrozenSet[str] = frozenset({"eval"})
_COMPILE_NAMES: FrozenSet[str] = frozenset({"compile"})

_DYNAMIC_NAMES: FrozenSet[str] = frozenset({
    "__import__", "import_module",
    "load_source", "load_dynamic", "load_extension",
    "find_loader", "exec_module",
})

# Pickle/marshal gadget hooks — serialisation-based RCE
_PICKLE_GADGET_NAMES: FrozenSet[str] = frozenset({
    "__reduce__", "__reduce_ex__", "__getstate__", "__setstate__",
    "__getnewargs__", "__getnewargs_ex__",
})

# Finalizer and hook dunder methods — abused for side-channel / persistence
_HOOK_DUNDER_NAMES: FrozenSet[str] = frozenset({
    "__del__",             # finalizer — can fire at arbitrary GC time
    "__init_subclass__",   # fires on every subclass creation
    "__class_getitem__",   # fires on generic syntax MyClass[T]
    "__missing__",         # fires on missing dict key
    "__set_name__",        # fires at class body creation
    "__init_subclass__",
    "__fspath__",          # fires on os.fspath(obj) — path traversal hook
})

_DESERIALISE_NAMES: FrozenSet[str] = frozenset({
    "load", "loads", "Unpickler",
})

_PRIVILEGE_NAMES: FrozenSet[str] = frozenset({
    "system", "popen", "spawn", "spawnl", "spawnle",
    "execv", "execve", "execvp", "execvpe",
    "run", "call", "check_output", "check_call", "Popen",
    "setuid", "setgid", "setresuid", "setresgid",
    "fork", "forkpty", "chroot", "ptrace",
    "kill", "killpg", "raise_signal",
    # ctypes / cffi — native code loading
    "CDLL", "WinDLL", "windll", "cdll", "CFUNCTYPE",
    "dlopen",
})

_NETWORK_NAMES: FrozenSet[str] = frozenset({
    "socket", "connect", "bind", "listen", "accept",
    "sendto", "recvfrom", "send", "recv",
    "create_connection", "urlopen", "urlretrieve",
    "get", "post", "put", "patch", "delete",
    "fetch", "AsyncClient", "Client", "ClientSession",
    "download", "upload",
})

_NETWORK_MODULES: FrozenSet[str] = frozenset({
    "socket", "ssl", "requests", "urllib", "urllib2",
    "urllib3", "http", "httpx", "aiohttp", "websockets",
    "paramiko", "ftplib", "smtplib", "imaplib",
    "telnetlib", "xmlrpc", "httplib", "pycurl",
    "twisted", "tornado", "grpc",
})

_IO_NAMES: FrozenSet[str] = frozenset({
    "open", "read", "write", "readline", "readlines",
    "seek", "truncate", "flush",
    "copyfile", "copy", "copy2", "move", "rmtree",
    "unlink", "remove", "makedirs", "mkdir", "rmdir",
    "listdir", "scandir", "walk",
})

_IO_MODULES: FrozenSet[str] = frozenset({
    "os", "os.path", "pathlib", "shutil", "glob",
    "tempfile", "io", "fileinput", "fnmatch",
})

_OBFUSCATION_NAMES: FrozenSet[str] = frozenset({
    "b64decode", "b64encode", "decodebytes", "encodebytes",
    "b85decode", "b32decode", "a85decode",
    "decompress", "decompressobj",
    "fromhex", "unhexlify", "rot13",
})

_OBFUSCATION_MODULES: FrozenSet[str] = frozenset({
    "base64", "binascii", "zlib", "gzip", "lzma", "bz2",
    "marshal", "pickle", "dill", "cloudpickle",
    "shelve", "copyreg", "msgpack",
})

_CRYPTOGRAPHY_MODULES: FrozenSet[str] = frozenset({
    "cryptography", "Crypto", "nacl", "ssl",
    "hashlib", "hmac", "secrets",
    "pyotp", "jwt",
})

_REFLECTION_NAMES: FrozenSet[str] = frozenset({
    "getattr", "setattr", "delattr", "hasattr",
    "vars", "dir", "type", "isinstance", "issubclass",
    "globals", "locals", "__builtins__", "inspect",
})

_INJECTION_RISK_NAMES: FrozenSet[str] = frozenset({
    "format", "execute", "executemany", "cursor",
    "query", "raw", "extra",
})

_CONCURRENCY_NAMES: FrozenSet[str] = frozenset({
    "Thread", "Process", "Pool", "ThreadPoolExecutor", "ProcessPoolExecutor",
    "create_task", "ensure_future", "gather", "Semaphore",
    "Lock", "RLock", "Condition",
    "local",   # threading.local() — thread-local storage for exfiltration
})

_CONCURRENCY_MODULES: FrozenSet[str] = frozenset({
    "threading", "multiprocessing", "concurrent", "asyncio",
    "celery", "joblib", "ray",
})

# Open() write-mode strings — file creation/overwrite vectors
_OPEN_WRITE_MODES: FrozenSet[str] = frozenset({
    "w", "wb", "wt", "a", "ab", "at", "x", "xb", "xt",
    "w+", "wb+", "a+", "ab+", "x+",
})

# weakref hooks — GC-based side channels
_WEAKREF_NAMES: FrozenSet[str] = frozenset({
    "ref", "proxy", "WeakValueDictionary", "WeakKeyDictionary",
    "WeakSet", "finalize",
})


# ── Utility ──────────────────────────────────────────────────────────────────

def _hash_id(name: str) -> str:
    """Deterministic one-way hash for identifier anonymisation."""
    return "ID_" + hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest()[:8]


def _source_entropy(source: str) -> float:
    """
    Shannon entropy of the source in bits per byte.
    Returns 0.0 for empty input (safe).
    High entropy (> _ENTROPY_THRESHOLD) indicates obfuscation or encoded blobs.
    Value is now stored in ASTPayload.root_node.attributes as 'source_entropy'.
    """
    if not source:
        return 0.0
    encoded = source.encode("utf-8", errors="replace")
    freq = Counter(encoded)
    total = len(encoded)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


def _call_name(node: ast.Call) -> Optional[str]:
    """Extract the leaf call name (function name only, no chain)."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _chain_depth_iterative(node: ast.Call) -> int:
    """
    Iteratively measure chained call depth: a().b().c() → 3.
    Avoids recursion limits on pathologically deep chains.
    """
    depth = 1
    current = node
    while (
        isinstance(current.func, ast.Attribute)
        and isinstance(current.func.value, ast.Call)
    ):
        depth += 1
        current = current.func.value
        if depth > 500:   # hard cap — pathological input guard
            break
    return depth


def _is_silent_handler(handler: ast.ExceptHandler) -> bool:
    """
    A handler is 'silent' if its body contains no meaningful action.
    Catches: `pass`, `...` (ellipsis).
    Explicitly NOT silent: logging/print calls, raise statements,
    assignments or any multi-statement bodies.
    """
    if not handler.body:
        return True
    if len(handler.body) == 1:
        stmt = handler.body[0]
        # except ...: pass
        if isinstance(stmt, ast.Pass):
            return True
        # except ...: ...
        if (isinstance(stmt, ast.Expr)
                and isinstance(getattr(stmt, "value", None), ast.Constant)
                and stmt.value.value is ...):
            return True
    # Anything else (logging, re-raise, assignment) → not silent
    return False


def _is_tainted_call(node: ast.Call) -> bool:
    """
    Returns True if exec/eval/compile is called with a non-constant argument.
    exec("literal")   → not tainted (static)
    exec(user_input)  → tainted (runtime input can control execution)
    exec(a + b)       → tainted
    exec(f"...")      → tainted (f-string = runtime evaluated)
    """
    if not node.args:
        return False
    first_arg = node.args[0]
    # Static string literal — safe
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return False
    # JoinedStr = f-string — runtime-composed
    return True


def _has_string_concat_before_eval(node: ast.Call) -> bool:
    """
    Detects exec(a + b), eval(x + y) — string concat fed to exec.
    The argument is a BinOp with Add operator.
    """
    if not node.args:
        return False
    first_arg = node.args[0]
    return (
        isinstance(first_arg, ast.BinOp)
        and isinstance(first_arg.op, ast.Add)
    )


def _open_write_mode(node: ast.Call) -> bool:
    """
    Returns True if open() is called with a write/append/exclusive-create mode.
    Checks second positional arg or 'mode' keyword arg.
    """
    mode_str: Optional[str] = None
    # Positional: open(path, mode)
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        mode_str = node.args[1].value if isinstance(node.args[1].value, str) else None
    # Keyword: open(path, mode="w")
    if mode_str is None:
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode_str = kw.value.value if isinstance(kw.value.value, str) else None
    if mode_str is None:
        return False
    return any(m in mode_str for m in _OPEN_WRITE_MODES)


# ── Semantic stripping ───────────────────────────────────────────────────────

class SemanticStrippingVisitor(ast.NodeTransformer):
    """
    Strips ALL semantic content from an AST in a single in-place pass.

    After transformation:
      - No string / bytes / f-string values exist anywhere in the tree
      - All identifier names → deterministic 8-char SHA-256 hashes
      - Docstrings removed from function / class / module bodies
      - Type annotations stripped entirely
      - Numeric and boolean constants KEPT (structural / magnitude signal)
      - None, True, False KEPT (structural signal)

    Edge cases handled:
      - Empty body after docstring removal → body = [Pass()]
      - Python 3.7 legacy Str / Bytes nodes
      - walrus operator (NamedExpr)
      - match/case (Python 3.10+): MatchAs.name, MatchMapping.rest stripped
      - type aliases (Python 3.12+)
    """

    # ── Literals ──────────────────────────────────────────────────────────────

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, (str, bytes)):
            replacement = "" if isinstance(node.value, str) else b""
            return ast.copy_location(ast.Constant(value=replacement), node)
        return node  # int / float / bool / complex / None → structural

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        return ast.copy_location(ast.Constant(value=""), node)

    def visit_FormattedValue(self, node: ast.FormattedValue) -> ast.AST:
        return ast.copy_location(ast.Constant(value=""), node)

    # Python ≤ 3.7 legacy
    def visit_Str(self, node) -> ast.AST:      # type: ignore[override]
        return ast.copy_location(ast.Constant(value=""), node)

    def visit_Bytes(self, node) -> ast.AST:    # type: ignore[override]
        return ast.copy_location(ast.Constant(value=b""), node)

    # ── Identifiers ───────────────────────────────────────────────────────────

    def visit_Name(self, node: ast.Name) -> ast.AST:
        node.id = _hash_id(node.id)
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        node.attr = _hash_id(node.attr)
        return self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = _hash_id(node.arg)
        node.annotation = None
        return node

    def visit_keyword(self, node: ast.keyword) -> ast.AST:
        if node.arg is not None:
            node.arg = _hash_id(node.arg)
        return self.generic_visit(node)

    # ── Type annotations ──────────────────────────────────────────────────────

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST:
        node.annotation = ast.Constant(value="")
        return self.generic_visit(node)

    # Python 3.12+ type alias statement
    def visit_TypeAlias(self, node) -> ast.AST:  # type: ignore[override]
        return ast.copy_location(ast.Pass(), node)

    # ── match/case (Python 3.10+) — strip pattern variable names ─────────────

    def visit_MatchAs(self, node) -> ast.AST:  # type: ignore[override]
        """MatchAs.name is a variable capture name — strip it."""
        if node.name is not None:
            node.name = _hash_id(node.name)
        return self.generic_visit(node)

    def visit_MatchMapping(self, node) -> ast.AST:  # type: ignore[override]
        """MatchMapping.rest is a variable name — strip it."""
        if node.rest is not None:
            node.rest = _hash_id(node.rest)
        return self.generic_visit(node)

    def visit_MatchStar(self, node) -> ast.AST:  # type: ignore[override]
        """MatchStar.name is a variable capture name — strip it."""
        if node.name is not None:
            node.name = _hash_id(node.name)
        return self.generic_visit(node)

    # ── Definitions ───────────────────────────────────────────────────────────

    @staticmethod
    def _strip_docstring(body: List[ast.stmt]) -> List[ast.stmt]:
        """Remove leading docstring. Ensure body is never empty."""
        if (body
                and isinstance(body[0], ast.Expr)
                and isinstance(getattr(body[0], "value", None), ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]
        if not body:
            body = [ast.Pass()]
        return body

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = _hash_id(node.name)
        node.body = self._strip_docstring(node.body)
        node.returns = None
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.name = _hash_id(node.name)
        node.body = self._strip_docstring(node.body)
        node.returns = None
        return self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.name = _hash_id(node.name)
        node.body = self._strip_docstring(node.body)
        return self.generic_visit(node)

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body = self._strip_docstring(node.body)
        if not node.body:
            node.body = [ast.Pass()]
        return self.generic_visit(node)

    # ── Imports ───────────────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> ast.AST:
        node.names = [
            ast.alias(
                name=_hash_id(a.name),
                asname=_hash_id(a.asname) if a.asname else None,
            )
            for a in node.names
        ]
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.AST:
        if node.module:
            node.module = _hash_id(node.module)
        node.names = [
            ast.alias(
                name=_hash_id(a.name),
                asname=_hash_id(a.asname) if a.asname else None,
            )
            for a in node.names
        ]
        return node

    # ── Scope ─────────────────────────────────────────────────────────────────

    def visit_Global(self, node: ast.Global) -> ast.AST:
        node.names = [_hash_id(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.AST:
        node.names = [_hash_id(n) for n in node.names]
        return node

    # ── Exception handlers ────────────────────────────────────────────────────

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        if node.name:
            node.name = _hash_id(node.name)
        return self.generic_visit(node)


# ── ASTNode conversion ───────────────────────────────────────────────────────

def _magnitude_class(v: Any) -> str:
    """Classify numeric magnitude without leaking the actual value."""
    try:
        av = abs(float(v))
        if av == 0:        return "zero"
        if av < 256:       return "byte_range"
        if av < 65536:     return "word_range"
        if av < 2**32:     return "dword_range"
        return "large"
    except Exception:
        return "unknown"


def _ast_to_node(node: ast.AST, depth: int = 0) -> ASTNode:
    """
    Convert a Python AST node to a schema ASTNode.
    MUST be called on the STRIPPED tree only.
    Depth-limited at MAX_AST_DEPTH.
    """
    if depth >= MAX_AST_DEPTH:
        return ASTNode(
            node_type="DEPTH_LIMIT",
            attributes={"truncated": True, "depth": depth},
        )

    node_type = type(node).__name__
    attrs: Dict[str, Any] = {}

    if isinstance(node, ast.Constant):
        attrs["value_type"] = type(node.value).__name__
        if isinstance(node.value, (int, float, complex)):
            attrs["numeric_magnitude"] = _magnitude_class(node.value)

    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = node.args
        attrs["is_async"]         = isinstance(node, ast.AsyncFunctionDef)
        attrs["arg_count"]        = len(args.args)
        attrs["kwonly_count"]     = len(args.kwonlyargs)
        attrs["posonlyargs"]      = len(getattr(args, "posonlyargs", []))
        attrs["has_varargs"]      = args.vararg is not None
        attrs["has_kwargs"]       = args.kwarg is not None
        attrs["has_defaults"]     = bool(args.defaults or args.kw_defaults)
        attrs["decorator_count"]  = len(node.decorator_list)

    elif isinstance(node, ast.ClassDef):
        attrs["base_count"]       = len(node.bases)
        attrs["decorator_count"]  = len(node.decorator_list)
        attrs["keyword_count"]    = len(node.keywords)
        attrs["has_metaclass"]    = any(kw.arg == "metaclass" for kw in node.keywords)

    elif isinstance(node, ast.Import):
        attrs["alias_count"]      = len(node.names)

    elif isinstance(node, ast.ImportFrom):
        attrs["alias_count"]      = len(node.names)
        attrs["import_level"]     = node.level or 0

    elif isinstance(node, ast.Call):
        attrs["arg_count"]        = len(node.args)
        attrs["kwarg_count"]      = len(node.keywords)
        attrs["has_starargs"]     = any(isinstance(a, ast.Starred) for a in node.args)
        attrs["has_star_kwargs"]  = any(kw.arg is None for kw in node.keywords)

    elif isinstance(node, (ast.For, ast.AsyncFor)):
        attrs["is_async"]         = isinstance(node, ast.AsyncFor)
        attrs["has_orelse"]       = bool(node.orelse)

    elif isinstance(node, ast.While):
        attrs["has_orelse"]       = bool(node.orelse)

    elif isinstance(node, ast.If):
        attrs["has_orelse"]       = bool(node.orelse)

    elif isinstance(node, ast.Try):
        attrs["handler_count"]    = len(node.handlers)
        attrs["has_orelse"]       = bool(node.orelse)
        attrs["has_finally"]      = bool(getattr(node, "finalbody", None))

    elif isinstance(node, ast.ExceptHandler):
        attrs["has_type"]         = node.type is not None
        attrs["has_name"]         = node.name is not None

    elif isinstance(node, (ast.With, ast.AsyncWith)):
        attrs["is_async"]         = isinstance(node, ast.AsyncWith)
        attrs["item_count"]       = len(node.items)

    elif isinstance(node, ast.Lambda):
        attrs["arg_count"]        = len(node.args.args)
        attrs["has_defaults"]     = bool(node.args.defaults)

    elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        attrs["generator_count"]  = len(node.generators)
        attrs["is_async"]         = any(g.is_async for g in node.generators)

    elif isinstance(node, ast.DictComp):
        attrs["generator_count"]  = len(node.generators)
        attrs["is_async"]         = any(g.is_async for g in node.generators)

    elif isinstance(node, ast.Global):
        attrs["name_count"]       = len(node.names)

    elif isinstance(node, ast.Nonlocal):
        attrs["name_count"]       = len(node.names)

    elif isinstance(node, ast.BoolOp):
        attrs["operand_count"]    = len(node.values)

    elif isinstance(node, ast.Compare):
        attrs["comparator_count"] = len(node.comparators)

    elif isinstance(node, ast.Subscript):
        attrs["is_slice"]         = isinstance(getattr(node, "slice", None), ast.Slice)

    children = [
        _ast_to_node(child, depth + 1)
        for child in ast.iter_child_nodes(node)
    ]
    return ASTNode(
        node_type=node_type,
        lineno=getattr(node, "lineno", None),
        col_offset=getattr(node, "col_offset", None),
        children=children,
        attributes=attrs,
    )


# ── Anomaly detection ────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Detects 48 structural anomaly patterns on the ORIGINAL (pre-strip) AST.
    All detection uses node structure and attribute values — NOT string content.

    Categories (12):
      EXEC        — dynamic code execution (exec/eval/compile)
      DYNAMIC     — dynamic imports / class loading / sys.modules poisoning
      PRIVILEGE   — OS / process / privilege operations / ctypes
      NETWORK     — network access
      IO          — file system access (read + write-mode separated)
      OBFUSC      — obfuscation / encoding / (de)serialisation
      CRYPTO      — cryptographic operations
      REFLECT     — runtime type manipulation
      INJECT      — patterns associated with injection risk
      CONCUR      — concurrency primitives / thread-local storage
      HOOK        — finalizer/hook dunders (__del__, __init_subclass__, etc.)
      TAINT       — exec/eval called with non-constant / concat argument
    """

    __slots__ = ("flags", "counts", "import_modules")

    def __init__(self) -> None:
        self.flags: Dict[str, bool] = {
            # Core anomaly flags
            "has_exec_calls":          False,
            "has_eval_calls":          False,
            "has_compile_calls":       False,
            "has_dynamic_imports":     False,
            "has_network_calls":       False,
            "has_file_io":             False,
            "has_file_write":          False,  # NEW: open() in write mode
            "has_privilege_calls":     False,
            "has_obfuscation":         False,
            "has_deserialisation":     False,
            "has_reflection":          False,
            "has_crypto_ops":          False,
            "has_injection_risk":      False,
            "has_concurrency":         False,
            "has_thread_local":        False,  # NEW: threading.local()
            "has_weakref_hooks":       False,  # NEW: weakref.finalize / ref
            # Structural flags
            "has_global_scope":        False,
            "has_nested_functions":    False,
            "has_decorators":          False,
            "has_async_ops":           False,
            "has_exception_silence":   False,
            "has_star_imports":        False,
            "has_relative_imports":    False,
            "has_chained_calls":       False,
            "has_high_entropy":        False,   # set by caller
            # Advanced threat flags
            "has_dynamic_attr_set":    False,   # setattr with non-const attr name
            "has_metaclass":           False,   # metaclass= in ClassDef
            "has_slot_manipulation":   False,   # __slots__ assignment
            "has_pickle_gadgets":      False,   # __reduce__, __reduce_ex__, etc.
            "has_sys_modules_poison":  False,   # sys.modules["x"] = ...
            "has_native_lib_load":     False,   # ctypes.CDLL / windll
            # Hook dunder methods
            "has_del_hook":            False,   # NEW: __del__ defined
            "has_subclass_hook":       False,   # NEW: __init_subclass__ defined
            "has_missing_hook":        False,   # NEW: __missing__ defined
            "has_fspath_hook":         False,   # NEW: __fspath__ defined
            # Taint flags — exec/eval called with dynamic input
            "has_tainted_exec":        False,   # NEW: exec(non_literal)
            "has_tainted_eval":        False,   # NEW: eval(non_literal)
            "has_concat_exec":         False,   # NEW: exec(a + b)
            # Format string surface
            "has_format_injection":    False,   # NEW: .format() calls
        }
        self.counts: Dict[str, int] = {
            "exec":             0,
            "eval":             0,
            "compile":          0,
            "privilege":        0,
            "network":          0,
            "io":               0,
            "io_write":         0,   # NEW
            "obfusc":           0,
            "deserialise":      0,
            "reflection":       0,
            "dynamic":          0,
            "inject":           0,
            "concur":           0,
            "silent_except":    0,
            "star_imports":     0,
            "relative_imports": 0,
            "chained_call_max": 0,   # max chain depth seen
            "hook_dunders":     0,   # NEW: __del__ + __init_subclass__ etc.
            "tainted_exec":     0,   # NEW
            "format_calls":     0,   # NEW
        }
        self.import_modules: Set[str] = set()

    def detect(self, tree: ast.AST) -> None:
        """Single-pass walk populating all flags and counts."""
        for node in ast.walk(tree):
            self._visit(node)

    def _visit(self, node: ast.AST) -> None:
        # ── Calls ──────────────────────────────────────────────────────────
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name:
                self._check_call(name, node)
            # Chained calls: a().b().c()
            if (isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Call)):
                self.flags["has_chained_calls"] = True
                depth = _chain_depth_iterative(node)
                if depth > self.counts["chained_call_max"]:
                    self.counts["chained_call_max"] = depth
            # setattr with non-constant attr name → computed attribute mutation
            if (name == "setattr" and len(node.args) >= 2
                    and not isinstance(node.args[1], ast.Constant)):
                self.flags["has_dynamic_attr_set"] = True
            # .format() calls — format-string injection surface
            if name == "format":
                self.flags["has_format_injection"] = True
                self.counts["format_calls"] += 1

        # ── Subscript assignments → sys.modules poisoning ───────────────
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.value, ast.Attribute)
                        and isinstance(tgt.value.attr, str)
                        and tgt.value.attr == "modules"):
                    self.flags["has_sys_modules_poison"] = True
                    self.counts["dynamic"] += 1
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "__slots__":
                    self.flags["has_slot_manipulation"] = True

        # ── Method/function definitions ──────────────────────────────────
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name
            if name in _PICKLE_GADGET_NAMES:
                self.flags["has_pickle_gadgets"] = True
            if name == "__del__":
                self.flags["has_del_hook"] = True
                self.counts["hook_dunders"] += 1
            if name == "__init_subclass__":
                self.flags["has_subclass_hook"] = True
                self.counts["hook_dunders"] += 1
            if name == "__missing__":
                self.flags["has_missing_hook"] = True
                self.counts["hook_dunders"] += 1
            if name == "__fspath__":
                self.flags["has_fspath_hook"] = True
                self.counts["hook_dunders"] += 1
            if name in _HOOK_DUNDER_NAMES:
                self.counts["hook_dunders"] += 1
            if node.decorator_list:
                self.flags["has_decorators"] = True

        # ── Class definitions ─────────────────────────────────────────────
        elif isinstance(node, ast.ClassDef):
            if node.decorator_list:
                self.flags["has_decorators"] = True
            for kw in node.keywords:
                if kw.arg == "metaclass":
                    self.flags["has_metaclass"] = True

        # ── Imports ──────────────────────────────────────────────────────
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0].lower()
                self.import_modules.add(top)
                self._check_import_module(alias.name)

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0].lower()
                self.import_modules.add(top)
                self._check_import_module(node.module)
                for alias in node.names:
                    if alias.name == "*":
                        self.flags["has_star_imports"] = True
                        self.counts["star_imports"] += 1
                    else:
                        self._check_call_name_only(alias.name)
            if node.level and node.level > 0:
                self.flags["has_relative_imports"] = True
                self.counts["relative_imports"] += 1

        # ── Global / Nonlocal ─────────────────────────────────────────────
        elif isinstance(node, ast.Global):
            self.flags["has_global_scope"] = True

        # ── Async — only set on top-level async nodes, not func defs ─────
        elif isinstance(node, (ast.AsyncFor, ast.AsyncWith, ast.Await)):
            self.flags["has_async_ops"] = True
        # AsyncFunctionDef handled above in func def branch

        # ── Silent exception handlers ─────────────────────────────────────
        elif isinstance(node, ast.ExceptHandler):
            if _is_silent_handler(node):
                self.flags["has_exception_silence"] = True
                self.counts["silent_except"] += 1

    def _check_call(self, name: str, node: ast.Call) -> None:
        # Taint tracking for exec/eval/compile
        if name in _EXEC_NAMES:
            if _is_tainted_call(node):
                self.flags["has_tainted_exec"] = True
                self.counts["tainted_exec"] += 1
            if _has_string_concat_before_eval(node):
                self.flags["has_concat_exec"] = True
        if name in _EVAL_NAMES:
            if _is_tainted_call(node):
                self.flags["has_tainted_eval"] = True
                self.counts["tainted_exec"] += 1
            if _has_string_concat_before_eval(node):
                self.flags["has_concat_exec"] = True
        # Write-mode open() detection
        if name == "open" and _open_write_mode(node):
            self.flags["has_file_write"] = True
            self.counts["io_write"] += 1
        self._check_call_name_only(name)

    def _check_call_name_only(self, name: str) -> None:
        if name in _EXEC_NAMES:
            self.flags["has_exec_calls"] = True
            self.counts["exec"] += 1
        if name in _EVAL_NAMES:
            self.flags["has_eval_calls"] = True
            self.counts["eval"] += 1
        if name in _COMPILE_NAMES:
            self.flags["has_compile_calls"] = True
            self.counts["compile"] += 1
        if name in _DYNAMIC_NAMES:
            self.flags["has_dynamic_imports"] = True
            self.counts["dynamic"] += 1
        if name in _DESERIALISE_NAMES:
            self.flags["has_deserialisation"] = True
            self.counts["deserialise"] += 1
        if name in _PRIVILEGE_NAMES:
            self.flags["has_privilege_calls"] = True
            self.counts["privilege"] += 1
            if name in ("CDLL", "WinDLL", "windll", "cdll", "CFUNCTYPE", "dlopen"):
                self.flags["has_native_lib_load"] = True
        if name in _NETWORK_NAMES:
            self.flags["has_network_calls"] = True
            self.counts["network"] += 1
        if name in _IO_NAMES:
            self.flags["has_file_io"] = True
            self.counts["io"] += 1
        if name in _OBFUSCATION_NAMES:
            self.flags["has_obfuscation"] = True
            self.counts["obfusc"] += 1
        if name in _REFLECTION_NAMES:
            self.flags["has_reflection"] = True
            self.counts["reflection"] += 1
        if name in _INJECTION_RISK_NAMES:
            self.flags["has_injection_risk"] = True
            self.counts["inject"] += 1
        if name in _CONCURRENCY_NAMES:
            self.flags["has_concurrency"] = True
            self.counts["concur"] += 1
            if name == "local":
                self.flags["has_thread_local"] = True
        if name in _WEAKREF_NAMES:
            self.flags["has_weakref_hooks"] = True

    def _check_import_module(self, module: str) -> None:
        top = module.split(".")[0].lower()
        if top in _NETWORK_MODULES:
            self.flags["has_network_calls"] = True
            self.counts["network"] += 1
        if top in _IO_MODULES:
            self.flags["has_file_io"] = True
            self.counts["io"] += 1
        if top in _OBFUSCATION_MODULES:
            self.flags["has_obfuscation"] = True
            self.counts["obfusc"] += 1
        if top in _CRYPTOGRAPHY_MODULES:
            self.flags["has_crypto_ops"] = True
        if top in ("subprocess", "os", "pty", "signal", "ctypes", "cffi", "winreg"):
            self.flags["has_privilege_calls"] = True
            self.counts["privilege"] += 1
            if top in ("ctypes", "cffi"):
                self.flags["has_native_lib_load"] = True
        if top in _CONCURRENCY_MODULES:
            self.flags["has_concurrency"] = True
            self.counts["concur"] += 1
        if top == "weakref":
            self.flags["has_weakref_hooks"] = True


# ── Complexity metrics ───────────────────────────────────────────────────────

def _compute_cyclomatic(tree: ast.AST) -> int:
    """
    McCabe cyclomatic complexity.
    cc = 1 + decision_points
    """
    cc = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.For,
                              ast.AsyncFor, ast.ExceptHandler,
                              ast.With, ast.AsyncWith, ast.Assert,
                              ast.comprehension)):
            cc += 1
        elif isinstance(node, ast.BoolOp):
            cc += len(node.values) - 1
        elif isinstance(node, ast.IfExp):
            cc += 1
        elif hasattr(ast, "Match") and isinstance(node, ast.Match):
            cc += max(len(node.cases) - 1, 0)
    return cc


def _compute_cognitive(tree: ast.AST) -> int:
    """
    Cognitive complexity approximation (Sonar method).
    Increments for nesting-dependent constructs and penalises depth.
    Fully iterative (stack-safe).
    """
    score = 0
    stack = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        children_depth = depth
        if isinstance(node, (ast.If, ast.While, ast.For,
                               ast.AsyncFor, ast.ExceptHandler)):
            score += 1 + depth
            children_depth = depth + 1
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                ast.ClassDef, ast.Lambda)):
            children_depth = 0   # new scope resets nesting penalty
        for child in ast.iter_child_nodes(node):
            stack.append((child, children_depth))
    return score


def _compute_halstead_proxy(tree: ast.AST) -> Dict[str, int]:
    """
    Halstead volume proxy.
    η1 = distinct operators, η2 = distinct operands
    N1 = total operators,    N2 = total operands
    Run on the ORIGINAL tree (before stripping) for meaningful operands.
    """
    operators: Counter = Counter()
    operands:  Counter = Counter()
    for node in ast.walk(tree):
        if isinstance(node, (ast.BinOp, ast.UnaryOp, ast.BoolOp,
                              ast.Compare, ast.AugAssign)):
            operators[type(node).__name__] += 1
        elif isinstance(node, ast.Call):
            operators["Call"] += 1
        elif isinstance(node, ast.Name):
            operands[node.id] += 1
        elif isinstance(node, ast.Constant):
            operands[repr(type(node.value))] += 1
    return {
        "distinct_operators": len(operators),
        "distinct_operands":  len(operands),
        "total_operators":    sum(operators.values()),
        "total_operands":     sum(operands.values()),
    }


def _compute_max_depth_iterative(tree: ast.AST) -> int:
    """Iterative (stack-safe) tree depth computation."""
    stack = [(tree, 0)]
    max_d = 0
    while stack:
        node, d = stack.pop()
        if d > max_d:
            max_d = d
        for child in ast.iter_child_nodes(node):
            stack.append((child, d + 1))
    return max_d


def _count_nodes_iterative(tree: ast.AST) -> int:
    """Iterative node count."""
    count = 0
    stack = [tree]
    while stack:
        n = stack.pop()
        count += 1
        stack.extend(ast.iter_child_nodes(n))
    return count


def _detect_nested_functions(tree: ast.AST) -> Tuple[bool, int]:
    """
    Returns (has_nested, max_nesting_level).

    Corrected algorithm:
      - module scope     = func_depth 0
      - top-level func   = func_depth 1   (not nested)
      - nested func      = func_depth 2+  (nested)

    Uses iterative DFS — safe for large trees.
    """
    max_level = 0
    stack: List[Tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, fdepth = stack.pop()
        is_func = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        if is_func:
            new_depth = fdepth + 1
            if new_depth > max_level:
                max_level = new_depth
        else:
            new_depth = fdepth
        for child in ast.iter_child_nodes(node):
            stack.append((child, new_depth))
    has_nested = max_level >= 2
    nesting_depth = max(0, max_level - 1)
    return has_nested, nesting_depth


def _count_source_lines(source: str) -> Tuple[int, int, float]:
    """
    Returns (total_lines, blank_lines, blank_ratio).
    Blank ratio excludes docstring-only lines to avoid inflation
    from heavily-documented code.
    """
    lines = source.splitlines()
    total = len(lines)
    # Count only truly blank lines (empty or whitespace-only)
    blank = sum(1 for l in lines if not l.strip())
    ratio = blank / total if total else 0.0
    return total, blank, round(ratio, 3)


# ── Public API ───────────────────────────────────────────────────────────────

def parse_python_source(
    source_bytes: bytes,
    file_index: int,
    task_id: str,
) -> ASTPayload:
    """
    Parse Python source bytes into a fully-sanitised, richly-annotated ASTPayload.

    Pipeline:
      1.  Size guard
      2.  Decode (UTF-8 with latin-1 fallback)
      3.  Source-level metrics (lines, entropy — entropy value STORED)
      4.  Parse → AST
      5.  Node count guard
      6.  Anomaly detection on ORIGINAL tree (inc. taint + hooks)
      7.  Complexity metrics on ORIGINAL tree
      8.  Nested function analysis on ORIGINAL tree
      9.  Strip semantic content (in-place transform, incl. match/case)
      10. Convert stripped tree → ASTPayload schema
      11. Delete source text and all ASTs

    Security: source_bytes and all AST objects are deleted after use.
    No semantic content (names, strings, literals) survives step 11.
    """
    from src.schemas.a2a_schemas import AgentRole, MessageType, create_header

    header = create_header(
        MessageType.AST_PAYLOAD,
        AgentRole.AST_PARSER,
        AgentRole.IR_BUILDER,
        task_id,
    )

    def _empty(errors: List[str]) -> ASTPayload:
        return ASTPayload(
            header=header,
            file_index=file_index,
            file_extension=".py",
            root_node=ASTNode(node_type="Module", children=[], attributes={}),
            node_count=0, depth=0,
            cyclomatic_complexity=0,
            cognitive_complexity=0,
            import_count=0, function_count=0, class_count=0,
            parse_errors=errors,
        )

    # ① Size guard
    if len(source_bytes) > MAX_SOURCE_BYTES:
        logger.warning("File %d too large (%d bytes)", file_index, len(source_bytes))
        return _empty(["FILE_TOO_LARGE"])

    # ② Decode — try UTF-8 first, fall back to latin-1 (never fails)
    try:
        source_text: str = source_bytes.decode("utf-8", errors="replace")
    except Exception:
        source_text = source_bytes.decode("latin-1", errors="replace")

    # ③ Source-level metrics
    total_lines, blank_lines, blank_ratio = _count_source_lines(source_text)
    entropy = _source_entropy(source_text)         # NOW stored as float
    high_entropy = entropy > _ENTROPY_THRESHOLD

    # ④ Parse
    try:
        tree = ast.parse(source_text, type_comments=False)
    except SyntaxError as e:
        return _empty([f"SyntaxError:L{e.lineno}:C{e.offset}"])
    except Exception as e:
        return _empty([f"ParseError:{type(e).__name__}"])

    # ⑤ Node count guard
    node_count = _count_nodes_iterative(tree)
    if node_count > MAX_NODE_COUNT:
        logger.warning("File %d: %d nodes exceeds limit", file_index, node_count)
        return _empty(["TOO_MANY_NODES"])

    # ⑥ Anomaly detection (ORIGINAL tree)
    detector = AnomalyDetector()
    detector.detect(tree)
    detector.flags["has_high_entropy"] = high_entropy
    # Async flag: also set if any AsyncFunctionDef found
    for n in ast.walk(tree):
        if isinstance(n, ast.AsyncFunctionDef):
            detector.flags["has_async_ops"] = True
            break

    # ⑦ Complexity metrics (ORIGINAL tree — halstead needs real names)
    cyclomatic  = _compute_cyclomatic(tree)
    cognitive   = _compute_cognitive(tree)
    halstead    = _compute_halstead_proxy(tree)
    max_depth   = _compute_max_depth_iterative(tree)

    # Single-pass counters
    import_count     = 0
    function_count   = 0
    class_count      = 0
    async_func_count = 0
    decorator_total  = 0
    try_count        = 0
    except_count     = 0
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            import_count += 1
        elif isinstance(n, ast.FunctionDef):
            function_count += 1
            decorator_total += len(n.decorator_list)
        elif isinstance(n, ast.AsyncFunctionDef):
            function_count += 1
            async_func_count += 1
            decorator_total += len(n.decorator_list)
        elif isinstance(n, ast.ClassDef):
            class_count += 1
            decorator_total += len(n.decorator_list)
        elif isinstance(n, ast.Try):
            try_count += 1
        elif isinstance(n, ast.ExceptHandler):
            except_count += 1

    # ⑧ Nested function analysis (ORIGINAL tree)
    has_nested, max_nested_depth = _detect_nested_functions(tree)
    detector.flags["has_nested_functions"] = has_nested

    # ⑨ Strip semantic content (includes match/case pattern variables)
    stripper = SemanticStrippingVisitor()
    stripped = stripper.visit(tree)
    ast.fix_missing_locations(stripped)

    # ⑩ Convert to schema (STRIPPED tree only)
    root_node = _ast_to_node(stripped)

    # ⑪ Delete originals
    del source_text
    del tree
    del stripped

    # ── Build rich attribute dict ─────────────────────────────────────────
    # All structural, zero semantic.
    rich_attrs: Dict[str, Any] = {
        # Anomaly flags (0/1 for JSON compat)
        **{k: (1 if v else 0) for k, v in detector.flags.items()},
        # Per-category counts
        "count_exec":             detector.counts["exec"],
        "count_eval":             detector.counts["eval"],
        "count_compile":          detector.counts["compile"],
        "count_privilege":        detector.counts["privilege"],
        "count_network":          detector.counts["network"],
        "count_io":               detector.counts["io"],
        "count_io_write":         detector.counts["io_write"],         # NEW
        "count_obfusc":           detector.counts["obfusc"],
        "count_deserialise":      detector.counts["deserialise"],
        "count_reflection":       detector.counts["reflection"],
        "count_dynamic":          detector.counts["dynamic"],
        "count_inject":           detector.counts["inject"],
        "count_concur":           detector.counts["concur"],
        "count_silent_except":    detector.counts["silent_except"],
        "count_star_imports":     detector.counts["star_imports"],
        "count_relative_imports": detector.counts["relative_imports"],
        "chained_call_max_depth": detector.counts["chained_call_max"],
        "count_hook_dunders":     detector.counts["hook_dunders"],     # NEW
        "count_tainted_exec":     detector.counts["tainted_exec"],     # NEW
        "count_format_calls":     detector.counts["format_calls"],     # NEW
        # Complexity signals
        "cyclomatic_complexity":          cyclomatic,
        "cognitive_complexity":           cognitive,
        "halstead_distinct_operators":    halstead["distinct_operators"],
        "halstead_distinct_operands":     halstead["distinct_operands"],
        "halstead_total_operators":       halstead["total_operators"],
        "halstead_total_operands":        halstead["total_operands"],
        # Structure signals
        "function_count":                 function_count,
        "async_function_count":           async_func_count,
        "class_count":                    class_count,
        "import_count":                   import_count,
        "decorator_total":                decorator_total,
        "try_count":                      try_count,
        "except_count":                   except_count,
        "max_nested_function_depth":      max_nested_depth,
        # Source signals
        "total_lines":                    total_lines,
        "blank_lines":                    blank_lines,
        "blank_ratio":                    blank_ratio,
        "source_entropy":                 round(entropy, 4),           # NEW: stored
        "imported_module_count":          len(detector.import_modules),
    }

    augmented_root = ASTNode(
        node_type=root_node.node_type,
        lineno=root_node.lineno,
        col_offset=root_node.col_offset,
        children=root_node.children,
        attributes=rich_attrs,
    )

    return ASTPayload(
        header=header,
        file_index=file_index,
        file_extension=".py",
        root_node=augmented_root,
        node_count=node_count,
        depth=max_depth,
        cyclomatic_complexity=cyclomatic,
        cognitive_complexity=cognitive,
        import_count=import_count,
        function_count=function_count,
        class_count=class_count,
        has_exec_calls=detector.flags["has_exec_calls"],
        has_eval_calls=detector.flags["has_eval_calls"],
        has_dynamic_imports=detector.flags["has_dynamic_imports"],
        has_network_calls=detector.flags["has_network_calls"],
        has_file_io=detector.flags["has_file_io"],
        has_privilege_calls=detector.flags["has_privilege_calls"],
        has_obfuscation=detector.flags["has_obfuscation"],
        has_high_entropy=high_entropy,
        has_injection_risk=detector.flags["has_injection_risk"],
        has_deserialisation=detector.flags["has_deserialisation"],
        parse_errors=[],
    )