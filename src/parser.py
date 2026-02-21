"""
Multi-Language Parser Dispatcher (parser.py)

Routes source files to the appropriate structural parser based on file extension.
All parsers produce the same ASTPayload schema — language-agnostic downstream.

Supported languages:
  .py          → Python AST (ast module, native)
  .js / .ts / .jsx / .tsx → JavaScript/TypeScript structural parser
  .go          → Go structural parser
  .java        → Java structural parser
  .rs          → Rust structural parser
  .rb          → Ruby structural parser
  .cs          → C# structural parser
  .cpp / .c / .h → C/C++ structural parser

All parsers:
  - Strip string literals
  - Anonymize identifiers (SHA-256 hash)
  - Remove comments
  - Detect high-risk structural patterns
  - Produce normalized ASTPayload

Parser selection is purely by extension — no content sniffing.
Content sniffing would require reading semantic content.
"""
from __future__ import annotations

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Type

from src.schemas.a2a_schemas import (
    AgentRole, ASTNode, ASTPayload, MessageType, create_header,
)

logger = logging.getLogger(__name__)

# Extension → parser class name
EXTENSION_MAP: Dict[str, str] = {
    ".py":   "PythonParser",
    ".js":   "JavaScriptParser",
    ".jsx":  "JavaScriptParser",
    ".ts":   "JavaScriptParser",
    ".tsx":  "JavaScriptParser",
    ".go":   "GoParser",
    ".java": "JavaParser",
    ".rs":   "RustParser",
    ".rb":   "RubyParser",
    ".cs":   "CSharpParser",
    ".cpp":  "CppParser",
    ".c":    "CppParser",
    ".h":    "CppParser",
    ".hpp":  "CppParser",
    ".php":  "PhpParser",
    ".sh":   "ShellParser",
}

SUPPORTED_EXTENSIONS = frozenset(EXTENSION_MAP.keys())


def _hash_id(name: str) -> str:
    """Anonymize identifier to 8-char hash."""
    return "ID_" + hashlib.sha256(name.encode()).hexdigest()[:8]


def _strip_strings(source: str, quote_chars: str = "\"'`") -> str:
    """
    Remove all string literals from source text.
    Works for most C-style and Python-style languages.
    Handles triple-quoted strings for Python.
    """
    # Triple-quoted strings first (Python)
    source = re.sub(r'"""[\s\S]*?"""', '""', source)
    source = re.sub(r"'''[\s\S]*?'''", "''", source)
    # Template literals (JS)
    source = re.sub(r'`[^`]*`', '``', source)
    # Regular strings (non-greedy, handles escaped quotes crudely but safely)
    source = re.sub(r'"(?:[^"\\]|\\.)*"', '""', source)
    source = re.sub(r"'(?:[^'\\]|\\.)*'", "''", source)
    return source


def _strip_comments(source: str, style: str = "c") -> str:
    """
    Strip comments from source.
    style: "c" → // and /* */ | "python" → # | "ruby" → # + =begin/=end
    """
    if style in ("c", "java", "go", "rust", "csharp", "cpp", "js"):
        source = re.sub(r'/\*[\s\S]*?\*/', '', source)
        source = re.sub(r'//[^\n]*', '', source)
    elif style in ("python", "ruby", "shell", "php"):
        source = re.sub(r'#[^\n]*', '', source)
    return source


def _count_lines(source: str) -> int:
    return source.count('\n') + 1


def _estimate_complexity(source: str, keywords: List[str]) -> int:
    """McCabe complexity approximation by counting decision keywords."""
    complexity = 1
    for kw in keywords:
        complexity += len(re.findall(r'\b' + kw + r'\b', source))
    return complexity


# ─────────────────────────────────────────────────────────────────
# Base Parser
# ─────────────────────────────────────────────────────────────────

class BaseStructuralParser(ABC):
    """Abstract base for all language parsers."""

    COMPLEXITY_KEYWORDS: List[str] = ["if", "else", "elif", "for", "while",
                                       "switch", "case", "catch", "and", "or"]
    COMMENT_STYLE: str = "c"

    def parse(
        self,
        source_bytes: bytes,
        file_index: int,
        task_id: str,
        file_extension: str = "",
    ) -> ASTPayload:
        """
        Parse source bytes into ASTPayload.
        Strips semantic content before returning.
        """
        header = create_header(
            MessageType.AST_PAYLOAD,
            AgentRole.AST_PARSER,
            AgentRole.IR_BUILDER,
            task_id,
        )
        try:
            source = source_bytes.decode("utf-8", errors="replace")
        except Exception:
            source = source_bytes.decode("latin-1", errors="replace")

        # Strip comments and strings BEFORE any structural parsing
        source_clean = _strip_comments(source, self.COMMENT_STYLE)
        source_clean = _strip_strings(source_clean)

        try:
            metrics, anomalies, root_node = self._extract_structure(source_clean)
        except Exception as e:
            logger.warning("%s parse error: %s", type(self).__name__, type(e).__name__)
            return ASTPayload(
                header=header,
                file_index=file_index,
                file_extension=file_extension,
                root_node=ASTNode(node_type="Module", children=[], attributes={}),
                node_count=0, depth=0, cyclomatic_complexity=0,
                import_count=0, function_count=0, class_count=0,
                parse_errors=[f"{type(e).__name__}"],
            )

        return ASTPayload(
            header=header,
            file_index=file_index,
            file_extension=file_extension,
            root_node=root_node,
            node_count=metrics["node_count"],
            depth=metrics["depth"],
            cyclomatic_complexity=metrics["complexity"],
            import_count=metrics["import_count"],
            function_count=metrics["function_count"],
            class_count=metrics["class_count"],
            has_exec_calls=anomalies.get("has_exec_calls", False),
            has_eval_calls=anomalies.get("has_eval_calls", False),
            has_dynamic_imports=anomalies.get("has_dynamic_imports", False),
            has_network_calls=anomalies.get("has_network_calls", False),
            has_file_io=anomalies.get("has_file_io", False),
            parse_errors=[],
        )

    @abstractmethod
    def _extract_structure(
        self, source_clean: str
    ) -> Tuple[Dict, Dict, ASTNode]:
        """
        Extract structural metrics from clean (stripped) source.
        Returns: (metrics_dict, anomalies_dict, root_ASTNode)
        """


class RegexStructuralParser(BaseStructuralParser):
    """
    Regex-based structural parser for languages without a native Python AST.

    Detects:
      - Function/method definitions
      - Class definitions
      - Import statements
      - Control flow constructs
      - Anomalous patterns (eval, exec, network, IO)

    Anonymizes all identifier names via SHA-256 hashing.
    """

    # Subclasses override these patterns
    FUNC_PATTERN: str = r'\bfunction\s+(\w+)\s*\('
    CLASS_PATTERN: str = r'\bclass\s+(\w+)'
    IMPORT_PATTERN: str = r'\bimport\s+'
    CONTROL_FLOW: List[str] = ["if", "else", "for", "while", "switch", "try", "catch"]

    # Anomaly detection patterns (applied to STRIPPED source — catches structural calls)
    EXEC_PATTERN: str = r'\bexec\s*\('
    EVAL_PATTERN: str = r'\beval\s*\('
    DYNAMIC_IMPORT_PATTERN: str = r'\b(?:require|import)\s*\('
    NETWORK_PATTERN: str = r'\b(?:fetch|XMLHttpRequest|net\.|http\.|socket|connect)\s*\('
    IO_PATTERN: str = r'\b(?:open|read|write|fs\.|File|Stream)\s*[\.(]'

    def _extract_structure(self, source: str) -> Tuple[Dict, Dict, ASTNode]:
        children = []
        node_count = 1  # root

        # Functions
        func_matches = re.findall(self.FUNC_PATTERN, source)
        function_count = len(func_matches)
        for _ in func_matches:
            children.append(ASTNode(
                node_type="FUNC_DEF",
                attributes={"anonymized": True},
                children=[],
            ))
            node_count += 1

        # Classes
        class_matches = re.findall(self.CLASS_PATTERN, source)
        class_count = len(class_matches)
        for _ in class_matches:
            children.append(ASTNode(node_type="CLASS_DEF", attributes={}, children=[]))
            node_count += 1

        # Imports
        import_count = len(re.findall(self.IMPORT_PATTERN, source))
        for _ in range(import_count):
            children.append(ASTNode(node_type="IMPORT", attributes={}, children=[]))
            node_count += 1

        # Control flow nodes
        cf_count = sum(
            len(re.findall(r'\b' + kw + r'\b', source))
            for kw in self.CONTROL_FLOW
        )
        for kw in self.CONTROL_FLOW:
            hits = len(re.findall(r'\b' + kw + r'\b', source))
            if hits > 0:
                children.append(ASTNode(
                    node_type=kw.upper(),
                    attributes={"count": hits},
                    children=[],
                ))
                node_count += hits

        complexity = _estimate_complexity(source, self.CONTROL_FLOW)

        metrics = {
            "node_count": node_count,
            "depth": min(3 + function_count // 5, 20),  # estimated
            "complexity": complexity,
            "import_count": import_count,
            "function_count": function_count,
            "class_count": class_count,
        }

        anomalies = {
            "has_exec_calls":      bool(re.search(self.EXEC_PATTERN, source)),
            "has_eval_calls":      bool(re.search(self.EVAL_PATTERN, source)),
            "has_dynamic_imports": bool(re.search(self.DYNAMIC_IMPORT_PATTERN, source)),
            "has_network_calls":   bool(re.search(self.NETWORK_PATTERN, source)),
            "has_file_io":         bool(re.search(self.IO_PATTERN, source)),
        }

        root = ASTNode(
            node_type="Module",
            attributes={"language": type(self).__name__.replace("Parser", "").lower()},
            children=children,
        )
        return metrics, anomalies, root


# ─────────────────────────────────────────────────────────────────
# Language-Specific Parsers
# ─────────────────────────────────────────────────────────────────

class PythonParser(BaseStructuralParser):
    """
    Native Python parser using the ast module.
    Full structural fidelity with semantic stripping.
    Delegates to ast_parser.py which uses AST node transformation.
    """
    COMMENT_STYLE = "python"

    def parse(self, source_bytes, file_index, task_id, file_extension=".py"):
        # Delegate to the proper Python AST parser
        from src.analyzer.ast_parser import parse_python_source
        return parse_python_source(source_bytes, file_index, task_id)

    def _extract_structure(self, source_clean):
        raise NotImplementedError("PythonParser uses native ast module")


class JavaScriptParser(RegexStructuralParser):
    """JavaScript / TypeScript / JSX / TSX structural parser."""
    COMMENT_STYLE = "js"
    FUNC_PATTERN = r'\b(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>))'
    CLASS_PATTERN = r'\bclass\s+(\w+)'
    IMPORT_PATTERN = r'\b(?:import|require)\s*[\(\{"\']'
    CONTROL_FLOW = ["if", "else", "for", "while", "switch", "try", "catch", "finally"]
    EXEC_PATTERN = r'\beval\s*\('
    EVAL_PATTERN = r'\bFunction\s*\('
    DYNAMIC_IMPORT_PATTERN = r'\bimport\s*\('
    NETWORK_PATTERN = r'\b(?:fetch|XMLHttpRequest|axios|got|request)\s*[\.(]'
    IO_PATTERN = r'\b(?:fs\.|readFile|writeFile|createReadStream)\s*'


class GoParser(RegexStructuralParser):
    """Go structural parser."""
    COMMENT_STYLE = "c"
    FUNC_PATTERN = r'\bfunc\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\('
    CLASS_PATTERN = r'\btype\s+(\w+)\s+struct'
    IMPORT_PATTERN = r'\b(?:import\s+[\(""]|import\s+\w+\s+")'
    CONTROL_FLOW = ["if", "else", "for", "switch", "case", "select", "defer", "go"]
    EXEC_PATTERN = r'\bexec\.Command\s*\('
    EVAL_PATTERN = r'\bunsafe\.'
    DYNAMIC_IMPORT_PATTERN = r'\bplugin\.Open\s*\('
    NETWORK_PATTERN = r'\b(?:net\.|http\.|dial|listen)\s*'
    IO_PATTERN = r'\b(?:os\.Open|os\.Create|ioutil\.|bufio\.)\s*'


class JavaParser(RegexStructuralParser):
    """Java structural parser."""
    COMMENT_STYLE = "c"
    FUNC_PATTERN = r'\b(?:public|private|protected|static|\s)+\w+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+\s*)?\{'
    CLASS_PATTERN = r'\b(?:class|interface|enum)\s+(\w+)'
    IMPORT_PATTERN = r'\bimport\s+[\w\.]+'
    CONTROL_FLOW = ["if", "else", "for", "while", "switch", "try", "catch", "finally"]
    EXEC_PATTERN = r'\bRuntime\.exec\s*\('
    EVAL_PATTERN = r'\bScriptEngine\b'
    DYNAMIC_IMPORT_PATTERN = r'\bClass\.forName\s*\('
    NETWORK_PATTERN = r'\b(?:Socket|URL|HttpURLConnection|HttpClient)\s*[\.(]'
    IO_PATTERN = r'\b(?:FileReader|FileWriter|InputStream|OutputStream)\s*[\.(]'


class RustParser(RegexStructuralParser):
    """Rust structural parser."""
    COMMENT_STYLE = "c"
    FUNC_PATTERN = r'\b(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*[<(]'
    CLASS_PATTERN = r'\b(?:struct|enum|trait|impl)\s+(\w+)'
    IMPORT_PATTERN = r'\buse\s+[\w::]+'
    CONTROL_FLOW = ["if", "else", "match", "for", "while", "loop", "return"]
    EXEC_PATTERN = r'\bCommand::new\s*\('
    EVAL_PATTERN = r'\bunsafe\s*\{'
    DYNAMIC_IMPORT_PATTERN = r'\blib::Library::new\s*\('
    NETWORK_PATTERN = r'\b(?:TcpStream|UdpSocket|TcpListener)\s*::'
    IO_PATTERN = r'\b(?:File::open|File::create|BufReader|BufWriter)\s*'


class RubyParser(RegexStructuralParser):
    """Ruby structural parser."""
    COMMENT_STYLE = "ruby"
    FUNC_PATTERN = r'\bdef\s+(\w+[\?!]?)'
    CLASS_PATTERN = r'\b(?:class|module)\s+(\w+)'
    IMPORT_PATTERN = r'\b(?:require|require_relative|include|extend)\s+'
    CONTROL_FLOW = ["if", "unless", "elsif", "else", "while", "until", "for",
                    "begin", "rescue", "ensure", "case", "when"]
    EXEC_PATTERN = r'\beval\s*[\("\'`]'
    EVAL_PATTERN = r'\binstance_eval\s*\{'
    DYNAMIC_IMPORT_PATTERN = r'\brequire\s*\('
    NETWORK_PATTERN = r'\b(?:Net::HTTP|TCPSocket|UDPSocket|open-uri)\b'
    IO_PATTERN = r'\b(?:File\.open|IO\.read|File\.read)\s*'


class CSharpParser(RegexStructuralParser):
    """C# structural parser."""
    COMMENT_STYLE = "c"
    FUNC_PATTERN = r'\b(?:public|private|protected|static|async|\s)+\w+\s+(\w+)\s*\([^)]*\)\s*(?:\{|=>)'
    CLASS_PATTERN = r'\b(?:class|interface|struct|enum)\s+(\w+)'
    IMPORT_PATTERN = r'\busing\s+[\w\.]+'
    CONTROL_FLOW = ["if", "else", "for", "foreach", "while", "switch", "try", "catch", "finally"]
    EXEC_PATTERN = r'\bProcess\.Start\s*\('
    EVAL_PATTERN = r'\bCompiler|CSharpCodeProvider\b'
    DYNAMIC_IMPORT_PATTERN = r'\bAssembly\.Load\s*\('
    NETWORK_PATTERN = r'\b(?:TcpClient|HttpClient|WebClient|Socket)\s*[\.(]'
    IO_PATTERN = r'\b(?:File\.|StreamReader|StreamWriter|FileStream)\s*'


class CppParser(RegexStructuralParser):
    """C/C++ structural parser."""
    COMMENT_STYLE = "cpp"
    FUNC_PATTERN = r'\b(\w+)\s+(\w+)\s*\([^)]*\)\s*(?:const\s*)?\{'
    CLASS_PATTERN = r'\b(?:class|struct|union)\s+(\w+)'
    IMPORT_PATTERN = r'#\s*include\s*[<"]'
    CONTROL_FLOW = ["if", "else", "for", "while", "switch", "try", "catch"]
    EXEC_PATTERN = r'\b(?:system|popen|execve?|execl[pe]?)\s*\('
    EVAL_PATTERN = r'\bdlopen\s*\('
    DYNAMIC_IMPORT_PATTERN = r'\bdlsym\s*\('
    NETWORK_PATTERN = r'\b(?:socket|connect|bind|listen|send|recv)\s*\('
    IO_PATTERN = r'\b(?:fopen|fread|fwrite|open|read|write)\s*\('


class PhpParser(RegexStructuralParser):
    """PHP structural parser."""
    COMMENT_STYLE = "python"
    FUNC_PATTERN = r'\bfunction\s+(\w+)\s*\('
    CLASS_PATTERN = r'\b(?:class|interface|trait)\s+(\w+)'
    IMPORT_PATTERN = r'\b(?:require|include|require_once|include_once)\s*[\("\'\\]'
    CONTROL_FLOW = ["if", "elseif", "else", "for", "foreach", "while", "switch", "try", "catch"]
    EXEC_PATTERN = r'\b(?:eval|exec|shell_exec|passthru|system)\s*\('
    EVAL_PATTERN = r'\beval\s*\('
    DYNAMIC_IMPORT_PATTERN = r'\b(?:require|include)\s*\(\s*\$'
    NETWORK_PATTERN = r'\b(?:fsockopen|curl_init|file_get_contents)\s*\('
    IO_PATTERN = r'\b(?:fopen|file_put_contents|file_get_contents)\s*\('


class ShellParser(RegexStructuralParser):
    """Shell script structural parser."""
    COMMENT_STYLE = "python"
    FUNC_PATTERN = r'\b(\w+)\s*\(\s*\)\s*\{'
    CLASS_PATTERN = r'(?!)'  # No classes in shell
    IMPORT_PATTERN = r'\b(?:source|\.|import)\s+'
    CONTROL_FLOW = ["if", "elif", "else", "fi", "for", "while", "until", "case", "esac"]
    EXEC_PATTERN = r'\beval\s+'
    EVAL_PATTERN = r'\bexec\s+'
    DYNAMIC_IMPORT_PATTERN = r'\bsource\s+\$'
    NETWORK_PATTERN = r'\b(?:curl|wget|nc|netcat|ncat|ssh)\s+'
    IO_PATTERN = r'\b(?:cat|read|write|dd|tee)\s+'


# ─────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────

_PARSER_REGISTRY: Dict[str, BaseStructuralParser] = {}


def _get_parser(extension: str) -> Optional[BaseStructuralParser]:
    """Get (cached) parser instance for a file extension."""
    ext = extension.lower()
    if ext not in _PARSER_REGISTRY:
        class_name = EXTENSION_MAP.get(ext)
        if class_name is None:
            return None
        parser_class = globals().get(class_name)
        if parser_class is None:
            logger.warning("Parser class %s not found", class_name)
            return None
        _PARSER_REGISTRY[ext] = parser_class()
    return _PARSER_REGISTRY[ext]


def parse_source_bytes(
    plaintext_bytes: bytes,
    file_extension: str,
    file_index: int,
    task_id: str,
) -> Optional[ASTPayload]:
    """
    Main dispatch entrypoint.

    Routes plaintext bytes to the appropriate language parser.
    Returns ASTPayload (sanitized) or None if extension unsupported.

    CALLER CONTRACT:
      - plaintext_bytes must be the raw file content
      - plaintext_bytes should be in a short-lived scope
      - caller must zeroize their copy after this call returns
    """
    ext = file_extension.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        logger.debug("Unsupported extension for parsing: %s", ext)
        return None

    parser = _get_parser(ext)
    if parser is None:
        return None

    try:
        result = parser.parse(plaintext_bytes, file_index, task_id, ext)
        logger.debug(
            "Parsed %s: nodes=%d complexity=%d imports=%d funcs=%d",
            ext, result.node_count, result.cyclomatic_complexity,
            result.import_count, result.function_count,
        )
        return result
    except Exception as e:
        logger.error("Parser dispatch error for %s: %s", ext, type(e).__name__)
        return None


def get_supported_extensions() -> List[str]:
    return sorted(SUPPORTED_EXTENSIONS)


def parser_info() -> Dict[str, str]:
    """Return extension → parser class mapping for diagnostics."""
    return {ext: EXTENSION_MAP[ext] for ext in sorted(EXTENSION_MAP)}