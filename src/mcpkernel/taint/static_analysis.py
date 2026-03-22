"""Static taint analysis — pre-execution AST scan for dangerous patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class StaticFinding:
    """A single dangerous pattern found in code."""

    rule_id: str
    severity: Severity
    message: str
    line: int
    col: int
    node_type: str


@dataclass
class StaticTaintReport:
    """Results of static taint analysis on code."""

    findings: list[StaticFinding] = field(default_factory=list)
    lines_scanned: int = 0
    has_critical: bool = False

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0


# Dangerous function patterns
_DANGEROUS_CALLS: dict[str, tuple[str, Severity, str]] = {
    "eval": ("STATIC-001", Severity.CRITICAL, "eval() allows arbitrary code execution"),
    "exec": ("STATIC-002", Severity.CRITICAL, "exec() allows arbitrary code execution"),
    "compile": ("STATIC-003", Severity.HIGH, "compile() can enable dynamic code execution"),
    "__import__": ("STATIC-004", Severity.HIGH, "__import__() allows dynamic module loading"),
    "getattr": ("STATIC-005", Severity.MEDIUM, "getattr() with user input can access private attributes"),
}

_DANGEROUS_MODULES: dict[str, tuple[str, Severity, str]] = {
    "subprocess": ("STATIC-010", Severity.CRITICAL, "subprocess allows shell command execution"),
    "os.system": ("STATIC-011", Severity.CRITICAL, "os.system() allows shell command execution"),
    "os.popen": ("STATIC-012", Severity.CRITICAL, "os.popen() allows shell command execution"),
    "pickle": ("STATIC-013", Severity.HIGH, "pickle.loads() can execute arbitrary code on deserialization"),
    "marshal": ("STATIC-014", Severity.HIGH, "marshal.loads() can execute arbitrary code"),
    "shelve": ("STATIC-015", Severity.HIGH, "shelve uses pickle internally"),
    "ctypes": ("STATIC-016", Severity.HIGH, "ctypes allows calling C functions directly"),
    "socket": ("STATIC-017", Severity.MEDIUM, "socket allows raw network access"),
}


class _DangerousPatternVisitor(ast.NodeVisitor):
    """AST visitor that detects dangerous code patterns."""

    def __init__(self) -> None:
        self.findings: list[StaticFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        # Direct dangerous function calls
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in _DANGEROUS_CALLS:
            rule_id, severity, msg = _DANGEROUS_CALLS[func_name]
            self.findings.append(
                StaticFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=msg,
                    line=node.lineno,
                    col=node.col_offset,
                    node_type="Call",
                )
            )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_module(alias.name, node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._check_module(node.module, node.lineno, node.col_offset)
        self.generic_visit(node)

    def _check_module(self, module: str, line: int, col: int) -> None:
        for pattern, (rule_id, severity, msg) in _DANGEROUS_MODULES.items():
            if module == pattern or module.startswith(f"{pattern}."):
                self.findings.append(
                    StaticFinding(
                        rule_id=rule_id,
                        severity=severity,
                        message=msg,
                        line=line,
                        col=col,
                        node_type="Import",
                    )
                )


def static_taint_analysis(code: str) -> StaticTaintReport:
    """Perform static analysis on Python code to detect dangerous patterns.

    The analysis is AST-based — fast and deterministic, but limited to
    syntactic patterns (no data-flow analysis).
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return StaticTaintReport(
            findings=[
                StaticFinding(
                    rule_id="STATIC-000",
                    severity=Severity.INFO,
                    message="Code contains syntax errors — cannot analyze",
                    line=0,
                    col=0,
                    node_type="SyntaxError",
                )
            ],
            lines_scanned=0,
        )

    visitor = _DangerousPatternVisitor()
    visitor.visit(tree)

    report = StaticTaintReport(
        findings=visitor.findings,
        lines_scanned=len(code.splitlines()),
        has_critical=any(f.severity == Severity.CRITICAL for f in visitor.findings),
    )
    return report
