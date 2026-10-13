"""Read-only AST checks for a deliberately small set of Python patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    line: int
    column: int
    rule: str
    severity: str
    message: str

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.line}:{self.column}: "
            f"{self.severity} {self.rule} {self.message}"
        )


def analyze_source(source: str, path: str = "<source>") -> list[Finding]:
    """Analyze source with ``ast.parse`` only; source is never imported or run."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as error:
        return [
            Finding(
                path,
                error.lineno or 1,
                error.offset or 1,
                "PY001",
                "error",
                f"invalid Python syntax: {error.msg}",
            )
        ]

    findings: list[Finding] = []

    def add(node: ast.AST, rule: str, severity: str, message: str) -> None:
        findings.append(
            Finding(
                path,
                getattr(node, "lineno", 1),
                getattr(node, "col_offset", 0) + 1,
                rule,
                severity,
                message,
            )
        )

    class Checker(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
                add(
                    node,
                    "SEC001",
                    "warning",
                    f"dynamic {func.id} can execute constructed code",
                )
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "pickle"
                and func.attr in {"load", "loads"}
            ):
                add(
                    node,
                    "SEC002",
                    "warning",
                    "pickle deserialization can execute code; do not load untrusted data",
                )
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
                and func.attr in {"run", "Popen", "call", "check_call", "check_output"}
                and any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
            ):
                add(
                    node,
                    "SEC003",
                    "warning",
                    "subprocess shell=True may enable command injection",
                )
            self.generic_visit(node)

        @staticmethod
        def _check_defaults(node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            for default in node.args.defaults + [
                value for value in node.args.kw_defaults if value is not None
            ]:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    add(
                        default,
                        "COR001",
                        "warning",
                        "mutable default is shared between calls",
                    )

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.type is None:
                add(node, "COR002", "warning", "bare except catches every exception")
            elif isinstance(node.type, ast.Name) and node.type.id == "BaseException":
                add(node, "COR002", "warning", "catching BaseException is usually too broad")
            self.generic_visit(node)

        def visit_Assert(self, node: ast.Assert) -> None:
            add(
                node,
                "COR003",
                "warning",
                "assert statements can be removed when Python runs with optimization",
            )
            self.generic_visit(node)

        def visit_Compare(self, node: ast.Compare) -> None:
            if any(
                isinstance(operator, (ast.Eq, ast.NotEq))
                and isinstance(comparator, ast.Constant)
                and comparator.value is None
                for operator, comparator in zip(node.ops, node.comparators)
            ):
                add(node, "STY001", "style", "use 'is None' or 'is not None'")
            self.generic_visit(node)

        def visit_Module(self, node: ast.Module) -> None:
            self._check_block(node.body)
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._check_defaults(node)
            self._check_block(node.body)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(
            self, node: ast.AsyncFunctionDef
        ) -> None:
            self._check_defaults(node)
            self._check_block(node.body)
            self.generic_visit(node)

        def visit_If(self, node: ast.If) -> None:
            self._check_block(node.body)
            self._check_block(node.orelse)
            self.generic_visit(node)

        def visit_For(self, node: ast.For) -> None:
            self._check_block(node.body)
            self._check_block(node.orelse)
            self.generic_visit(node)

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            self._check_block(node.body)
            self._check_block(node.orelse)
            self.generic_visit(node)

        def visit_While(self, node: ast.While) -> None:
            self._check_block(node.body)
            self._check_block(node.orelse)
            self.generic_visit(node)

        def visit_With(self, node: ast.With) -> None:
            self._check_block(node.body)
            self.generic_visit(node)

        def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
            self._check_block(node.body)
            self.generic_visit(node)

        def visit_Try(self, node: ast.Try) -> None:
            self._check_block(node.body)
            for handler in node.handlers:
                self._check_block(handler.body)
            self._check_block(node.orelse)
            self._check_block(node.finalbody)
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._check_block(node.body)
            self.generic_visit(node)

        def _check_block(self, statements: list[ast.stmt]) -> None:
            terminal = False
            for statement in statements:
                if terminal:
                    add(statement, "COR004", "warning", "statement is unreachable")
                    break
                if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    terminal = True

    Checker().visit(tree)
    for line_number, line in enumerate(source.splitlines(), 1):
        if len(line) > 120:
            findings.append(
                Finding(path, line_number, 121, "STY002", "style", "line exceeds 120 characters")
            )
    findings.sort(key=lambda finding: (finding.line, finding.column, finding.rule))
    return findings


def analyze_file(path: str | Path) -> list[Finding]:
    """Read and analyze one UTF-8 file without executing it."""
    file_path = Path(path)
    try:
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [Finding(str(file_path), 1, 1, "IO001", "error", str(error))]
    return analyze_source(source, str(file_path))
