import ast
import io
import re
import tokenize
from pathlib import Path

import pytest


FSTRING_BACKSLASH_RE = re.compile(r"\{\s*[^}]*\\[^}]*\}")
SKIP_DIRS = {".git", "venv", ".venv"}


def _iter_python_files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*.py")
        if not any(part in SKIP_DIRS for part in path.parts)
    ]


def _is_fstring_token(token_text: str) -> bool:
    prefix = []
    for ch in token_text:
        if ch in "rRuUbBfF":
            prefix.append(ch.lower())
        else:
            break
    return "f" in prefix


def _fallback_find_violations(source: str) -> list[int]:
    violations: list[int] = []
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for token in tokens:
        if token.type != tokenize.STRING:
            continue
        if not _is_fstring_token(token.string):
            continue
        for match in FSTRING_BACKSLASH_RE.finditer(token.string):
            line_offset = token.string[: match.start()].count("\n")
            violations.append(token.start[0] + line_offset)
    return violations


def _find_backslash_in_fstring_expr(source: str, path: Path) -> list[int]:
    violations: set[int] = set()
    needs_fallback = False
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        pytest.fail(f"SyntaxError parsing {path}:{exc.lineno} {exc.msg}")
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for value in node.values:
            if not isinstance(value, ast.FormattedValue):
                continue
            segment = ast.get_source_segment(source, value)
            if segment is None:
                needs_fallback = True
                continue
            if "\\" in segment:
                violations.add(value.lineno)
    if needs_fallback:
        violations.update(_fallback_find_violations(source))
    return sorted(violations)


def test_no_backslash_in_fstring_expressions() -> None:
    root = Path(__file__).resolve().parents[1]
    failures: dict[str, list[int]] = {}
    for path in _iter_python_files(root):
        source = path.read_text(encoding="utf-8", errors="ignore")
        lines = _find_backslash_in_fstring_expr(source, path)
        if lines:
            failures[str(path)] = lines
    if failures:
        details = "\n".join(
            f"{path}: {', '.join(str(line) for line in lines)}"
            for path, lines in sorted(failures.items())
        )
        pytest.fail(f"Found backslash in f-string expressions:\n{details}")
