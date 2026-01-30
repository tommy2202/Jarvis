import ast
import io
import tokenize
from pathlib import Path

import pytest


SKIP_DIRS = {".git", "venv", ".venv"}


def _iter_python_files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*.py")
        if not any(part in SKIP_DIRS for part in path.parts)
    ]


def _slice_source_segment(
    source: str,
    start_line: int,
    start_col: int,
    end_line: int,
    end_col: int,
) -> str | None:
    lines = source.splitlines(keepends=True)
    if (
        start_line < 1
        or end_line < start_line
        or start_line > len(lines)
        or end_line > len(lines)
    ):
        return None
    if start_line == end_line:
        return lines[start_line - 1][start_col:end_col]
    parts = [lines[start_line - 1][start_col:]]
    parts.extend(lines[start_line:end_line - 1])
    parts.append(lines[end_line - 1][:end_col])
    return "".join(parts)


def _slice_node_segment(source: str, node: ast.AST) -> str | None:
    if not all(
        hasattr(node, attr)
        for attr in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ):
        return None
    if (
        node.lineno is None
        or node.col_offset is None
        or node.end_lineno is None
        or node.end_col_offset is None
    ):
        return None
    return _slice_source_segment(
        source,
        node.lineno,
        node.col_offset,
        node.end_lineno,
        node.end_col_offset,
    )


def _line_col_to_index(lines: list[str], line: int, col: int) -> int:
    return sum(len(lines[i]) for i in range(line - 1)) + col


def _strip_format_spec(expr: str) -> str:
    depth = 0
    lines = expr.splitlines(keepends=True)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(expr).readline)
    except tokenize.TokenError:
        return expr
    for token in tokens:
        if token.type != tokenize.OP:
            continue
        if token.string in "([{":
            depth += 1
            continue
        if token.string in ")]}":
            depth = max(depth - 1, 0)
            continue
        if depth == 0 and token.string in {"!", ":"}:
            cut_index = _line_col_to_index(lines, token.start[0], token.start[1])
            return expr[:cut_index]
    return expr


def _extract_formatted_expression(source: str, node: ast.FormattedValue) -> str | None:
    expr_segment = ast.get_source_segment(source, node.value)
    if expr_segment is not None:
        return expr_segment
    fallback_segment = _slice_node_segment(source, node)
    if fallback_segment is None:
        return None
    open_brace = fallback_segment.find("{")
    close_brace = fallback_segment.rfind("}")
    if open_brace == -1 or close_brace == -1 or close_brace <= open_brace:
        return None
    inner = fallback_segment[open_brace + 1 : close_brace]
    return _strip_format_spec(inner)


def _find_backslash_in_fstring_expr(source: str, path: Path) -> list[tuple[int, str]]:
    violations: list[tuple[int, str]] = []
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
            segment = _extract_formatted_expression(source, value)
            if segment is None:
                continue
            if "\\" in segment:
                snippet = segment.strip().replace("\n", "\\n")
                violations.append((value.lineno, snippet))
    return sorted(violations, key=lambda item: item[0])


def test_no_backslash_in_fstring_expressions() -> None:
    root = Path(__file__).resolve().parents[1]
    failures: dict[str, list[tuple[int, str]]] = {}
    for path in _iter_python_files(root):
        source = path.read_text(encoding="utf-8", errors="ignore")
        lines = _find_backslash_in_fstring_expr(source, path)
        if lines:
            failures[str(path)] = lines
    if failures:
        details = "\n".join(
            f"{path}:{line}: {snippet}"
            for path, lines in sorted(failures.items())
            for line, snippet in lines
        )
        pytest.fail(f"Found backslash in f-string expressions:\n{details}")
