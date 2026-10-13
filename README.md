# Static Code Analyzer

A standard-library-only, read-only Python AST checker. It parses source with
`ast.parse`; it never imports or executes the files being analyzed.

## Run

From this folder with Python 3.13:

```powershell
python -m static_analyzer path\to\file.py path\to\source-folder
python -m unittest discover -s tests -v
```

The CLI prints `file:line:column`, severity, rule ID, and a short message. An
invalid Python file is reported as `PY001`; error-severity findings make the
CLI exit nonzero.

## Current rules

- `SEC001`: calls to `eval` and `exec`.
- `SEC002`: `pickle.load` / `pickle.loads`.
- `SEC003`: common `subprocess` calls with literal `shell=True`.
- `COR001`: list, dict, or set function defaults.
- `COR002`: bare `except` and `except BaseException`.
- `COR003`: `assert`, which optimized Python can omit.
- `COR004`: a statement immediately after a direct `return`, `raise`, `break`,
  or `continue` in a block.
- `STY001`: equality comparison with `None`.
- `STY002`: a detected AST expression over 120 characters.

This is a small teaching/example checker, **not** a comprehensive security
auditor, type checker, or replacement for established linting tools. AST
patterns can miss aliases, indirect calls, control-flow subtleties, and
project-specific risks; warnings require human review.
