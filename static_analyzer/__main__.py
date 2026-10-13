"""Command-line entry point for the static analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path

from .core import Finding, analyze_file


def collect(paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.py")))
        elif path.is_file():
            files.append(path)
        else:
            findings.append(Finding(str(path), 1, 1, "IO001", "error", "path does not exist"))
    for file_path in files:
        findings.extend(analyze_file(file_path))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report selected Python AST red flags without running analyzed code."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Python files or directories")
    args = parser.parse_args()
    findings = collect(args.paths)
    for finding in findings:
        print(finding)
    if not findings:
        print("No findings.")
    return 1 if any(finding.severity == "error" for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
