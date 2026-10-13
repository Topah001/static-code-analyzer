"""A small, read-only Python source checker."""

from .core import Finding, analyze_file, analyze_source

__all__ = ["Finding", "analyze_file", "analyze_source"]
