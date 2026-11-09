#!/usr/bin/env python3
"""Fail if a long dash or long-dash entity appears in source or documentation.

The project uses a regular hyphen everywhere. This guard runs in CI and can be
run locally with `make check-dashes` or `python3 scripts/check_no_long_dashes.py`.
Use `--fix` to replace the long forms with a regular hyphen.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "data",
    ".next",
    ".cache",
    "coverage",
}
TEXT_SUFFIXES = {
    ".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".yaml", ".yml",
    ".md", ".mdx", ".sql", ".html", ".htm", ".css", ".scss", ".sh", ".bash",
    ".txt", ".env", ".example", ".conf", ".toml", ".xml", ".svg", ".dockerfile",
}
CHAR_MAP = {
    chr(0x2012): "figure dash",
    chr(0x2013): "en dash",
    chr(0x2014): "em dash",
    chr(0x2015): "horizontal bar",
    chr(0x2011): "non-breaking hyphen",
    chr(0x2212): "minus sign",
}
ENTITY_MAP = {
    "&" + "mdash;": "HTML em dash",
    "&" + "ndash;": "HTML en dash",
    "&#" + "8212;": "numeric em dash",
    "&#" + "8211;": "numeric en dash",
    "\\" + "u2014": "escaped em dash",
    "\\" + "u2013": "escaped en dash",
    "\\" + "x{2014}": "Go escaped em dash",
    "\\" + "x{2013}": "Go escaped en dash",
}


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return path.name in {"Dockerfile", "Makefile", ".env", ".env.example", ".gitignore"}


def scan(fix: bool) -> int:
    problems: list[str] = []
    changed: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if not is_text_file(path):
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        original = text
        for char, name in CHAR_MAP.items():
            if char in text:
                for line_no, line in enumerate(text.splitlines(), 1):
                    if char in line:
                        problems.append(f"{path.relative_to(ROOT)}:{line_no}: {name} (U+{ord(char):04X})")
                if fix:
                    text = text.replace(char, "-")
        for entity, name in ENTITY_MAP.items():
            if entity in text:
                for line_no, line in enumerate(text.splitlines(), 1):
                    if entity in line:
                        problems.append(f"{path.relative_to(ROOT)}:{line_no}: {name} ({entity})")
                if fix:
                    text = text.replace(entity, "-")
        if fix and text != original:
            path.write_text(text)
            changed.append(str(path.relative_to(ROOT)))

    if fix:
        for path in changed:
            print(f"fixed {path}")
        if changed:
            return 0

    if problems:
        print("Long dashes are not allowed. Use a regular hyphen (-).")
        for problem in problems:
            print(f"  {problem}")
        print(f"\n{len(problems)} problem(s) found.")
        return 1
    print("No long dashes found.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check for long dashes in the repository.")
    parser.add_argument("--fix", action="store_true", help="Replace long dashes with a regular hyphen.")
    args = parser.parse_args()
    return scan(args.fix)


if __name__ == "__main__":
    sys.exit(main())
